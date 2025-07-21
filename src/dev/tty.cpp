
#ifdef __x86_64__
#include <arch/x86_64/cpu.hpp>
#endif

#include <dev/dev.hpp>
#include <dev/kbd.hpp>
#include <dev/tty.hpp>
#include <fs/devfs.hpp>
#include <mm/ucopy.hpp>
#include <sched/sched.hpp>

namespace NDev {
    using namespace NFS;

    TTY::TTY(void) : inbuffer(4096), outbuffer(4096), linebuffer(1024) {
        // Initialise termios with defaults.
        this->termios.iflag = ICRNL | IXON;
        this->termios.oflag = ONLCR | OPOST;
        this->termios.cflag = 0;
        this->termios.lflag = ECHO | ICANON | ISIG | ECHOE | ECHOK;
        this->termios.ibaud = 38400;
        this->termios.obaud = 38400;
        this->termios.line = 0;
        this->termios.cc.vmin = 1;
        this->termios.cc.vintr = 0x03;
        this->termios.cc.vquit = 0x1c;
        this->termios.cc.verase = '\b';
        this->termios.cc.vkill = 0x15;
        this->termios.cc.veof = 0x04;
        this->termios.cc.vstart = 0x11;
        this->termios.cc.vstop = 0x13;
        this->termios.cc.vsusp = 0x1a;
        this->termios.cc.veol = 0;
        this->termios.cc.vtime = 0;
        this->termios.cc.vreprint = 0x12;
        this->termios.cc.vlnext = 0x16;

        size_t rows;
        size_t cols;
        flanterm_get_dimensions(NLimine::flanctx, &cols, &rows);
        this->winsize.col = cols;
        this->winsize.row = rows;
        this->winsize.xpixel = NLimine::fbreq.response->framebuffers[0]->width;
        this->winsize.ypixel = NLimine::fbreq.response->framebuffers[0]->height;

    }

static char asciitable[] = {
       0, '\033', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '-', '=', '\b', '\t', 'q', 'w', 'e', 'r', 't', 'y', 'u', 'i', 'o', 'p', '[', ']', '\r', 0, 'a', 's', 'd', 'f', 'g', 'h', 'j', 'k', 'l', ';', '\'', '`', 0, '\\', 'z', 'x', 'c', 'v', 'b', 'n', 'm', ',', '.', '/', 0, '*', 0, ' ', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, '7', '8', '9', '-', '4', '5', '6', '+', '1', '2', '3', '0', '.', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, '\r', 0, '/', 0, 0, '\r', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

    void TTY::process(char c, void (*writefn)(const char *, size_t)) {
        bool canwrite = writefn != NULL;


        if (termios.lflag & ICANON) {
            if (c == this->termios.cc.verase) {
                NLib::ScopeSpinlock guard(&this->linelock);
                if (!this->linebuffer.empty()) {
                    this->linebuffer.popback(); // Remove a character.
                    if (this->termios.lflag & ECHO) {
                        NLib::ScopeSpinlock guard(&this->outlock);
                        if (this->termios.lflag & ECHOE) { // Backspace should actually be backspace, and get rid of the last character, not just move the cursor back over it.
                            this->outbuffer.push('\b');
                            this->outbuffer.push(' ');
                            this->outbuffer.push('\b');
                            if (canwrite) {
                                writefn("\b \b", 3);
                            }
                        } else {
                            c = this->termios.cc.verase;
                            this->outbuffer.push(c);

                            if (canwrite) {
                                writefn(&c, 1); // Otherwise, we should just print out the control code as is.
                            }
                        }
                    }
                }
                return;
            } else if (c == this->termios.cc.vkill) {
                if (this->termios.lflag & ECHO) {
                    if (this->termios.lflag & ECHOK) {
                        NLib::ScopeSpinlock guard(&this->outlock);

                        this->outbuffer.push('^');
                        this->outbuffer.push(this->termios.cc.vkill + 0x40);
                        this->outbuffer.push('\n');
                        if (canwrite) {
                            char cc[3];
                            cc[0]  = '^';
                            cc[1] = this->termios.cc.vkill + 0x40;
                            cc[2] = '\n';
                            writefn(cc, 3);
                        }
                    }
                }
                return;
            } else if (c == this->termios.cc.veof) {
                // Forced to flush output to buffer, there's nothing left.
                // POLLIN. We might have some data.
                NLib::ScopeSpinlock guard(&this->linelock);
                if (this->linebuffer.empty()) { // EOF is only valid at the start of a line.
                    this->linebuffer.push(c);
                    return;
                }
            }

            if ((this->termios.iflag & IGNCR) && c == '\r') {
                return; // Flag determines that we should ignore carriage returns.
            } else if ((this->termios.iflag & ICRNL) && c == '\r') {
                c = '\n'; // Flag determines that we should convert carriage returns into newlines.
            } else if ((this->termios.iflag & INLCR) && c == '\n') {
                c = '\r'; // Flag determines that we should convert newlines into carriage returns.
            }

            if (c == '\n' || c == this->termios.cc.veol || c == this->termios.cc.veol2) {
                NLib::ScopeSpinlock guard1(&this->linelock);
                NLib::ScopeSpinlock guard2(&this->outlock);
                this->linebuffer.push(c);
                if (this->termios.lflag & ECHO) {
                    if (canwrite) {
                        writefn(&c, 1);
                    }
                    this->outbuffer.push(c);
                }
                this->readwait.wake(); // We have a full line now. Wake waiters.
                return;
                // Forced to flush output to buffer, we've finished this line.
                // POLLIN. We've got data! Canonical mode only does this if it finds a line.
            }

            if (c >= 32 && c <= 126) { // Add if printable.
                NLib::ScopeSpinlock guard(&this->linelock);
                this->linebuffer.push(c);
                if ((this->termios.lflag & ECHO) && !((this->termios.lflag & ECHONL) && c == '\n')) {
                    if (canwrite) {
                        writefn(&c, 1);
                    }
                    NLib::ScopeSpinlock guard(&this->outlock);
                    this->outbuffer.push(c);
                }
            }
        } else {
            if (canwrite && this->termios.lflag & ECHO) {
                writefn(&c, 1);
            }
            NLib::ScopeSpinlock guard(&this->inlock);

            this->inbuffer.push(c); // Append character to input buffer. Raw mode doesn't process any input.

            this->readwait.wake();
            // POLLIN. Raw will notify for every appending character.
        }
    }

    static bool hasline(NLib::CircularBuffer<char> *buf, char eol, char eof) {
        for (size_t i = 0; i < buf->size(); i++) {
            char c = buf->peek(i);
            if (c == '\n' || c == eol || c == eof) {
                return true;
            }
        }
        return false;
    }

    ssize_t TTY::read(char *buf, size_t count, int fdflags) {
        if (!count) {
            return 0;
        }

        if (this->termios.lflag & ICANON) {
            this->linelock.acquire();
            if ((fdflags & VFS::O_NONBLOCK) && this->linebuffer.empty()) {
                this->linelock.release();
                return -EAGAIN; // There's nothing we can do. Caller should try again when we have data.
            }

            // Wait for a full line.
            waiteventlocked(
                &this->readwait,
                hasline(&this->linebuffer, this->termios.cc.veol, this->termios.cc.veof),
                &this->linelock
            );

            size_t tocopy = this->linebuffer.size();
            if (tocopy > count) { // If there is more data in the line than the user wants, we should only copy out as much the caller wants.
                tocopy = count;
            }

            for (size_t i = 0; i < tocopy; i++) {
                buf[i] = this->linebuffer.pop();
            }
            this->linelock.release();
            return tocopy;
        } else {
            this->inlock.acquire();

            if ((fdflags & VFS::O_NONBLOCK) && this->inbuffer.empty()) {
                this->inlock.release();
                return -EAGAIN; // There's nothing we can do. Caller should try again when we have data.
            }

            // Wait until we have enough data.
            waiteventlocked(
                &this->readwait,
                this->inbuffer.size() >= this->termios.cc.vmin, // Wait until we have at least VMIN characters.
                &this->inlock
            );

            size_t toread = this->inbuffer.size();

            if (toread > count) {
                toread = count;
            }

            for (size_t i = 0; i < toread; i++) {
                buf[i] = this->inbuffer.pop();
            }
            this->inlock.release();
            return toread;
        }

        // Read from read buffer.
        return count;
    }

    ssize_t TTY::write(const char *buf, size_t count, int fdflags, void (*writefn)(const char *, size_t)) {
        (void)fdflags;
        if (writefn) {
            writefn(buf, count);
        }

        NLib::ScopeSpinlock guard(&this->outlock);
        for (size_t i = 0; i < count; i++) {
            outbuffer.push(buf[i]);
        }
        return count;
    }

    TTYDevice *ttys[63];

    class TTYDriver : public DevDriver {
        private:
            // /dev/tty represents the current process' TTY, can represent a pseudo-terminal as well. We do *not* handle pseudo-terminals in this driver, but the correct handler does.
            // /dev/tty0 represents the global currently active VT (CTRL+ALT+F# stuff).
            // /dev/tty1-63 are virtual consoles. Kind of assumes that this is for a seated user. /dev/ttyS# does as well, but does it through serial terminals.

            // XXX: Implement VT system for /dev/tty0. Simply builds on top of existing /dev/tty#, but can be switched through with keyboard events.

            static const uint32_t MAJOR = 4; // TTY major. Actual virtual consoles.
            static const uint32_t MINMINOR = 1;
            static const uint32_t MAXMINOR = 63; // Ends at /dev/tty63, past this are the /dev/ttyS# devices, which this driver does NOT implement.
            static const uint32_t MAXTTYS = (MAXMINOR - MINMINOR) + 1;

            static const uint64_t CURDEVICEID = DEVFS::makedev(5, 0); // /dev/tty -> Points to running process's active TTY.
            static const uint64_t CURVTDEVICEID = DEVFS::makedev(MAJOR, 0); // /dev/tty0 -> Points to currently active virtual terminal.
        public:
            TTYDriver(void) {
                registry->add(new Device(CURVTDEVICEID, this)); // Register abstract.
                registry->add(new Device(CURDEVICEID, this)); // Register abstract.

                struct VFS::stat st {
                    // Should be rw by root, but only write by group. Non-priviledged users can't access it at all.
                    .st_mode = (VFS::S_IRUSR | VFS::S_IWUSR | VFS::S_IWGRP) | VFS::S_IFCHR,
                    .st_uid = 0,
                    .st_gid = 0,
                    .st_rdev = CURVTDEVICEID,
                    .st_blksize = 1024
                };

                assert(VFS::vfs.create("/dev/tty0", st), "Failed to create device node."); // Create abstract /dev/tty0.

                st.st_rdev = CURDEVICEID;
                // Should be rw by all users. It's not an actual device itself, it just points to the current one.
                st.st_mode = (VFS::S_IRUSR | VFS::S_IWUSR | VFS::S_IRGRP | VFS::S_IWGRP | VFS::S_IROTH | VFS::S_IWOTH) | VFS::S_IFCHR;
                assert(VFS::vfs.create("/dev/tty", st), "Failed to create device node."); // Create abstract /dev/tty.

                for (size_t i = 0; i < MAXTTYS; i++) {
                    uint32_t minor = MINMINOR + i; // Device ID minor.

                    ttys[i] = new TTYDevice(DEVFS::makedev(MAJOR, minor), this);
                    registry->add(ttys[i]);

                    struct VFS::stat st {
                        .st_mode = (VFS::S_IRUSR | VFS::S_IWUSR | VFS::S_IWGRP) | VFS::S_IFCHR,
                        .st_uid = 0,
                        .st_gid = 0,
                        .st_rdev = DEVFS::makedev(MAJOR, minor),
                        .st_blksize = 1024
                    };
                    char path[512];
                    NUtil::snprintf(path, sizeof(path), "/dev/tty%lu", minor);

                    assert(VFS::vfs.create(path, st), "Failed to create device node."); // Create device node. This will automatically assign the TTYDevice to the node, and give the TTYDevice reference to its node.
                }

                NSched::Thread *thread = new NSched::Thread(NSched::kprocess, NSched::DEFAULTSTACKSIZE, (void *)activevtthread);

                NSched::schedulethread(thread);
            }

            static void activevtthread(void) {
                // XXX: Actual event system for keyboard events.
                for (;;) {
                    if (KBD::cur != 0) {
                        ttys[0]->tty->process(asciitable[KBD::cur], NLimine::console_write);
                        KBD::cur = 0;
                    }
                    asm volatile("pause");
                }

                __builtin_unreachable();
            }

            VFS::INode *getctty(void) {
                NSched::Process *proc = NArch::CPU::get()->currthread->process;

                uint64_t ctty = __atomic_load_n(&proc->tty, memory_order_relaxed); // Get current TTY.

                uint32_t num = DEVFS::minor(ctty) - 1;
                assert(num < MAXTTYS, "Process is somehow being controlled by an invalid TTY.\n"); // XX: Implement check for /dev/ttyS#.
                TTYDevice *dev = ttys[num];
                assert(dev->ifnode, "TTY device was never given reference to its device node.\n");
                dev->ifnode->ref();
                return dev->ifnode;
            }

            int stat(uint64_t dev, struct NFS::VFS::stat *st) override {
                if (dev == CURDEVICEID) {
                    VFS::INode *ifnode = this->getctty();
                    *st = ifnode->getattr(); // Fill stat buffer with the wrapped node's attributes.
                    ifnode->unref();
                    return 0;
                } else if (dev == CURVTDEVICEID) {

                }
                return -123123123; // Default to node fill of our stat.
            }

            ssize_t read(uint64_t dev, void *buf, size_t count, off_t offset, int fdflags) override {
                if (dev == CURDEVICEID) { // Device is /dev/tty
                    VFS::INode *ifnode = this->getctty();
                    // NUtil::printf("/dev/tty was read. Redirecting to /dev/%s.\n", ifnode->getname());
                    ssize_t ret = ifnode->read(buf, count, offset, fdflags); // Pass operation to CTTY node.
                    ifnode->unref();
                    return ret;
                } else if (dev == CURVTDEVICEID) { // Device is /dev/tty0
                    ;
                } else { // Device is /dev/tty1-63
                    // Here, we could be coming from direct access, or through /dev/tty.
                    uint32_t num = DEVFS::minor(dev) - 1;

                    TTYDevice *tty = ttys[num];
                    return tty->tty->read((char *)buf, count, fdflags);
                }
                return 0;
            }

            ssize_t write(uint64_t dev, const void *buf, size_t count, off_t offset, int fdflags) override {
                if (dev == CURDEVICEID) {
                    VFS::INode *ifnode = this->getctty();
                    // NUtil::printf("/dev/tty was written to. Redirecting to /dev/%s.\n", ifnode->getname());
                    ssize_t ret = ifnode->write(buf, count, offset, fdflags);
                    ifnode->unref();
                    return ret;
                } else if (dev == CURVTDEVICEID) {
                    ;
                } else {
                    // Bypass tty write handler, because we don't need any output buffering (instant output).
                    NLimine::console_write((const char *)buf, count);
                    return count;
                }
                return 0;
            }

            int ioctl(uint64_t dev, unsigned long request, uint64_t arg) override {
                (void)dev;
                if (dev == CURDEVICEID) {
                    VFS::INode *ifnode = this->getctty();
                    int ret = ifnode->ioctl(request, arg);
                    ifnode->unref();
                    return ret;
                } else if (dev == CURVTDEVICEID) {
                    ;
                } else {
                    uint32_t num = DEVFS::minor(dev) - 1;

                    TTYDevice *tty = ttys[num];

                    switch (request) {
                        case TTY::ioctls::TCGETS:
                            if (!arg) {
                                return -EINVAL;
                            }
                            return NMem::UserCopy::copyto((void *)arg, &tty->tty->termios, sizeof(struct TTY::termios));
                        case TTY::ioctls::TCSETS:
                            if (!arg) {
                                return -EINVAL;
                            }
                            return NMem::UserCopy::copyfrom(&tty->tty->termios, (void *)arg, sizeof(struct TTY::termios));
                        case TTY::ioctls::TCSETSW:
                            if (!arg) {
                                return -EINVAL;
                            }
                            // Wait until output buffer is flushed.
                            return NMem::UserCopy::copyfrom(&tty->tty->termios, (void *)arg, sizeof(struct TTY::termios));
                        case TTY::ioctls::TCSETSF:
                            if (!arg) {
                                return -EINVAL;
                            }
                            { // Discard queued input before setting flags.
                                NLib::ScopeSpinlock guard1(&tty->tty->inlock);
                                NLib::ScopeSpinlock guard2(&tty->tty->outlock);
                                NLib::ScopeSpinlock guard3(&tty->tty->linelock);
                                tty->tty->inbuffer.clear();
                                tty->tty->outbuffer.clear();
                                tty->tty->linebuffer.clear();
                            }
                            return NMem::UserCopy::copyfrom(&tty->tty->termios, (void *)arg, sizeof(struct TTY::termios)); // Then set attributes.
                        case TTY::ioctls::TCFLSH: {
                            // XXX: Flush specifics.
                            return 0;
                        }

                        case TTY::ioctls::TIOCSCTTY: {
                            NSched::Process *proc = NArch::CPU::get()->currthread->process;
                            tty->ifnode->ref();
                            __atomic_store_n(&proc->tty, tty->ifnode->getattr().st_rdev, memory_order_relaxed);
                            proc->tty = tty->ifnode->getattr().st_rdev;
                            tty->ifnode->unref();
                            return 0;
                        }

                        case TTY::ioctls::TIOCGWINSZ:
                            if (!arg) {
                                return -EINVAL;
                            }
                            return NMem::UserCopy::copyto((void *)arg, &tty->tty->winsize, sizeof(struct TTY::winsize));
                        case TTY::ioctls::TIOCSWINSZ:
                            if (!arg) {
                                return -EINVAL;
                            }
                            return NMem::UserCopy::copyfrom(&tty->tty->winsize, (void *)arg, sizeof(struct TTY::winsize));
                    }
                }

                return -EINVAL;
            }
    };

    static struct reginfo info = {
        .name = "tty",
        .type = reginfo::GENERIC,
        .match = { }
    };

    REGDRIVER(TTYDriver, &info);
}
