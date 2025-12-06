
#ifdef __x86_64__
#include <arch/x86_64/cpu.hpp>
#endif

#include <dev/dev.hpp>
#include <dev/kbd.hpp>
#include <dev/input/input.hpp>
#include <dev/drivers/tty.hpp>
#include <fs/devfs.hpp>
#include <lib/signal.hpp>
#include <mm/ucopy.hpp>
#include <sched/sched.hpp>
#include <std/stddef.h>

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

    const char asciitable[Input::key::KMAX] = {
        '\0',   // RSVD
        '\0',   // UNKNOWN
        '\x1B', // KESC
        '\0',   // KF1 (no ASCII)
        '\0',   // KF2
        '\0',   // KF3
        '\0',   // KF4
        '\0',   // KF5
        '\0',   // KF6
        '\0',   // KF7
        '\0',   // KF8
        '\0',   // KF9
        '\0',   // KF10
        '\0',   // KF11
        '\0',   // KF12
        '`',    // KGRAVE
        '1',    // K1
        '2',    // K2
        '3',    // K3
        '4',    // K4
        '5',    // K5
        '6',    // K6
        '7',    // K7
        '8',    // K8
        '9',    // K9
        '0',    // K0
        '-',    // KMINUS
        '=',    // KEQUALS
        '\b',   // KBACKSPACE
        '\t',   // KTAB
        'q',    // KQ
        'w',    // KW
        'e',    // KE
        'r',    // KR
        't',    // KT
        'y',    // KY
        'u',    // KU
        'i',    // KI
        'o',    // KO
        'p',    // KP
        '[',    // KLEFTBRACKET
        ']',    // KRIGHTBRACKET
        '\\',   // KBACKSLASH
        '\0',   // KCAPSLOCK
        'a',    // KA
        's',    // KS
        'd',    // KD
        'f',    // KF
        'g',    // KG
        'h',    // KH
        'j',    // KJ
        'k',    // KK
        'l',    // KL
        ';',    // KSEMICOLON
        '\'',   // KAPOSTROPHE
        '\n',   // KENTER
        '\0',   // KLSHIFT
        'z',    // KZ
        'x',    // KX
        'c',    // KC
        'v',    // KV
        'b',    // KB
        'n',    // KN
        'm',    // KM
        ',',    // KCOMMA
        '.',    // KDOT
        '/',    // KSLASH
        '\0',   // KRSHIFT
        '\0',   // KLCTRL
        '\0',   // KSUPER
        '\0',   // KLALT
        ' ',    // KSPACE
        '\0',   // KRALT
        '\0',   // KRCTRL
        '\0',   // KLEFT (arrow)
        '\0',   // KUP
        '\0',   // KDOWN
        '\0',   // KRIGHT
        '\0',   // KPRNTSCR
        '\0',   // KINSERT
        '\0',   // KDELETE
        '\0',   // KPAGEUP
        '\0',   // KPAGEDOWN
        '\0',   // KHOME
        '\0',   // KEND
        '\0',   // KNUMLOCK
        '\0',   // KSCROLLLOCK
        '0',    // KKPAD0
        '1',    // KKPAD1
        '2',    // KKPAD2
        '3',    // KKPAD3
        '4',    // KKPAD4
        '5',    // KKPAD5
        '6',    // KKPAD6
        '8',    // KKPAD8
        '9',    // KKPAD9
        '*',    // KKPADMUL
        '-',    // KKPADSUB
        '+',    // KKPADADD
        '/',    // KKPADDIV
        '.',    // KKPADDOT
        '\n',   // KKPADENTER
    };

    const char asciitableshift[Input::key::KMAX] = {
        '\0',   // RSVD
        '\0',   // UNKNOWN
        '\x1B', // KESC
        '\0',   // KF1 (no ASCII)
        '\0',   // KF2
        '\0',   // KF3
        '\0',   // KF4
        '\0',   // KF5
        '\0',   // KF6
        '\0',   // KF7
        '\0',   // KF8
        '\0',   // KF9
        '\0',   // KF10
        '\0',   // KF11
        '\0',   // KF12
        '~',    // KGRAVE
        '!',    // K1
        '@',    // K2
        '#',    // K3
        '$',    // K4
        '%',    // K5
        '^',    // K6
        '&',    // K7
        '*',    // K8
        '(',    // K9
        ')',    // K0
        '_',    // KMINUS
        '+',    // KEQUALS
        '\b',   // KBACKSPACE
        '\t',   // KTAB
        'Q',    // KQ
        'W',    // KW
        'E',    // KE
        'R',    // KR
        'T',    // KT
        'Y',    // KY
        'U',    // KU
        'I',    // KI
        'O',    // KO
        'P',    // KP
        '{',    // KLEFTBRACKET
        '}',    // KRIGHTBRACKET
        '|',   // KBACKSLASH
        '\0',   // KCAPSLOCK
        'A',    // KA
        'S',    // KS
        'D',    // KD
        'F',    // KF
        'G',    // KG
        'H',    // KH
        'J',    // KJ
        'K',    // KK
        'L',    // KL
        ':',    // KSEMICOLON
        '"',    // KAPOSTROPHE
        '\n',   // KENTER
        '\0',   // KLSHIFT
        'Z',    // KZ
        'X',    // KX
        'C',    // KC
        'V',    // KV
        'B',    // KB
        'N',    // KN
        'M',    // KM
        '<',    // KCOMMA
        '>',    // KDOT
        '?',    // KSLASH
        '\0',   // KRSHIFT
        '\0',   // KLCTRL
        '\0',   // KSUPER
        '\0',   // KLALT
        ' ',    // KSPACE
        '\0',   // KRALT
        '\0',   // KRCTRL
        '\0',   // KLEFT (arrow)
        '\0',   // KUP
        '\0',   // KDOWN
        '\0',   // KRIGHT
        '\0',   // KPRNTSCR
        '\0',   // KINSERT
        '\0',   // KDELETE
        '\0',   // KPAGEUP
        '\0',   // KPAGEDOWN
        '\0',   // KHOME
        '\0',   // KEND
        '\0',   // KNUMLOCK
        '\0',   // KSCROLLLOCK
        '0',    // KKPAD0
        '1',    // KKPAD1
        '2',    // KKPAD2
        '3',    // KKPAD3
        '4',    // KKPAD4
        '5',    // KKPAD5
        '6',    // KKPAD6
        '8',    // KKPAD8
        '9',    // KKPAD9
        '*',    // KKPADMUL
        '-',    // KKPADSUB
        '+',    // KKPADADD
        '/',    // KKPADDIV
        '.',    // KKPADDOT
        '\n',   // KKPADENTER
    };

    void TTY::process(char c, void (*writefn)(const char *, size_t)) {
        bool canwrite = writefn != NULL;


        if (termios.lflag & ISIG) {
            int signal = -1;
            if (c == this->termios.cc.vintr) {
                signal = SIGINT;
                NUtil::printf("Interrupt.\n");
            } else if (c == this->termios.cc.vquit) {
                signal = SIGQUIT;
                NUtil::printf("Quit.\n");
            } else if (c == this->termios.cc.vsusp) {
                signal = SIGTSTP;
                NUtil::printf("Suspend.\n");
            }

            if (signal >= 0) {
                if (this->fpgrp) {
                    NSched::signalpgrp(this->fpgrp, signal);
                }
                return;
            }
        }

        if (termios.lflag & ICANON) {
            if (c == this->termios.cc.verase) {
                NLib::ScopeIRQSpinlock guard(&this->linelock);
                if (!this->linebuffer.empty()) {
                    this->linebuffer.popback(); // Remove a character.
                    if (this->termios.lflag & ECHO) {
                        NLib::ScopeIRQSpinlock guard(&this->outlock);
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
                        NLib::ScopeIRQSpinlock guard(&this->outlock);

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
                NLib::ScopeIRQSpinlock guard(&this->linelock);
                if (this->linebuffer.empty()) { // EOF is only valid at the start of a line.
                    this->pending_eof = true;
                    this->readwait.wake();
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
                NLib::ScopeIRQSpinlock guard1(&this->linelock);
                NLib::ScopeIRQSpinlock guard2(&this->outlock);
                this->linebuffer.push(c);
                bool shouldecho = (this->termios.lflag & ECHO) || (!(this->termios.lflag & ECHO) && (this->termios.lflag & ECHONL) && (c == '\n'));
                if (shouldecho) {
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

            // if (c >= 32 && c <= 126) { // Add if printable.
                NLib::ScopeIRQSpinlock guard(&this->linelock);
                this->linebuffer.push(c);
                bool shouldecho = (this->termios.lflag & ECHO) || (!(this->termios.lflag & ECHO) && (this->termios.lflag & ECHONL) && (c == '\n'));
                if (shouldecho) {
                    if (canwrite) {
                        writefn(&c, 1);
                    }
                    NLib::ScopeIRQSpinlock guard(&this->outlock);
                    this->outbuffer.push(c);
                }
            // }
        } else {
            if (canwrite && this->termios.lflag & ECHO) {
                writefn(&c, 1);
            }
            NLib::ScopeIRQSpinlock guard(&this->inlock);

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
        NSched::Thread *thread = NArch::CPU::get()->currthread;
        if (thread->process->pgrp != this->fpgrp) {
            NSched::signalthread(thread, SIGTTIN);
            return -EIO;
        }

        if (!count) {
            return 0;
        }

        if (this->termios.lflag & ICANON) {
            // Create an IRQSpinlock guard to manage line lock (because input interrupt sources also acquire this lock).
            this->linelock.acquire();
            // If an EOF was received at the start of the line, return EOF (0).
            if (this->pending_eof && this->linebuffer.empty()) {
                this->pending_eof = false;
                this->linelock.release();
                return 0;
            }

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

        NSched::Thread *thread = NArch::CPU::get()->currthread;
        this->fpgrp = thread->process->pgrp;

        if (thread->process->pgrp != this->fpgrp) {
            NSched::signalthread(thread, SIGTTOU);
            return -EIO;
        }

        if (writefn) {
            writefn(buf, count);
        }

        NLib::ScopeIRQSpinlock guard(&this->outlock);
        for (size_t i = 0; i < count; i++) {
            outbuffer.push(buf[i]);
        }
        return count;
    }

    static TTYDevice *ttys[63];
    static size_t currentvt = 1; // Current VT index.

    static struct Input::eventhandler handler;
    static bool capslock = false;
    static bool shifted = false;
    static bool ctrl = false;
    static bool alted = false;

    class TTYDriver : public DevDriver {
        private:
            // /dev/tty represents the current process' TTY, can represent a pseudo-terminal as well. We do *not* handle pseudo-terminals in this driver, but the correct handler does.
            // /dev/tty0 represents the global currently active VT (CTRL+ALT+F# stuff).
            // /dev/tty1-63 are virtual consoles. Kind of assumes that this is for a seated user. /dev/ttyS# does as well, but does it through serial terminals.

            // XXX: Implement VT system for /dev/tty0. Simply builds on top of existing /dev/tty#, but can be switched through with keyboard events.
            // - Expected to save the state of the entire screen between VT swaps.
            // - Only active VT will have writefn() valid.
            //
            // - Maintain multiple flanterm contexts, then full refresh before restoring a copy.

            static const uint32_t MAJOR = 4; // TTY major. Actual virtual consoles.
            static const uint32_t MINMINOR = 1;
            static const uint32_t MAXMINOR = 63; // Ends at /dev/tty63, past this are the /dev/ttyS# devices, which this driver does NOT implement.
            static const uint32_t MAXTTYS = (MAXMINOR - MINMINOR) + 1;

            static const uint64_t CURDEVICEID = DEVFS::makedev(5, 0); // /dev/tty -> Points to running process's active TTY.
            static const uint64_t CURVTDEVICEID = DEVFS::makedev(MAJOR, 0); // /dev/tty0 -> Points to currently active virtual terminal.
        public:
            TTYDriver(void) {
                // "Abstract" devices are fake devices that represent the current TTY (/dev/tty) and current VT (/dev/tty0).
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

                handler.connect = NULL;
                handler.disconnect = NULL;
                handler.evsubscription = Input::event::KEY; // Subscribe to keyboard events.
                handler.event = event;
                Input::registerhandler(&handler); // Register handler.
            }

            static void event(uint16_t type, uint16_t code, int32_t value) {
                assert(type == Input::event::KEY, "Invalid event type received.\n");

                if (code == Input::key::KLSHIFT || code == Input::key::KRSHIFT) {
                    shifted = value == 1;
                    return;
                } else if (code == Input::key::KLCTRL || code == Input::key::KRCTRL) {
                    ctrl = value == 1;
                    return;
                } else if (code == Input::key::KCAPSLOCK && value == 1) {
                    capslock = !capslock; // Toggle.
                    return;
                } else if (code == Input::key::KLALT || code == Input::key::KRALT) {
                    alted = value == 1;
                    return;
                }


                if (value == 1) { // Pressed.

                    char ascii = '\0';
                    if (ctrl) { // Handle control sequences.

                        if (alted) {
                            if (code >= Input::key::KF1 && code <= Input::key::KF9) {
                                // XXX: VT Switching.
                                // currentvt = 1 + (code - Input::key::KF1);
                                return;
                            }
                        }

                        if ((asciitable[code] >= 'a' && asciitable[code] <= 'z') || (asciitable[code] >= 'A' && asciitable[code] <= '\\')) {

                            ascii = asciitable[code] >= 'a' ? asciitable[code] - 0x60 : asciitable[code] - 0x40;
                            // Send to TTY.
                            ttys[currentvt - 1]->tty->process(ascii, NLimine::console_write);
                        }
                        return;
                    }

                    const char *esccode = NULL;
                    switch (code) {
                        case Input::key::KHOME:
                            esccode = "\x1b[1~";
                            break;
                        case Input::key::KEND:
                            esccode = "\x1b[4~";
                            break;
                        case Input::key::KDELETE:
                            esccode = "\x1b[3~";
                            break;
                        case Input::key::KINSERT:
                            esccode = "\x1b[2~";
                            break;
                        case Input::key::KPAGEUP:
                            esccode = "\x1b[5~";
                            break;
                        case Input::key::KPAGEDOWN:
                            esccode = "\x1b[6~";
                            break;
                        case Input::key::KLEFT:
                            esccode = "\x1b[D";
                            break;
                        case Input::key::KRIGHT:
                            esccode = "\x1b[C";
                            break;
                        case Input::key::KUP:
                            esccode = "\x1b[A";
                            break;
                        case Input::key::KDOWN:
                            esccode = "\x1b[B";
                            break;
                        default:
                            goto notspecial; // Clearly not a special key that emits an escape code.
                    }

                    // Write escape code to TTY.
                    for (size_t i = 0; i < NLib::strlen(esccode); i++) {
                        ttys[currentvt - 1]->tty->process(esccode[i], NLimine::console_write);
                    }
                    return;

notspecial:
                    if (code < Input::key::KMAX) {

                        bool upshift = shifted;

                        if (asciitable[code] >= 'a' && asciitable[code] <= 'z') {
                            upshift ^= capslock; // Capslock should only apply to alphabetical characters. Apply it if we aren't already uppercase.
                        }
                        ascii = upshift ? asciitableshift[code] : asciitable[code];
                    }
                    if (ascii != '\0') {
                        ttys[currentvt - 1]->tty->process(ascii, NLimine::console_write);
                    }
                }
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
                    assert((currentvt - 1) < MAXTTYS, "Current VT exceeds number of TTYs.\n");

                    TTYDevice *tty = ttys[currentvt - 1];
                    tty->devlock.acquire();
                    tty->ifnode->ref();
                    *st = tty->ifnode->getattr();
                    tty->ifnode->unref();
                    tty->devlock.release();
                    return 0;
                }
                return DEVFS::NOSTAT; // Default to node fill of our stat.
            }

            ssize_t read(uint64_t dev, void *buf, size_t count, off_t offset, int fdflags) override {
                if (dev == CURDEVICEID) { // Device is /dev/tty
                    VFS::INode *ifnode = this->getctty();
                    ssize_t ret = ifnode->read(buf, count, offset, fdflags); // Pass operation to CTTY node.
                    ifnode->unref();
                    return ret;
                } else if (dev == CURVTDEVICEID) { // Device is /dev/tty0
                    assert((currentvt - 1) < MAXTTYS, "Current VT exceeds number of TTYs.\n");

                    TTYDevice *tty = ttys[currentvt - 1];
                    ssize_t ret = tty->tty->read((char *)buf, count, fdflags);
                    return ret;
                } else { // Device is /dev/tty1-63
                    // Here, we could be coming from direct access, or through /dev/tty.
                    uint32_t num = DEVFS::minor(dev) - 1;

                    TTYDevice *tty = ttys[num];
                    ssize_t ret = tty->tty->read((char *)buf, count, fdflags);
                    return ret;
                }
                return 0;
            }

            ssize_t write(uint64_t dev, const void *buf, size_t count, off_t offset, int fdflags) override {
                if (dev == CURDEVICEID) {
                    VFS::INode *ifnode = this->getctty();
                    ssize_t ret = ifnode->write(buf, count, offset, fdflags);
                    ifnode->unref();
                    return ret;
                } else if (dev == CURVTDEVICEID) {
                    return write(DEVFS::makedev(MAJOR, currentvt), buf, count, offset, fdflags);
                } else {
                    // Bypass tty write handler, because we don't need any output buffering (instant output).
                    uint32_t num = DEVFS::minor(dev) - 1;

                    TTYDevice *tty = ttys[num];

                    ssize_t ret = tty->tty->write((const char *)buf, count, fdflags, DEVFS::minor(dev) == currentvt ? NLimine::console_write : NULL);
                    return ret;

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
                    return ioctl(DEVFS::makedev(MAJOR, currentvt), request, arg);
                } else {
                    uint32_t num = DEVFS::minor(dev) - 1;

                    TTYDevice *tty = ttys[num];
                    tty->devlock.acquire();

                    ssize_t ret = 0;
                    switch (request) {
                        case TTY::ioctls::TCGETS:
                            if (!arg) {
                                tty->devlock.release();
                                return -EINVAL;
                            }
                            ret = NMem::UserCopy::copyto((void *)arg, &tty->tty->termios, sizeof(struct TTY::termios));
                            tty->devlock.release();
                            return ret;
                        case TTY::ioctls::TCSETS:
                            if (!arg) {
                                tty->devlock.release();
                                return -EINVAL;
                            }

                            ret = NMem::UserCopy::copyfrom(&tty->tty->termios, (void *)arg, sizeof(struct TTY::termios));
                            tty->devlock.release();
                            return ret;
                        case TTY::ioctls::TCSETSW:
                            if (!arg) {
                                tty->devlock.release();
                                return -EINVAL;
                            }
                            // Wait until output buffer is flushed.
                            ret = NMem::UserCopy::copyfrom(&tty->tty->termios, (void *)arg, sizeof(struct TTY::termios));
                            tty->devlock.release();
                            return ret;
                        case TTY::ioctls::TCSETSF:
                            if (!arg) {
                                tty->devlock.release();
                                return -EINVAL;
                            }
                            { // Discard queued input before setting flags.
                                NLib::ScopeIRQSpinlock guard1(&tty->tty->linelock);
                                NLib::ScopeIRQSpinlock guard2(&tty->tty->outlock);
                                NLib::ScopeIRQSpinlock guard3(&tty->tty->inlock);
                                tty->tty->inbuffer.clear();
                                tty->tty->outbuffer.clear();
                                tty->tty->linebuffer.clear();
                            }
                            ret = NMem::UserCopy::copyfrom(&tty->tty->termios, (void *)arg, sizeof(struct TTY::termios)); // Then set attributes.
                            tty->devlock.release();
                            return ret;
                        case TTY::ioctls::TCFLSH: {
                            if (!arg) {
                                tty->devlock.release();
                                return -EINVAL;
                            }

                            int which = 0;
                            ret = NMem::UserCopy::copyfrom(&which, (void *)arg, sizeof(which));
                            if (ret < 0) {
                                tty->devlock.release();
                                return ret;
                            }

                            // Which: 0 = flush input, 1 = flush output, 2 = flush both
                            switch (which) {
                                case 0: { // Flush input
                                    NLib::ScopeIRQSpinlock guard1(&tty->tty->linelock);
                                    NLib::ScopeIRQSpinlock guard2(&tty->tty->inlock);
                                    tty->tty->inbuffer.clear();
                                    tty->tty->linebuffer.clear();
                                    break;
                                }
                                case 1: { // Flush output
                                    NLib::ScopeIRQSpinlock guard(&tty->tty->outlock);
                                    tty->tty->outbuffer.clear();
                                    break;
                                }
                                case 2: { // Flush both
                                    // Use canonical lock order: linelock -> outlock -> inlock
                                    NLib::ScopeIRQSpinlock guard1(&tty->tty->linelock);
                                    NLib::ScopeIRQSpinlock guard2(&tty->tty->outlock);
                                    NLib::ScopeIRQSpinlock guard3(&tty->tty->inlock);
                                    tty->tty->inbuffer.clear();
                                    tty->tty->outbuffer.clear();
                                    tty->tty->linebuffer.clear();
                                    break;
                                }
                                default:
                                    tty->devlock.release();
                                    return -EINVAL;
                            }

                            tty->devlock.release();
                            return 0;
                        }

                        case TTY::ioctls::TIOCSCTTY: {
                            NSched::Process *proc = NArch::CPU::get()->currthread->process;
                            tty->ifnode->ref();
                            __atomic_store_n(&proc->tty, tty->ifnode->getattr().st_rdev, memory_order_relaxed);
                            proc->tty = tty->ifnode->getattr().st_rdev;
                            tty->ifnode->unref();
                            tty->devlock.release();
                            return 0;
                        }

                        case TTY::ioctls::TIOCGPGRP: {
                            if (!arg) {
                                tty->devlock.release();
                                return -EINVAL;
                            }

                            int pgid = 0;
                            if (tty->tty->fpgrp) {
                                pgid = (int)tty->tty->fpgrp->id;
                            }

                            ret = NMem::UserCopy::copyto((void *)arg, &pgid, sizeof(pgid));
                            tty->devlock.release();
                            return ret;
                        }

                        case TTY::ioctls::TIOCSPGRP: {
                            if (!arg) {
                                tty->devlock.release();
                                return -EINVAL;
                            }

                            int requested = 0;
                            ret = NMem::UserCopy::copyfrom(&requested, (void *)arg, sizeof(requested));
                            if (ret < 0) {
                                tty->devlock.release();
                                return ret;
                            }

                            NSched::Process **ppgrp = NSched::pidtable->find(requested);
                            if (!ppgrp) {
                                tty->devlock.release();
                                return -ESRCH;
                            }
                            NSched::ProcessGroup *target = (*ppgrp)->pgrp;

                            // Ensure caller is in the same session as the target process group.
                            NSched::Process *caller = NArch::CPU::get()->currthread->process;
                            if (!caller->session || !target->session || caller->session != target->session) {
                                tty->devlock.release();
                                return -EPERM;
                            }

                            // If the TTY has an associated session, ensure the target is in the same session.
                            if (tty->tty->session && tty->tty->session != target->session) {
                                tty->devlock.release();
                                return -EPERM;
                            }

                            // Accept the requested process group as the foreground pgrp.
                            tty->tty->fpgrp = target;
                            tty->devlock.release();
                            return 0;
                        }

                        case TTY::ioctls::TIOCGWINSZ:
                            if (!arg) {
                                tty->devlock.release();
                                return -EINVAL;
                            }
                            ret = NMem::UserCopy::copyto((void *)arg, &tty->tty->winsize, sizeof(struct TTY::winsize));
                            tty->devlock.release();
                            return ret;
                        case TTY::ioctls::TIOCSWINSZ:
                            if (!arg) {
                                tty->devlock.release();
                                return -EINVAL;
                            }
                            ret = NMem::UserCopy::copyfrom(&tty->tty->winsize, (void *)arg, sizeof(struct TTY::winsize));
                            tty->devlock.release();
                            return ret;
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
