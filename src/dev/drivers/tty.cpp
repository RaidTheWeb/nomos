
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
#include <sched/jobctrl.hpp>
#include <std/stddef.h>

namespace NDev {
    using namespace NFS;

    TTY::TTY(void) : inbuffer(4096), outbuffer(4096), linebuffer(1024) {
        // Initialise termios with defaults (similar to Linux defaults).
        this->termios.iflag = ICRNL | IXON | IMAXBEL;
        this->termios.oflag = OPOST | ONLCR;
        this->termios.cflag = CREAD | CS8 | CLOCAL; // Enable receiver, 8-bit chars, ignore modem
        this->termios.lflag = ECHO | ICANON | ISIG | ECHOE | ECHOK | ECHOCTL | ECHOKE | IEXTEN;
        this->termios.ibaud = 38400;
        this->termios.obaud = 38400;
        this->termios.line = 0;
        this->termios.cc.vmin = 1;
        this->termios.cc.vintr = 0x03;    // ^C
        this->termios.cc.vquit = 0x1c;    // ^\
        this->termios.cc.verase = 0x7f;   // DEL (more common than ^H)
        this->termios.cc.vkill = 0x15;    // ^U
        this->termios.cc.veof = 0x04;     // ^D
        this->termios.cc.vswtch = 0;
        this->termios.cc.vstart = 0x11;   // ^Q
        this->termios.cc.vstop = 0x13;    // ^S
        this->termios.cc.vsusp = 0x1a;    // ^Z
        this->termios.cc.veol = 0;
        this->termios.cc.vtime = 0;
        this->termios.cc.vreprint = 0x12; // ^R
        this->termios.cc.vdiscard = 0x0f; // ^O
        this->termios.cc.vwerase = 0x17;  // ^W
        this->termios.cc.vlnext = 0x16;   // ^V
        this->termios.cc.veol2 = 0;

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
        '7',    // KKPAD7
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
        '7',    // KKPAD7
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

        // VLNEXT (Ctrl+V): if the previous character was VLNEXT, insert this character literally, bypassing all signal and editing processing.
        if (this->vlnextpending) {
            this->vlnextpending = false;

            if (this->termios.lflag & ICANON) {
                NLib::ScopeIRQSpinlock guard(&this->linelock);
                this->linebuffer.push(c);

                if (this->termios.lflag & ECHO) {
                    // ECHOCTL: echo control characters as ^X.
                    if ((this->termios.lflag & ECHOCTL) && c < 32 && c != '\t' && c != '\n') {
                        char ctrl[2] = { '^', (char)(c + 0x40) };
                        if (canwrite) {
                            writefn(ctrl, 2);
                        }
                        NLib::ScopeIRQSpinlock guard2(&this->outlock);
                        this->outbuffer.push(ctrl[0]);
                        this->outbuffer.push(ctrl[1]);
                    } else {
                        if (canwrite) {
                            writefn(&c, 1);
                        }
                        NLib::ScopeIRQSpinlock guard2(&this->outlock);
                        this->outbuffer.push(c);
                    }
                }
            } else {
                if (canwrite && (this->termios.lflag & ECHO)) {
                    writefn(&c, 1);
                }
                NLib::ScopeIRQSpinlock guard(&this->inlock);
                this->inbuffer.push(c);
                if (NSched::initialised) {
                    this->readwait.wakeone();
                }
            }
            return;
        }

        if (termios.lflag & ISIG) {
            int signal = -1;
            char sigch = 0;
            if (c == this->termios.cc.vintr) {
                signal = SIGINT;
                sigch = c;
            } else if (c == this->termios.cc.vquit) {
                signal = SIGQUIT;
                sigch = c;
            } else if (c == this->termios.cc.vsusp) {
                signal = SIGTSTP;
                sigch = c;
            }

            if (signal >= 0) {
                if ((this->termios.lflag & ECHO) && (this->termios.lflag & ECHOCTL) && canwrite) {
                    char ctrl[3] = { '^', (char)(sigch + 0x40), '\n' };
                    writefn(ctrl, 3);
                }

                // POSIX: Unless NOFLSH is set, flush input and output queues.
                if (!(this->termios.lflag & NOFLSH)) {
                    NLib::ScopeIRQSpinlock guard1(&this->linelock);
                    NLib::ScopeIRQSpinlock guard2(&this->outlock);
                    NLib::ScopeIRQSpinlock guard3(&this->inlock);
                    this->linebuffer.clear();
                    this->inbuffer.clear();
                    // Note: Some implementations also clear outbuffer here.
                }

                {
                    NLib::ScopeIRQSpinlock guard(&this->ctrllock);
                    if (this->fpgrp) {
                        // Signal the foreground process group.
                        NSched::signalpgrp(this->fpgrp, signal);
                    }
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
                NLib::ScopeIRQSpinlock guard(&this->linelock);
                size_t linesize = this->linebuffer.size();

                if (this->termios.lflag & ECHO) {
                    NLib::ScopeIRQSpinlock guard2(&this->outlock);
                    if (this->termios.lflag & ECHOKE) {
                        // ECHOKE: Visually erase the line by backspacing over each character.
                        for (size_t i = 0; i < linesize; i++) {
                            this->outbuffer.push('\b');
                            this->outbuffer.push(' ');
                            this->outbuffer.push('\b');
                            if (canwrite) {
                                writefn("\b \b", 3);
                            }
                        }
                    } else if (this->termios.lflag & ECHOK) {
                        // ECHOK: Echo ^U and newline.
                        this->outbuffer.push('^');
                        this->outbuffer.push(this->termios.cc.vkill + 0x40);
                        this->outbuffer.push('\n');
                        if (canwrite) {
                            char cc[3];
                            cc[0] = '^';
                            cc[1] = this->termios.cc.vkill + 0x40;
                            cc[2] = '\n';
                            writefn(cc, 3);
                        }
                    }
                }

                // Actually clear the line buffer.
                this->linebuffer.clear();
                return;
            } else if (c == this->termios.cc.veof) {
                // Ctrl+D: flush the line buffer.
                NLib::ScopeIRQSpinlock guard(&this->linelock);
                if (this->linebuffer.empty()) {
                    this->pendingeof = true;
                } else {
                    this->pendingflush = true;
                }
                if (NSched::initialised) {
                    this->readwait.wakeone();
                }
                return;
            } else if ((this->termios.lflag & IEXTEN) && c == this->termios.cc.vwerase) {
                // VWERASE (Ctrl+W): erase the last word.
                // A word is defined as a sequence of non-whitespace characters.
                NLib::ScopeIRQSpinlock guard(&this->linelock);

                // First, skip trailing whitespace.
                while (!this->linebuffer.empty()) {
                    char last = this->linebuffer.peek(this->linebuffer.size() - 1);
                    if (last != ' ' && last != '\t') {
                        break;
                    }
                    this->linebuffer.popback();
                    if ((this->termios.lflag & ECHO) && (this->termios.lflag & ECHOE) && canwrite) {
                        writefn("\b \b", 3);
                    }
                }

                // Then, erase the word itself (non-whitespace chars).
                while (!this->linebuffer.empty()) {
                    char last = this->linebuffer.peek(this->linebuffer.size() - 1);
                    if (last == ' ' || last == '\t') {
                        break;
                    }
                    this->linebuffer.popback();
                    if ((this->termios.lflag & ECHO) && (this->termios.lflag & ECHOE) && canwrite) {
                        // If the erased char was a control char echoed as ^X,
                        // we need to erase two columns.
                        if ((this->termios.lflag & ECHOCTL) && last < 32 && last != '\t' && last != '\n') {
                            writefn("\b \b\b \b", 6);
                        } else {
                            writefn("\b \b", 3);
                        }
                    }
                }
                return;
            } else if ((this->termios.lflag & IEXTEN) && c == this->termios.cc.vreprint) {
                // VREPRINT (Ctrl+R): reprint the current input line.
                if ((this->termios.lflag & ECHO) && canwrite) {
                    // Echo ^R and newline first.
                    if (this->termios.lflag & ECHOCTL) {
                        writefn("^R\n", 3);
                    }

                    NLib::ScopeIRQSpinlock guard(&this->linelock);
                    for (size_t i = 0; i < this->linebuffer.size(); i++) {
                        char ch = this->linebuffer.peek(i);
                        if ((this->termios.lflag & ECHOCTL) && ch < 32 && ch != '\t' && ch != '\n') {
                            char ctrl[2] = { '^', (char)(ch + 0x40) };
                            writefn(ctrl, 2);
                        } else {
                            writefn(&ch, 1);
                        }
                    }
                }
                return;
            } else if ((this->termios.lflag & IEXTEN) && c == this->termios.cc.vlnext) {
                // VLNEXT (Ctrl+V): the next character is taken literally.
                this->vlnextpending = true;
                if ((this->termios.lflag & ECHO) && (this->termios.lflag & ECHOCTL) && canwrite) {
                    writefn("^V", 2);
                }
                return;
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
                if (NSched::initialised) {
                    this->readwait.wakeone(); // We have a full line now. Wake one waiter.
                }
                return;
                // Forced to flush output to buffer, we've finished this line.
                // POLLIN. We've got data! Canonical mode only does this if it finds a line.
            }

            // if (c >= 32 && c <= 126) { // Add if printable.
                NLib::ScopeIRQSpinlock guard(&this->linelock);
                this->linebuffer.push(c);
                bool shouldecho = (this->termios.lflag & ECHO) || (!(this->termios.lflag & ECHO) && (this->termios.lflag & ECHONL) && (c == '\n'));
                if (shouldecho) {
                    // ECHOCTL: Echo control characters as ^X (except TAB, NL, and START/STOP chars).
                    if ((this->termios.lflag & ECHOCTL) && c < 32 && c != '\t' && c != '\n' &&
                        c != this->termios.cc.vstart && c != this->termios.cc.vstop) {
                        char ctrl[2] = { '^', (char)(c + 0x40) };
                        if (canwrite) {
                            writefn(ctrl, 2);
                        }
                        NLib::ScopeIRQSpinlock guard(&this->outlock);
                        this->outbuffer.push(ctrl[0]);
                        this->outbuffer.push(ctrl[1]);
                    } else {
                        if (canwrite) {
                            writefn(&c, 1);
                        }
                        NLib::ScopeIRQSpinlock guard(&this->outlock);
                        this->outbuffer.push(c);
                    }
                }
            // }
        } else {
            if (canwrite && this->termios.lflag & ECHO) {
                writefn(&c, 1);
            }
            NLib::ScopeIRQSpinlock guard(&this->inlock);

            this->inbuffer.push(c); // Append character to input buffer. Raw mode doesn't process any input.

            if (NSched::initialised) {
                this->readwait.wakeone();
            }
            // POLLIN. Raw will notify for every appending character.
        }
    }

    static bool hasline(NLib::CircularBuffer<char> *buf, char eol, char eof, bool pendingflush) {
        if (pendingflush) {
            return true; // VEOF mid-line: data is ready without a delimiter.
        }
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
        NSched::Process *proc = thread->process;

        // Check if this is a background process trying to read.
        // POSIX: Background processes receive SIGTTIN unless:
        // 1. SIGTTIN is ignored → return EIO
        // 2. SIGTTIN is blocked → return EIO
        // 3. Process group is orphaned → return EIO
        {
            NLib::ScopeIRQSpinlock ctrlguard(&this->ctrllock);
            if (this->fpgrp && proc->pgrp && proc->pgrp != this->fpgrp) {
                // Check if process is in the same session as the TTY.
                if (this->session && proc->session == this->session) {
                    bool orphaned = true;
                    proc->pgrp->lock.acquire();
                    NLib::DoubleList<NSched::Process *>::Iterator it = proc->pgrp->procs.begin();
                    for (; it.valid(); it.next()) {
                        NSched::Process *member = *it.get();
                        if (!member) {
                            continue;
                        }
                        member->lock.acquire();
                        NSched::Process *parent = member->parent;
                        if (parent) {
                            parent->lock.acquire();
                            // Parent exists, in same session, different pgrp?
                            if (parent->session == proc->session && parent->pgrp != proc->pgrp) {
                                orphaned = false;
                            }
                            parent->lock.release();
                        }
                        member->lock.release();
                        if (!orphaned) {
                            break;
                        }
                    }
                    proc->pgrp->lock.release();

                    if (orphaned) {
                        // Orphaned process group: return EIO without sending signal.
                        return -EIO;
                    }

                    // Check if SIGTTIN is ignored or blocked (per-thread).
                    NSched::Thread *thread = NArch::CPU::get()->currthread;
                    proc->lock.acquire();
                    bool ignored = (NSched::gethandler(&proc->signalstate, SIGTTIN) == SIG_IGN);
                    bool blocked = NSched::isblocked(&thread->blocked, SIGTTIN);
                    proc->lock.release();

                    if (ignored || blocked) {
                        // SIGTTIN is ignored or blocked: return EIO without sending signal.
                        return -EIO;
                    }

                    // Send SIGTTIN to the background process group.
                    NSched::signalpgrp(proc->pgrp, SIGTTIN);
                    return -EIO;
                }
            }
        }

        if (!count) {
            return 0;
        }

        if (this->termios.lflag & ICANON) {
            // Create an IRQSpinlock guard to manage line lock (because input interrupt sources also acquire this lock).
            this->linelock.acquire();
            // If an EOF was received at the start of the line, return EOF (0).
            if (this->pendingeof && this->linebuffer.empty()) {
                this->pendingeof = false;
                this->linelock.release();
                return 0;
            }

            if ((fdflags & VFS::O_NONBLOCK) && this->linebuffer.empty()) {
                this->linelock.release();
                return -EAGAIN; // There's nothing we can do. Caller should try again when we have data.
            }

            // Wait for a full line.
            int ret;
            waiteventinterruptiblelocked(
                &this->readwait,
                hasline(&this->linebuffer, this->termios.cc.veol, this->termios.cc.veof, this->pendingflush) || this->pendingeof,
                &this->linelock,
                ret
            );

            if (ret < 0) {
                this->linelock.release();
                return ret; // Interrupted by signal.
            }

            // Check for EOF again (may have been set while waiting).
            if (this->pendingeof && this->linebuffer.empty()) {
                this->pendingeof = false;
                this->linelock.release();
                return 0;
            }

            bool wasflushed = this->pendingflush;
            this->pendingflush = false;

            size_t tocopy = this->linebuffer.size();
            if (tocopy > count) { // If there is more data in the line than the user wants, we should only copy out as much the caller wants.
                tocopy = count;
            }

            uint8_t kbuf[256];
            size_t kbufidx = 0;

            for (size_t i = 0; i < tocopy;) {
                // Minimum between remaining to copy and size of kbuf.
                size_t chunk = (sizeof(tocopy - i) < sizeof(kbuf)) ? (tocopy - i) : sizeof(kbuf);
                for (size_t j = 0; j < chunk; j++) {
                    kbuf[j] = this->linebuffer.pop();
                    kbufidx++;
                }

                if (kbufidx > 0) {
                    size_t ret = NMem::UserCopy::copyto(buf + i, (const char *)kbuf, kbufidx);
                    if (ret < 0) {
                        // Failed to copy to user.
                        this->linelock.release();
                        return ret;
                    }
                }
                i += chunk;
                kbufidx = 0;
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
            int ret;
            waiteventinterruptiblelocked(
                &this->readwait,
                this->inbuffer.size() >= this->termios.cc.vmin, // Wait until we have at least VMIN characters.
                &this->inlock,
                ret
            );

            if (ret < 0) {
                this->inlock.release();
                return ret; // Interrupted by signal.
            }

            size_t toread = this->inbuffer.size();

            if (toread > count) {
                toread = count;
            }

            char kbuf[256];
            size_t kbufidx = 0;
            for (size_t i = 0; i < toread;) {
                size_t chunk = (sizeof(toread - i) < sizeof(kbuf)) ? (toread - i) : sizeof(kbuf);
                for (size_t j = 0; j < chunk; j++) {
                    kbuf[j] = this->inbuffer.pop();
                    kbufidx++;
                }

                if (kbufidx > 0) {
                    size_t ret = NMem::UserCopy::copyto(buf + i, (const char *)kbuf, kbufidx);
                    if (ret < 0) {
                        // Failed to copy to user.
                        this->inlock.release();
                        return ret;
                    }
                }
                i += chunk;
                kbufidx = 0;
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
        NSched::Process *proc = thread->process;

        // Check if this is a background process trying to write.
        // POSIX: Background processes receive SIGTTOU if TOSTOP is set, unless:
        // 1. SIGTTOU is ignored → allow write
        // 2. SIGTTOU is blocked → allow write
        // 3. Process group is orphaned → return EIO
        if (this->fpgrp && proc->pgrp && proc->pgrp != this->fpgrp) {
            // Only check SIGTTOU if TOSTOP is set.
            if (this->termios.lflag & TOSTOP) {
                // Check if process is in the same session as the TTY.
                if (this->session && proc->session == this->session) {
                    // Check if SIGTTOU is ignored or blocked (per-thread).
                    NSched::Thread *thread = NArch::CPU::get()->currthread;
                    proc->lock.acquire();
                    bool ignored = (NSched::gethandler(&proc->signalstate, SIGTTOU) == SIG_IGN);
                    bool blocked = NSched::isblocked(&thread->blocked, SIGTTOU);
                    proc->lock.release();

                    if (ignored || blocked) {
                        // SIGTTOU is ignored or blocked: allow write to proceed.
                        goto dowrite;
                    }

                    // Check if process group is orphaned.
                    bool orphaned = true;
                    proc->pgrp->lock.acquire();
                    NLib::DoubleList<NSched::Process *>::Iterator it = proc->pgrp->procs.begin();
                    for (; it.valid(); it.next()) {
                        NSched::Process *member = *it.get();
                        if (!member) {
                            continue;
                        }
                        member->lock.acquire();
                        NSched::Process *parent = member->parent;
                        if (parent) {
                            parent->lock.acquire();
                            if (parent->session == proc->session && parent->pgrp != proc->pgrp) {
                                orphaned = false;
                            }
                            parent->lock.release();
                        }
                        member->lock.release();
                        if (!orphaned) {
                            break;
                        }
                    }
                    proc->pgrp->lock.release();

                    if (orphaned) {
                        // Orphaned process group: return EIO without sending signal.
                        return -EIO;
                    }

                    // Send SIGTTOU to the background process group.
                    NSched::signalpgrp(proc->pgrp, SIGTTOU);
                    return -EIO;
                }
            }
        }

dowrite:

        // Apply output processing if OPOST is set.
        if (this->termios.oflag & OPOST) {
            // Process each character according to output flags.
            for (size_t i = 0; i < count; i++) {
                char c = buf[i];

                // OLCUC: Map lowercase to uppercase.
                if ((this->termios.oflag & OLCUC) && c >= 'a' && c <= 'z') {
                    c = c - 'a' + 'A';
                }

                // ONLCR: Map NL to CR-NL.
                if ((this->termios.oflag & ONLCR) && c == '\n') {
                    if (writefn) {
                        writefn("\r\n", 2);
                    }
                    NLib::ScopeIRQSpinlock guard(&this->outlock);
                    this->outbuffer.push('\r');
                    this->outbuffer.push('\n');
                    continue;
                }

                // OCRNL: Map CR to NL.
                if ((this->termios.oflag & OCRNL) && c == '\r') {
                    c = '\n';
                }

                if (writefn) {
                    writefn(&c, 1);
                }
                NLib::ScopeIRQSpinlock guard(&this->outlock);
                this->outbuffer.push(c);
            }
        } else {
            // No output processing, write raw.
            if (writefn) {
                writefn(buf, count);
            }

            NLib::ScopeIRQSpinlock guard(&this->outlock);
            for (size_t i = 0; i < count; i++) {
                this->outbuffer.push(buf[i]);
            }
        }

        return count;
    }

    int TTY::poll(short events, short *revents, int fdflags) {
        (void)fdflags;
        *revents = 0;

        if ((events & VFS::POLLIN) || (events & VFS::POLLRDNORM)) {
            if (this->termios.lflag & ICANON) {
                NLib::ScopeIRQSpinlock guard(&this->linelock);
                if (hasline(&this->linebuffer, this->termios.cc.veol, this->termios.cc.veof, this->pendingflush) || this->pendingeof) {
                    *revents |= (events & (VFS::POLLIN | VFS::POLLRDNORM));
                }
            } else {
                NLib::ScopeIRQSpinlock guard(&this->inlock);
                if (this->inbuffer.size() >= this->termios.cc.vmin) {
                    *revents |= (events & (VFS::POLLIN | VFS::POLLRDNORM));
                }
            }
        }

        if ((events & VFS::POLLOUT) || (events & VFS::POLLWRNORM)) {
            NLib::ScopeIRQSpinlock guard(&this->outlock);
            if (!this->outbuffer.full()) {
                *revents |= (events & (VFS::POLLOUT | VFS::POLLWRNORM));
            }
        }

        return 0;
    }





    // Driver implementation begins here.





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

                DEVFS::registerdevfile("tty0", st);
                st.st_rdev = CURDEVICEID;
                // Should be rw by all users. It's not an actual device itself, it just points to the current one.
                st.st_mode = (VFS::S_IRUSR | VFS::S_IWUSR | VFS::S_IRGRP | VFS::S_IWGRP | VFS::S_IROTH | VFS::S_IWOTH) | VFS::S_IFCHR;

                DEVFS::registerdevfile("tty", st);

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
                    NUtil::snprintf(path, sizeof(path), "tty%lu", minor);
                    DEVFS::registerdevfile(path, st);
                }

                handler.connect = NULL;
                handler.disconnect = NULL;
                handler.evsubscription = Input::event::KEY; // Subscribe to keyboard events.
                handler.event = event;
                Input::registerhandler(&handler); // Register handler.
            }

            static void event(uint64_t tmstmp, uint16_t type, uint16_t code, int32_t value) {
                (void)tmstmp;
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

                    if (ctrl && alted) {
                        if (code >= Input::key::KF1 && code <= Input::key::KF9) {
                            // XXX: VT Switching.
                            // currentvt = 1 + (code - Input::key::KF1);
                            return;
                        }
                    }

                    // Helper lambda to write an escape sequence string to the active TTY.
                    auto writeesc = [](const char *s, size_t n) {
                        for (size_t i = 0; i < n; i++) {
                            ttys[currentvt - 1]->tty->process(s[i], NLimine::console_write);
                        }
                    };

                    { // Emit arrow key codes.
                        const char *esccode = NULL;
                        switch (code) {
                            case Input::key::KUP:    esccode = "\x1b[A"; break;
                            case Input::key::KDOWN:  esccode = "\x1b[B"; break;
                            case Input::key::KRIGHT: esccode = "\x1b[C"; break;
                            case Input::key::KLEFT:  esccode = "\x1b[D"; break;
                            default: break;
                        }

                        if (esccode) {
                            writeesc(esccode, NLib::strlen(esccode));
                            return;
                        }
                    }

                    {
                        const char *esccode = NULL;
                        switch (code) {
                            case Input::key::KHOME:     esccode = "\x1b[1~"; break;
                            case Input::key::KINSERT:   esccode = "\x1b[2~"; break;
                            case Input::key::KDELETE:   esccode = "\x1b[3~"; break;
                            case Input::key::KEND:      esccode = "\x1b[4~"; break;
                            case Input::key::KPAGEUP:   esccode = "\x1b[5~"; break;
                            case Input::key::KPAGEDOWN: esccode = "\x1b[6~"; break;
                            default: break;
                        }

                        if (esccode) {
                            writeesc(esccode, NLib::strlen(esccode));
                            return;
                        }
                    }

                    {
                        const char *esccode = NULL;
                        switch (code) {
                            case Input::key::KF1:  esccode = "\x1b[[A";  break;
                            case Input::key::KF2:  esccode = "\x1b[[B";  break;
                            case Input::key::KF3:  esccode = "\x1b[[C";  break;
                            case Input::key::KF4:  esccode = "\x1b[[D";  break;
                            case Input::key::KF5:  esccode = "\x1b[[E";  break;
                            case Input::key::KF6:  esccode = "\x1b[17~"; break;
                            case Input::key::KF7:  esccode = "\x1b[18~"; break;
                            case Input::key::KF8:  esccode = "\x1b[19~"; break;
                            case Input::key::KF9:  esccode = "\x1b[20~"; break;
                            case Input::key::KF10: esccode = "\x1b[21~"; break;
                            case Input::key::KF11: esccode = "\x1b[23~"; break;
                            case Input::key::KF12: esccode = "\x1b[24~"; break;
                            default: break;
                        }

                        if (esccode) {
                            writeesc(esccode, NLib::strlen(esccode));
                            return;
                        }
                    }

                    // Ctrl+letter produces a control character (e.g. Ctrl+C = 0x03).
                    if (ctrl) {
                        if ((asciitable[code] >= 'a' && asciitable[code] <= 'z') || (asciitable[code] >= 'A' && asciitable[code] <= '\\')) {
                            ascii = asciitable[code] >= 'a' ? asciitable[code] - 0x60 : asciitable[code] - 0x40;
                            ttys[currentvt - 1]->tty->process(ascii, NLimine::console_write);
                        }
                        return;
                    }

                    // Alt+key sends ESC prefix followed by the character.
                    if (alted) {
                        if (code < Input::key::KMAX) {
                            bool upshift = shifted;
                            if (asciitable[code] >= 'a' && asciitable[code] <= 'z') {
                                upshift ^= capslock;
                            }
                            ascii = upshift ? asciitableshift[code] : asciitable[code];
                        }
                        if (ascii != '\0') {
                            ttys[currentvt - 1]->tty->process('\x1b', NLimine::console_write);
                            ttys[currentvt - 1]->tty->process(ascii, NLimine::console_write);
                        }
                        return;
                    }

                    // Regular key (no modifiers, or shift only).
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

            // Get the device ID of the controlling TTY for the current process.
            uint64_t getcttydev(void) {
                NSched::Process *proc = NArch::CPU::get()->currthread->process;
                uint64_t ctty = __atomic_load_n(&proc->tty, memory_order_relaxed);
                return ctty;
            }

            int stat(uint64_t dev, struct NFS::VFS::stat *st) override {
                if (dev == CURDEVICEID) {
                    uint64_t cttydev = this->getcttydev();
                    if (cttydev == 0) {
                        return -ENXIO; // No controlling terminal.
                    }
                    return stat(cttydev, st); // Forward to actual TTY.
                } else if (dev == CURVTDEVICEID) {
                    assert((currentvt - 1) < MAXTTYS, "Current VT exceeds number of TTYs.\n");
                    return stat(DEVFS::makedev(MAJOR, currentvt), st); // Forward to current VT.
                }
                return DEVFS::NOSTAT; // Default to node fill of our stat.
            }

            ssize_t read(uint64_t dev, void *buf, size_t count, off_t offset, int fdflags) override {
                if (dev == CURDEVICEID) { // Device is /dev/tty
                    uint64_t cttydev = this->getcttydev();
                    if (cttydev == 0) {
                        return -ENXIO; // No controlling terminal.
                    }
                    return read(cttydev, buf, count, offset, fdflags); // Forward to actual TTY.
                } else if (dev == CURVTDEVICEID) { // Device is /dev/tty0
                    assert((currentvt - 1) < MAXTTYS, "Current VT exceeds number of TTYs.\n");
                    return read(DEVFS::makedev(MAJOR, currentvt), buf, count, offset, fdflags); // Forward to current VT.
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
                    uint64_t cttydev = this->getcttydev();
                    if (cttydev == 0 || (DEVFS::major(cttydev) != MAJOR || DEVFS::minor(cttydev) > MAXMINOR)) {
                        return -ENXIO; // No controlling terminal.
                    }
                    return write(cttydev, buf, count, offset, fdflags); // Forward to actual TTY.
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
                    uint64_t cttydev = this->getcttydev();
                    if (cttydev == 0) {
                        return -ENXIO; // No controlling terminal.
                    }
                    return ioctl(cttydev, request, arg); // Forward to actual TTY.
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

                            // Only session leaders can acquire a controlling terminal.
                            proc->lock.acquire();
                            bool is_session_leader = proc->session && proc->session->id == proc->id;
                            NSched::Session *proc_session = proc->session;
                            proc->lock.release();

                            if (!is_session_leader) {
                                tty->devlock.release();
                                return -EPERM;
                            }

                            // If session already has a controlling terminal, cannot acquire another.
                            if (proc_session->ctty != 0) {
                                tty->devlock.release();
                                return -EPERM;
                            }

                            // If TTY already has a session, must force it (arg == 1) if we're root.
                            if (tty->tty->session) {
                                if (arg != 1) {
                                    tty->devlock.release();
                                    return -EPERM;
                                }
                                proc->lock.acquire();
                                if (proc->euid != 0) {
                                    proc->lock.release();
                                    tty->devlock.release();
                                    return -EPERM;
                                }
                                proc->lock.release();
                            }

                            // Set up the controlling terminal.
                            {
                                NLib::ScopeIRQSpinlock ctrlguard(&tty->tty->ctrllock);

                                // Release old references.
                                if (tty->tty->session) {
                                    tty->tty->session->unref();
                                }
                                if (tty->tty->fpgrp) {
                                    tty->tty->fpgrp->unref();
                                }

                                // Set new values and take references.
                                tty->tty->session = proc_session;
                                tty->tty->fpgrp = proc->pgrp;

                                if (tty->tty->session) {
                                    tty->tty->session->ref();
                                }
                                if (tty->tty->fpgrp) {
                                    tty->tty->fpgrp->ref();
                                }
                            }
                            proc_session->ctty = tty->id;

                            // Store TTY device ID in process structure directly.
                            __atomic_store_n(&proc->tty, tty->id, memory_order_relaxed);

                            tty->devlock.release();
                            return 0;
                        }
                        case TTY::ioctls::TIOCGPGRP: {
                            if (!arg) {
                                tty->devlock.release();
                                return -EINVAL;
                            }

                            int pgid = 0;
                            {
                                NLib::ScopeIRQSpinlock ctrlguard(&tty->tty->ctrllock);
                                if (tty->tty->fpgrp) {
                                    pgid = (int)tty->tty->fpgrp->id;
                                }
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
                            if (!ppgrp || !*ppgrp) {
                                tty->devlock.release();
                                return -ESRCH;
                            }
                            NSched::ProcessGroup *target = (*ppgrp)->pgrp;
                            if (!target) {
                                tty->devlock.release();
                                return -ESRCH;
                            }

                            NSched::Process *caller = NArch::CPU::get()->currthread->process;

                            // The caller must be in the same session as the TTY.
                            {
                                NLib::ScopeIRQSpinlock ctrlguard(&tty->tty->ctrllock);
                                if (!tty->tty->session || !caller->session || caller->session != tty->tty->session) {
                                    tty->devlock.release();
                                    return -ENOTTY;
                                }

                                // The target process group must be in the same session as the TTY.
                                if (!target->session || target->session != tty->tty->session) {
                                    tty->devlock.release();
                                    return -EPERM;
                                }

                                // Release old reference.
                                if (tty->tty->fpgrp) {
                                    tty->tty->fpgrp->unref();
                                }

                                // Accept the requested process group as the foreground pgrp.
                                tty->tty->fpgrp = target;
                                tty->tty->fpgrp->ref();
                            }
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
                        case TTY::ioctls::TIOCSWINSZ: {
                            if (!arg) {
                                tty->devlock.release();
                                return -EINVAL;
                            }
                            struct TTY::winsize oldsize = tty->tty->winsize;
                            ret = NMem::UserCopy::copyfrom(&tty->tty->winsize, (void *)arg, sizeof(struct TTY::winsize));
                            if (ret >= 0) {
                                // POSIX: Send SIGWINCH to foreground process group if size changed.
                                if ((oldsize.row != tty->tty->winsize.row || oldsize.col != tty->tty->winsize.col) &&
                                    tty->tty->fpgrp) {
                                    NSched::signalpgrp(tty->tty->fpgrp, SIGWINCH);
                                }
                            }
                            tty->devlock.release();
                            return ret;
                        }

                        case TTY::ioctls::TIOCNOTTY: {
                            // Give up the controlling terminal.
                            NSched::Process *proc = NArch::CPU::get()->currthread->process;

                            // Process must be session leader to give up ctty this way.
                            proc->lock.acquire();
                            bool is_session_leader = proc->session && proc->session->id == proc->id;
                            NSched::Session *proc_session = proc->session;
                            proc->lock.release();

                            if (!is_session_leader) {
                                tty->devlock.release();
                                return -EPERM;
                            }

                            // Check that this is actually the controlling terminal.
                            if (tty->tty->session != proc_session) {
                                tty->devlock.release();
                                return -ENOTTY;
                            }

                            // Dissociate.
                            tty->tty->session = NULL;
                            tty->tty->fpgrp = NULL;
                            if (proc_session) {
                                proc_session->ctty = 0;
                            }
                            __atomic_store_n(&proc->tty, 0, memory_order_relaxed);

                            tty->devlock.release();
                            return 0;
                        }

                        case TTY::ioctls::TIOCGSID: {
                            // Get session ID of the TTY.
                            if (!arg) {
                                tty->devlock.release();
                                return -EINVAL;
                            }

                            NSched::Process *proc = NArch::CPU::get()->currthread->process;

                            // Caller must be in the same session as the TTY.
                            if (!tty->tty->session || !proc->session || proc->session != tty->tty->session) {
                                tty->devlock.release();
                                return -ENOTTY;
                            }

                            int sid = (int)tty->tty->session->id;
                            ret = NMem::UserCopy::copyto((void *)arg, &sid, sizeof(sid));
                            tty->devlock.release();
                            return ret;
                        }

                        case TTY::ioctls::FIONREAD: {
                            // Get number of bytes available for reading (TIOCINQ is alias).
                            if (!arg) {
                                tty->devlock.release();
                                return -EINVAL;
                            }

                            int count = 0;
                            if (tty->tty->termios.lflag & TTY::ICANON) {
                                NLib::ScopeIRQSpinlock guard(&tty->tty->linelock);
                                count = (int)tty->tty->linebuffer.size();
                            } else {
                                NLib::ScopeIRQSpinlock guard(&tty->tty->inlock);
                                count = (int)tty->tty->inbuffer.size();
                            }

                            ret = NMem::UserCopy::copyto((void *)arg, &count, sizeof(count));
                            tty->devlock.release();
                            return ret;
                        }

                        case TTY::ioctls::TIOCOUTQ: {
                            // Get number of bytes in output buffer.
                            if (!arg) {
                                tty->devlock.release();
                                return -EINVAL;
                            }

                            NLib::ScopeIRQSpinlock guard(&tty->tty->outlock);
                            int count = (int)tty->tty->outbuffer.size();

                            ret = NMem::UserCopy::copyto((void *)arg, &count, sizeof(count));
                            tty->devlock.release();
                            return ret;
                        }

                        case TTY::ioctls::TCXONC: {
                            // Flow control operations.
                            tty->devlock.release();
                            return 0;
                        }

                        case TTY::ioctls::TCSBRK: {
                            // Send break. For virtual terminals, this is essentially a no-op.
                            tty->devlock.release();
                            return 0;
                        }

                        case TTY::ioctls::TTYNAME:
                            if (!arg) {
                                tty->devlock.release();
                                return -EINVAL;
                            }

                            {
                                char namebuf[32];
                                NUtil::snprintf(namebuf, sizeof(namebuf), "/dev/tty%u", DEVFS::minor(tty->id));

                                ret = NMem::UserCopy::copyto((void *)arg, namebuf, NLib::strlen(namebuf) + 1);
                                tty->devlock.release();
                                return ret;
                            }

                        default:
                            tty->devlock.release();
                            return -EINVAL;
                    }
                }
                return -EINVAL;
            }

            int poll(uint64_t dev, short events, short *revents, int fdflags) override {
                if (dev == CURDEVICEID) {
                    uint64_t cttydev = this->getcttydev();
                    if (cttydev == 0) {
                        return -ENXIO; // No controlling terminal.
                    }
                    return poll(cttydev, events, revents, fdflags); // Forward to actual TTY.
                } else if (dev == CURVTDEVICEID) {
                    return poll(DEVFS::makedev(MAJOR, currentvt), events, revents, fdflags);
                } else {
                    uint32_t num = DEVFS::minor(dev) - 1;

                    TTYDevice *tty = ttys[num];
                    int ret = tty->tty->poll(events, revents, fdflags);
                    return ret;
                }
                return 0;
            }
    };

    static struct reginfo info = {
        .name = "tty",
        .type = reginfo::GENERIC,
        .match = { }
    };

    REGDRIVER(TTYDriver, &info);
}
