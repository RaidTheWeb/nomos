#ifndef _DEV__DRIVERS__TTY_HPP
#define _DEV__DRIVERS__TTY_HPP

#include <dev/dev.hpp>
#include <lib/list.hpp>
#include <sched/event.hpp>
#include <sched/jobctrl.hpp>

namespace NDev {
    class TTY {
        private:
            NSched::WaitQueue readwait;
            NSched::WaitQueue writewait; // For writing when we can't do it immediately.
        public:
            enum iflags {
                IGNBRK          = (1 << 0),
                BRKINT          = (1 << 1),
                IGNPAR          = (1 << 2),
                PARMRK          = (1 << 3),
                INPCK           = (1 << 4),
                ISTRIP          = (1 << 5),
                INLCR           = (1 << 6),
                IGNCR           = (1 << 7),
                ICRNL           = (1 << 8),
                IUCLC           = (1 << 9),
                IXON            = (1 << 10),
                IXANY           = (1 << 11),
                IXOFF           = (1 << 12),
                IMAXBEL         = (1 << 13)
            };

            enum oflags {
                OPOST           = (1 << 0),
                OLCUC           = (1 << 1),
                ONLCR           = (1 << 2),
                OCRNL           = (1 << 3),
                ONOCR           = (1 << 4),
                ONLRET          = (1 << 5),
                OFILL           = (1 << 6),
                OFDEL           = (1 << 7)
            };

            enum cflags {
                // Character size (CS5-CS8)
                CSIZE           = 0x30,
                CS5             = 0x00,
                CS6             = 0x10,
                CS7             = 0x20,
                CS8             = 0x30, // We only really support this.
                CSTOPB          = (1 << 6),  // 2 stop bits
                CREAD           = (1 << 7),  // Enable receiver
                PARENB          = (1 << 8),  // Enable parity
                PARODD          = (1 << 9),  // Odd parity
                HUPCL           = (1 << 10), // Hang up on close
                CLOCAL          = (1 << 11)  // Ignore modem control lines
            };

            enum lflags {
                ISIG            = (1 << 0),
                ICANON          = (1 << 1),
                XCASE           = (1 << 2),  // Canonical upper/lower presentation
                ECHO            = (1 << 3),
                ECHOE           = (1 << 4),
                ECHOK           = (1 << 5),
                ECHONL          = (1 << 6),
                NOFLSH          = (1 << 7),
                TOSTOP          = (1 << 8),
                ECHOCTL         = (1 << 9),  // Echo control chars as ^X
                ECHOPRT         = (1 << 10), // Echo erased chars
                ECHOKE          = (1 << 11), // Visual erase for VKILL
                FLUSHO          = (1 << 12), // Output being flushed (state flag)
                PENDIN          = (1 << 14), // Retype pending input
                IEXTEN          = (1 << 15)  // Enable impl-defined input processing
            };

            enum ioctls {
                TCGETS          = 0x5401,
                TCSETS          = 0x5402,
                TCSETSW         = 0x5403,
                TCSETSF         = 0x5404,
                TCSBRK          = 0x5405,
                TCXONC          = 0x5406,
                TCFLSH          = 0x5407,
                TIOCEXCL        = 0x540c, // Set exclusive mode
                TIOCNXCL        = 0x540d, // Clear exclusive mode
                TIOCSCTTY       = 0x540e,
                TIOCGPGRP       = 0x540f,
                TIOCSPGRP       = 0x5410,
                TIOCOUTQ        = 0x5411, // Output queue size
                TIOCSTI         = 0x5412, // Simulate terminal input
                TIOCGWINSZ      = 0x5413,
                TIOCSWINSZ      = 0x5414,
                TIOCMGET        = 0x5415, // Get modem bits
                TIOCMBIS        = 0x5416, // Set modem bits
                TIOCMBIC        = 0x5417, // Clear modem bits
                TIOCMSET        = 0x5418, // Set modem bits
                TIOCGSOFTCAR    = 0x5419, // Get software carrier flag
                TIOCSSOFTCAR    = 0x541a, // Set software carrier flag
                FIONREAD        = 0x541b, // Get input queue size (aka TIOCINQ)
                TIOCINQ         = 0x541b, // Alias for FIONREAD
                TIOCNOTTY       = 0x5422, // Give up controlling terminal
                TIOCGETD        = 0x5424, // Get line discipline
                TIOCSETD        = 0x5425, // Set line discipline
                TIOCSBRK        = 0x5427, // Set break
                TIOCCBRK        = 0x5428, // Clear break
                TIOCGSID        = 0x5429, // Get session ID
                TIOCGRS485      = 0x542e, // Get RS485 config
                TIOCSRS485      = 0x542f, // Set RS485 config

                // Non-POSIX special ioctl to get the TTY name.
                TTYNAME         = 0x16789123
            };

            struct winsize {
                uint16_t row;
                uint16_t col;
                uint16_t xpixel;
                uint16_t ypixel;
            };

            struct cc {
                uint8_t vintr; // CTRL+C.
                uint8_t vquit; /* CTRL+\. */
                uint8_t verase; // Backspace.
                uint8_t vkill; // Ctrl+U.
                uint8_t veof; // Ctrl+D.
                uint8_t vtime; // Non-canon read timeout.
                uint8_t vmin; // Minimum for non-canon read.
                uint8_t vswtch; // Switch character.
                uint8_t vstart; // CTRL+Q.
                uint8_t vstop; // CTRL+S.
                uint8_t vsusp; // CTRL+Z.
                uint8_t veol; // EOL alt.
                uint8_t vreprint; // CTRL+R.
                uint8_t vdiscard; // CTRL+O.
                uint8_t vwerase; // CTRL+W.
                uint8_t vlnext; // CTRL+V.
                uint8_t veol2;
                uint8_t padding[17];
            };

            struct termios {
                uint32_t iflag;
                uint32_t oflag;
                uint32_t cflag;
                uint32_t lflag;
                uint8_t line;
                struct cc cc;
                uint32_t ibaud;
                uint32_t obaud;
            };

            struct termios termios;
            struct winsize winsize;

            NLib::CircularBuffer<char> inbuffer;
            NArch::IRQSpinlock inlock;
            NLib::CircularBuffer<char> outbuffer;
            NArch::IRQSpinlock outlock;
            NLib::CircularBuffer<char> linebuffer;
            NArch::IRQSpinlock linelock;

            // Multi-lock ordering:
            // 1. linelock
            // 2. outlock
            // 3. inlock

            bool pending_eof = false;

            // Job control structures:
            NSched::ProcessGroup *fpgrp = NULL; // Foreground process group.
            NSched::Session *session = NULL;
            NArch::Spinlock ctrllock;

            TTY(void);

            // Process an individual character. Written to read buffer. Takes a callback to a write function, this handles echoing of characters and such.
            void process(char c, void (*writefn)(const char *str, size_t count));
            // Read characters post-processing.
            ssize_t read(char *buf, size_t count, int fdflags);
            // Write character, with driver write.
            ssize_t write(const char *buf, size_t count, int fdflags, void (*writefn)(const char *str, size_t count));
            int poll(short events, short *revents, int fdflags);

            // NOTE: The TTY provides no way to manage writing to it. This is driver/implementation specific and should be handled separately.
    };

    class TTYDevice : public Device {
        private:
        public:

            TTY *tty = NULL;
            NSched::Mutex devlock; // Lock for device access.

            TTYDevice(uint64_t id, DevDriver *driver) : Device(id, driver) {
                this->tty = new TTY();
            }
    };
}

#endif
