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
            };

            enum lflags {
                ISIG            = (1 << 0),
                ICANON          = (1 << 1),
                ECHO            = (1 << 3),
                ECHOE           = (1 << 4),
                ECHOK           = (1 << 5),
                ECHONL          = (1 << 6),
                NOFLSH          = (1 << 7),
                TOSTOP          = (1 << 8)
            };

            enum ioctls {
                TCGETS          = 0x5401,
                TCSETS          = 0x5402,
                TCSETSW         = 0x5403,
                TCSETSF         = 0x5404,
                TCSBRK          = 0x5405,
                TCXONC          = 0x5406,
                TCFLSH          = 0x5407,
                TIOCSCTTY       = 0x540e,
                TIOCGPGRP       = 0x540f,
                TIOCSPGRP       = 0x5410,
                TIOCGWINSZ      = 0x5413,
                TIOCSWINSZ      = 0x5414
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
                uint8_t vstart; // CTRL+Q.
                uint8_t vstop; // CTRL+S.
                uint8_t vsusp; // CTRL+Z.
                uint8_t veol; // EOL alt.
                uint8_t vreprint; // CTRL+R.
                uint8_t vwerase; // CTRL+W.
                uint8_t vlnext; // CTRL+V.
                uint8_t veol2;
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
            NArch::Spinlock inlock;
            NLib::CircularBuffer<char> outbuffer;
            NArch::Spinlock outlock;
            NLib::CircularBuffer<char> linebuffer;
            NArch::Spinlock linelock;

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

            // NOTE: The TTY provides no way to manage writing to it. This is driver/implementation specific and should be handled separately.
    };

    class TTYDevice : public Device {
        private:
        public:

            TTY *tty = NULL;

            TTYDevice(uint64_t id, DevDriver *driver) : Device(id, driver) {
                this->tty = new TTY();
            }
    };
}
