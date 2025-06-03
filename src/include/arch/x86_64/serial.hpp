#ifndef _ARCH__X86_64__SERIAL_HPP
#define _ARCH__X86_64__SERIAL_HPP

#include <stddef.h>
#include <stdint.h>

namespace NArch {
    namespace Serial {
        extern bool serialenabled;
        extern bool serialchecked;

        // Offsets:
        enum {
            READ        = 0,
            WRITE       = 0,
            INTEN       = 1, // Enable interrupts.
            LSBAUD      = 0, // Requires DLAB=1
            MSBAUD      = 1, // Ditto.
            INTID       = 2,
            FIFOCTL     = 2,
            LINECTL     = 3, // DLAB at MSB
            MODEMCTL    = 4,
            LINESTAT    = 5,
            MODEMSTAT   = 6,
            SCRATCH     = 7
        };

        // Masks.
        enum {
            LINECTL_DLAB    = 0b10000000,
            LINECTL_BREAK   = 0b01000000,
            LINECTL_PARITY3 = 0b00001000, // Bit 3
            LINECTL_PARITY4 = 0b00010000, // Bit 4
            LINECTL_PARITY5 = 0b00100000, // Bit 5
            LINECTL_STOP    = 0b00000100,
            LINECTL_DATA0   = 0b00000001, // Bit 0
            LINECTL_DATA1   = 0b00000010, // Bit 1

            INTEN_RSVD      = 0b11110000,
            INTEN_MODEM     = 0b00001000,
            INTEN_RCVLINE   = 0b00000100,
            INTEN_HOLDEMPTY = 0b00000010,
            INTEN_NEWDATA   = 0b00000001,

            FIFO_TRIGGER7   = 0b10000000, // Bit 7
            FIFO_TRIGGER6   = 0b01000000, // Bit 6
            FIFO_RSVD       = 0b00110000,
            FIFO_DMA        = 0b00001000,
            FIFO_CLRTRANS   = 0b00000100,
            FIFO_CLRRCV     = 0b00000010,
            FIFO_FIFOEN     = 0b00000001,

            MODEMCTL_DTR    = 0b00000001,
            MODEMCTL_RTS    = 0b00000010,
            MODEMCTL_OUT1   = 0b00000100,
            MODEMCTL_OUT2   = 0b00001000,
            MODEMCTL_LOOP   = 0b00010000,
            MODEMCTL_RSVD   = 0b11100000,

            LINESTAT_DR     = 0b00000001, // Data ready. Can we read?
            LINESTAT_OE     = 0b00000010, // Overrun.
            LINESTAT_PE     = 0b00000100, // Parity error.
            LINESTAT_FE     = 0b00001000, // Framing error.
            LINESTAT_BI     = 0b00010000, // Break indicator.
            LINESTAT_THRE   = 0b00100000, // Transmitter holding empty.
            LINESTAT_TEMT   = 0b01000000, // Transmitter empty. Can we transmit?
            LINESTAT_IE     = 0b10000000, // Impending error.
        };

        class SerialPort {
            public:
                // I/O Ports:
                enum port {
                    COM1 = 0x3f8,
                    COM2 = 0x2f8,

                    COM3 = 0x3e8,
                    COM4 = 0x2e8,

                    COM5 = 0x5f8,
                    COM6 = 0x4f8,

                    COM7 = 0x5e8,
                    COM8 = 0x4e8
                };
            private:
                enum port port;
                bool initialised;
                // Pre-serial init backbuffer.
                uint8_t backbuffer[1024 * 16]; // 16KiB backbuffer.
                size_t backbufferidx = 0;
            public:

                bool isinitialised(void) {
                    return this->initialised;
                }
                SerialPort(void) {
                    initialised = false;
                };
                void init(enum port port);
                bool poll(void);
                bool writeable(void);
                uint8_t read(void);
                void write(uint8_t data);

        };

        void setup(void);
        extern SerialPort ports[8];
    }
}

#endif
