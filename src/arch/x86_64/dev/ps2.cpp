#include <arch/x86_64/apic.hpp>
#include <arch/x86_64/interrupts.hpp>
#include <arch/x86_64/io.hpp>
#include <dev/dev.hpp>
#include <stddef.h>
#include <util/kprint.hpp>

namespace NDev {
    using namespace NArch;

    static const uint16_t DATAPORT   = 0x60;
    static const uint16_t CMDPORT    = 0x64;
    static const uint16_t STATPORT   = 0x64;

    static inline bool canwrite(void) {
        return !(inb(STATPORT) & (1 << 1)); // We can only write if the input buffer status is clear.
    }

    static inline bool canread(void) {
        return (inb(STATPORT) & (1 << 0)); // We can only read if the output buffer status is set.
    }

    static inline void writecmd(uint8_t cmd) {
        while (!canwrite());
        outb(CMDPORT, cmd);
    }

    static inline void writedata(uint8_t data) {
        while (!canwrite());
        outb(DATAPORT, data);
    }

    static inline uint8_t read(void) {
        while (!canread());
        return inb(DATAPORT);
    }

    class PS2Driver : public Driver {
        public:
            PS2Driver(void) {
                writecmd(0xad); // Disable PS/2 port 1.
                writecmd(0xa7); // Disable PS/2 port 2.

                while (NArch::inb(CMDPORT) & (1 << 0)) {
                    NArch::inb(DATAPORT);
                }

                writecmd(0x20); // Request that the controller dump its config byte into the data buffer.
                uint8_t conf = read();
                conf |= (1 << 0); // Enable interrupt on first port (keyboard).
                writecmd(0x60); // Request that the controller prepare to read in new config byte from the data buffer.
                writedata(conf); // Write out config.

                writecmd(0xae); // Enable PS/2 port 1.

                uint8_t vec = Interrupts::allocvec(); // Allocate vector for keyboard handler.

                // Register ISR for the keyboard handler.
                Interrupts::regisr(vec, kbdhandler, true);

                APIC::setirq(1, vec, false, 0); // Unmask IRQ1 for keyboard handler.
            }

            static void kbdhandler(struct Interrupts::isr *isr, struct CPU::context *ctx) {
                (void)isr;
                (void)ctx;

                uint8_t scan = read();
                if (scan & 0x80) { // Release scancode.
                    return;
                }

                NUtil::printf("KBD Scan 0x%02x.\n", scan);
            }
    };

    static struct reginfo info = {
        .name = "PS2",
        .type = reginfo::GENERIC,
        .match = { }
    };

    REGDRIVER(PS2Driver, &info);
}
