#include <arch/x86_64/apic.hpp>
#include <arch/x86_64/cpu.hpp>
#include <arch/x86_64/interrupts.hpp>
#include <arch/x86_64/io.hpp>
#include <dev/dev.hpp>
#include <dev/input/input.hpp>
#include <dev/kbd.hpp>
#include <stddef.h>
#include <util/kprint.hpp>

namespace NDev {
    using namespace NArch;

    namespace KBD {
        uint8_t cur;
    }


    // Generic scan codes.
    static const uint16_t scancodes[] = {
        Input::key::RSVD,         // 0x00
        Input::key::KESC,         // 0x01
        Input::key::K1,           // 0x02
        Input::key::K2,           // 0x03
        Input::key::K3,           // 0x04
        Input::key::K4,           // 0x05
        Input::key::K5,           // 0x06
        Input::key::K6,           // 0x07
        Input::key::K7,           // 0x08
        Input::key::K8,           // 0x09
        Input::key::K9,           // 0x0A
        Input::key::K0,           // 0x0B
        Input::key::KMINUS,       // 0x0C
        Input::key::KEQUALS,      // 0x0D
        Input::key::KBACKSPACE,   // 0x0E
        Input::key::KTAB,         // 0x0F
        Input::key::KQ,           // 0x10
        Input::key::KW,           // 0x11
        Input::key::KE,           // 0x12
        Input::key::KR,           // 0x13
        Input::key::KT,           // 0x14
        Input::key::KY,           // 0x15
        Input::key::KU,           // 0x16
        Input::key::KI,           // 0x17
        Input::key::KO,           // 0x18
        Input::key::KP,           // 0x19
        Input::key::KLEFTBRACKET, // 0x1A
        Input::key::KRIGHTBRACKET,// 0x1B
        Input::key::KENTER,       // 0x1C
        Input::key::KLCTRL,       // 0x1D
        Input::key::KA,           // 0x1E
        Input::key::KS,           // 0x1F
        Input::key::KD,           // 0x20
        Input::key::KF,           // 0x21
        Input::key::KG,           // 0x22
        Input::key::KH,           // 0x23
        Input::key::KJ,           // 0x24
        Input::key::KK,           // 0x25
        Input::key::KL,           // 0x26
        Input::key::KSEMICOLON,   // 0x27
        Input::key::KAPOSTROPHE,  // 0x28
        Input::key::KGRAVE,       // 0x29
        Input::key::KLSHIFT,      // 0x2A
        Input::key::KBACKSLASH,   // 0x2B
        Input::key::KZ,           // 0x2C
        Input::key::KX,           // 0x2D
        Input::key::KC,           // 0x2E
        Input::key::KV,           // 0x2F
        Input::key::KB,           // 0x30
        Input::key::KN,           // 0x31
        Input::key::KM,           // 0x32
        Input::key::KCOMMA,       // 0x33
        Input::key::KDOT,         // 0x34
        Input::key::KSLASH,       // 0x35
        Input::key::KRSHIFT,      // 0x36
        Input::key::KKPADMUL,     // 0x37
        Input::key::KLALT,        // 0x38
        Input::key::KSPACE,       // 0x39
        Input::key::KCAPSLOCK,    // 0x3A
        Input::key::KF1,          // 0x3B
        Input::key::KF2,          // 0x3C
        Input::key::KF3,          // 0x3D
        Input::key::KF4,          // 0x3E
        Input::key::KF5,          // 0x3F
        Input::key::KF6,          // 0x40
        Input::key::KF7,          // 0x41
        Input::key::KF8,          // 0x42
        Input::key::KF9,          // 0x43
        Input::key::KF10,         // 0x44
        Input::key::KNUMLOCK,     // 0x45
        Input::key::KSCROLLLOCK,  // 0x46
        Input::key::KKPAD7,       // 0x47
        Input::key::KKPAD8,       // 0x48
        Input::key::KKPAD9,       // 0x49
        Input::key::KKPADSUB,     // 0x4A
        Input::key::KKPAD4,       // 0x4B
        Input::key::KKPAD5,       // 0x4C
        Input::key::KKPAD6,       // 0x4D
        Input::key::KKPADADD,     // 0x4E
        Input::key::KKPAD1,       // 0x4F
        Input::key::KKPAD2,       // 0x50
        Input::key::KKPAD3,       // 0x51
        Input::key::KKPAD0,       // 0x52
        Input::key::KKPADDOT,     // 0x53
        Input::key::UNKNOWN,      // 0x54
        Input::key::UNKNOWN,      // 0x55
        Input::key::UNKNOWN,      // 0x56
        Input::key::KF11,         // 0x57
        Input::key::KF12,         // 0x58
    };

    // 0xE0 special prefix scan codes.
    static const uint16_t extscancodes[] = {
        Input::key::UNKNOWN,      // 0x10
        Input::key::UNKNOWN,      // 0x11
        Input::key::UNKNOWN,      // 0x12
        Input::key::UNKNOWN,      // 0x13
        Input::key::UNKNOWN,      // 0x14
        Input::key::UNKNOWN,      // 0x15
        Input::key::UNKNOWN,      // 0x16
        Input::key::UNKNOWN,      // 0x17
        Input::key::UNKNOWN,      // 0x18
        Input::key::UNKNOWN,      // 0x19
        Input::key::UNKNOWN,      // 0x1A
        Input::key::UNKNOWN,      // 0x1B
        Input::key::KKPADENTER,   // 0x1C
        Input::key::KRCTRL,       // 0x1D
        Input::key::UNKNOWN,      // 0x1E
        Input::key::UNKNOWN,      // 0x1F
        Input::key::UNKNOWN,      // 0x20
        Input::key::UNKNOWN,      // 0x21
        Input::key::UNKNOWN,      // 0x22
        Input::key::UNKNOWN,      // 0x23
        Input::key::UNKNOWN,      // 0x24
        Input::key::UNKNOWN,      // 0x25
        Input::key::UNKNOWN,      // 0x26
        Input::key::UNKNOWN,      // 0x27
        Input::key::UNKNOWN,      // 0x28
        Input::key::UNKNOWN,      // 0x29
        Input::key::UNKNOWN,      // 0x2A
        Input::key::UNKNOWN,      // 0x2B
        Input::key::UNKNOWN,      // 0x2C
        Input::key::UNKNOWN,      // 0x2D
        Input::key::UNKNOWN,      // 0x2E
        Input::key::UNKNOWN,      // 0x2F
        Input::key::UNKNOWN,      // 0x30
        Input::key::UNKNOWN,      // 0x31
        Input::key::UNKNOWN,      // 0x32
        Input::key::UNKNOWN,      // 0x33
        Input::key::UNKNOWN,      // 0x34
        Input::key::KKPADDIV,     // 0x35
        Input::key::UNKNOWN,      // 0x36
        Input::key::KPRNTSCR,     // 0x37
        Input::key::KRALT,        // 0x38
        Input::key::UNKNOWN,      // 0x39
        Input::key::UNKNOWN,      // 0x3A
        Input::key::UNKNOWN,      // 0x3B
        Input::key::UNKNOWN,      // 0x3C
        Input::key::UNKNOWN,      // 0x3D
        Input::key::UNKNOWN,      // 0x3E
        Input::key::UNKNOWN,      // 0x3F
        Input::key::UNKNOWN,      // 0x40
        Input::key::UNKNOWN,      // 0x41
        Input::key::UNKNOWN,      // 0x42
        Input::key::UNKNOWN,      // 0x43
        Input::key::UNKNOWN,      // 0x44
        Input::key::UNKNOWN,      // 0x45
        Input::key::UNKNOWN,      // 0x46
        Input::key::KHOME,        // 0x47
        Input::key::KUP,          // 0x48
        Input::key::KPAGEUP,      // 0x49
        Input::key::UNKNOWN,      // 0x4A
        Input::key::KLEFT,        // 0x4B
        Input::key::UNKNOWN,      // 0x4C
        Input::key::KRIGHT,       // 0x4D
        Input::key::UNKNOWN,      // 0x4E
        Input::key::KEND,         // 0x4F
        Input::key::KDOWN,        // 0x50
        Input::key::KPAGEDOWN,    // 0x51
        Input::key::KINSERT,      // 0x52
        Input::key::KDELETE,      // 0x53
        Input::key::UNKNOWN,      // 0x54
        Input::key::UNKNOWN,      // 0x55
        Input::key::UNKNOWN,      // 0x56
        Input::key::UNKNOWN,      // 0x57
        Input::key::UNKNOWN,      // 0x58
        Input::key::UNKNOWN,      // 0x59
        Input::key::UNKNOWN,      // 0x5A
        Input::key::KSUPER,       // 0x5B
        Input::key::KSUPER,       // 0x5C
        Input::key::UNKNOWN,      // 0x5D
        Input::key::UNKNOWN,      // 0x5E
        Input::key::UNKNOWN,      // 0x5F
        Input::key::UNKNOWN,      // 0x60
        Input::key::UNKNOWN,      // 0x61
        Input::key::UNKNOWN,      // 0x62
        Input::key::UNKNOWN,      // 0x63
        Input::key::KHOME,        // 0x64
        Input::key::KUP,          // 0x65
        Input::key::KPAGEUP,      // 0x66
        Input::key::UNKNOWN,      // 0x67
        Input::key::KLEFT,        // 0x68
        Input::key::UNKNOWN,      // 0x69
        Input::key::KRIGHT,       // 0x6A
        Input::key::UNKNOWN,      // 0x6B
        Input::key::KEND,         // 0x6C
        Input::key::KDOWN,        // 0x6D
        Input::key::KPAGEDOWN,    // 0x6E
        Input::key::KINSERT,      // 0x6F
        Input::key::KDELETE,      // 0x70
    };

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

    static Input::Device *idev = NULL;
    static bool e0pfx = false;

    class PS2Driver : public Driver {
        private:
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

                NArch::CPU::get()->currthread->disablemigrate(); // Guard to prevent the thread from being migrated to a different CPU halfway through registering an interrupt handler on it.

                uint8_t vec = Interrupts::allocvec(); // Allocate vector for keyboard handler.

                // Register ISR for the keyboard handler.
                Interrupts::regisr(vec, kbdhandler, true);

                APIC::setirq(1, vec, false, NArch::CPU::get()->lapicid); // Unmask IRQ1 for keyboard handler.
                NArch::CPU::get()->currthread->enablemigrate();

                idev = new Input::Device();
                idev->evsupported |= Input::event::KEY;

                for (size_t i = 0; i < Input::key::KMAX; i++) {
                    idev->keybit.set(i);
                }

                Input::registerdevice(idev);
            }

            static void kbdhandler(struct Interrupts::isr *isr, struct CPU::context *ctx) {
                (void)isr;
                (void)ctx;

                uint8_t scan = read();

                if (scan == 0xe0) {
                    e0pfx = true;
                    return;
                }

                if (e0pfx) {
                    uint8_t pressed = !(scan & 0x80);
                    uint8_t code = scan & 0x7f;

                    idev->reportkey(extscancodes[code - 0x10], pressed); // 0x10 is subtracted from the code, because the translation array begins describing scancodes beginning at 0x10.
                    idev->sync();

                    e0pfx = false;
                } else {
                    uint8_t pressed = !(scan & 0x80);
                    uint8_t code = scan & 0x7f;

                    idev->reportkey(scancodes[code], pressed);
                    idev->sync();
                }
            }
    };

    static struct reginfo info = {
        .name = "ps2kbd",
        .type = reginfo::GENERIC,
        .match = { }
    };

    REGDRIVER(PS2Driver, &info);
}
