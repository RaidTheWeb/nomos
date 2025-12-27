#ifndef _DEV__INPUT__INPUT_HPP
#define _DEV__INPUT__INPUT_HPP

#include <lib/bitmap.hpp>
#include <lib/list.hpp>
#include <lib/sync.hpp>
#include <stdint.h>

namespace NDev {
    namespace Input {
        enum sync {
            REPORT              = 0
        };

        enum key {
            RSVD                = 0,
            UNKNOWN,

            KESC,
            KF1,
            KF2,
            KF3,
            KF4,
            KF5,
            KF6,
            KF7,
            KF8,
            KF9,
            KF10,
            KF11,
            KF12,
            KGRAVE,
            K1,
            K2,
            K3,
            K4,
            K5,
            K6,
            K7,
            K8,
            K9,
            K0,
            KMINUS,
            KEQUALS,
            KBACKSPACE,
            KTAB,
            KQ,
            KW,
            KE,
            KR,
            KT,
            KY,
            KU,
            KI,
            KO,
            KP,
            KLEFTBRACKET,
            KRIGHTBRACKET,
            KBACKSLASH,
            KCAPSLOCK,
            KA,
            KS,
            KD,
            KF,
            KG,
            KH,
            KJ,
            KK,
            KL,
            KSEMICOLON,
            KAPOSTROPHE,
            KENTER,
            KLSHIFT,
            KZ,
            KX,
            KC,
            KV,
            KB,
            KN,
            KM,
            KCOMMA,
            KDOT,
            KSLASH,
            KRSHIFT,
            KLCTRL,
            KSUPER,
            KLALT,
            KSPACE,
            KRALT,
            KRCTRL,
            KLEFT,
            KUP,
            KDOWN,
            KRIGHT,

            KPRNTSCR,
            KINSERT,
            KDELETE,
            KPAGEUP,
            KPAGEDOWN,
            KHOME,
            KEND,

            KNUMLOCK,
            KSCROLLLOCK,

            KKPAD0,
            KKPAD1,
            KKPAD2,
            KKPAD3,
            KKPAD4,
            KKPAD5,
            KKPAD6,
            KKPAD7,
            KKPAD8,
            KKPAD9,

            KKPADMUL,
            KKPADSUB,
            KKPADADD,
            KKPADDIV,
            KKPADDOT,
            KKPADENTER,

            KMAX
        };


        struct event {
            enum type {
                SYN             = (1 << 0),  // Event packet finalisation.
                KEY             = (1 << 1), // Typical keyboard press.
            };

            enum disposition {
                IGNORE          = 0, // Input should be disregarded (code is unsupported, or similar issue).
                DIRECT          = 1, // Input should be passed to the device from the moment it was reported.
                BUFFER          = 2, // Input should be buffered into the packet, and flushed out on sync.
                FLUSH           = 4, // Flush packet to device.
            };

            uint64_t tmstmp; // When did this happen?
            uint16_t type; // What type of event is this?
            uint16_t code; // Event code -> Type specific.
            int32_t value; // Event data -> Type specific.
        };

        struct eventhandler;

        class Device {
            public:
                NArch::Spinlock lock;
                uint64_t evsupported; // What events do we support?
                NLib::Bitmap keybit; // What key codes do we support?

                NLib::Vector<struct event> packet; // Packet buffer.

                NLib::DoubleList<struct eventhandler *> handlers; // Attached handlers.

                Device(void) : keybit(key::KMAX) {
                    this->packet.reserve(64);
                }

                enum event::disposition getdispose(uint16_t type, uint16_t *pcode, int32_t *pvalue);

                void sendtohandler(struct event ev);

                void handle(uint16_t type, uint16_t code, int32_t value);

                // Add to input packet.
                void doevent(uint16_t type, uint16_t code, int32_t value);

                // Add key event to input packet.
                void reportkey(uint16_t code, int32_t value) {
                    this->doevent(event::type::KEY, code, value);
                }

                // Declare end of input packet.
                void sync(void) {
                    this->doevent(event::type::SYN, sync::REPORT, 0);
                }
        };

        struct eventhandler {
            uint64_t evsubscription; // What events are we listening for?

            // Called by input system on connection of a new device with even a partial match of subscribed input events. The supported events are passed in through the argument.
            bool (*connect)(Device *dev, uint64_t supported);
            bool (*disconnect)(void);
            void (*event)(uint64_t tmstmp, uint16_t type, uint16_t code, int32_t value);
        };

        extern NLib::DoubleList<Device *> devices;

        // Register with the
        int registerhandler(struct eventhandler *handler);
        int registerdevice(Device *dev);
    }
}

#endif
