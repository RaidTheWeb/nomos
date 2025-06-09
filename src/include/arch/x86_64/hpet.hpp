#ifndef _ARCH__X86_64__HPET_HPP
#define _ARCH__X86_64__HPET_HPP

#include <stddef.h>
#include <stdint.h>

namespace NArch {
    namespace HPET {
        static const uint64_t GENERALCAPS = 0x000; // General Capabilities and ID Register.
        static const uint64_t GENERALCONF = 0x010; // General Configuration Register.
        static const uint64_t GENERALISR  = 0x020; // General Interrupt Status Register.
        static const uint64_t MAINCOUNTER = 0x0f0; // Main Counter Value Register.

        // Query HPET for the current counter ticks.
        uint64_t query(void);

        // Calibrate TSC using HPET.
        uint64_t calibratetsc(void);

        void setup(void);
    }
}

#endif
