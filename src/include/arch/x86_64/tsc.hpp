#ifndef _ARCH__X86_64__TSC_HPP
#define _ARCH__X86_64__TSC_HPP

#include <stdint.h>

namespace NArch {
    namespace TSC {
        extern uint64_t hz;

        uint64_t query(void);

        void setup(void);
    }
}

#endif
