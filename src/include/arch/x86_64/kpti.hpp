#ifndef _ARCH__X86_64__KPTI_HPP
#define _ARCH__X86_64__KPTI_HPP

#include <arch/x86_64/cpu.hpp>
#include <stdint.h>

namespace NArch {
    namespace KPTI {
        static const uint64_t ULOCALVIRT        = 0xfffffffffff01000;
        static const uint64_t ULOCALVIRTTOP     = 0xffffffffffff4000;
        static const uint64_t TRAMPOLINEVIRT    = 0xffffffffff600000;

        extern uintptr_t ulocalphy;
        extern struct CPU::ulocal *ulocals;

        // Used for per-CPU initialisation.
        void apsetup(void);
        void setup(void);
    }
}

#endif
