#ifndef _ARCH__X86_64__BARRIER_HPP
#define _ARCH__X86_64__BARRIER_HPP

namespace NArch {
    namespace CPU {
        static __attribute__((always_inline)) void writemb(void) {
            asm volatile("" : : : "memory");
        }

        static __attribute__((always_inline)) void readmb(void) {
            asm volatile("" : : : "memory");
        }

        static __attribute__((always_inline)) void mb(void) {
            asm volatile("mfence" : : : "memory");
        }
    }
}

#endif
