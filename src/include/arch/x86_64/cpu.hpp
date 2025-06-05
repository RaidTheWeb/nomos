#ifndef _ARCH__X86_64__CPU_HPP
#define _ARCH__X86_64__CPU_HPP

#include <arch/x86_64/interrupts.hpp>
#include <arch/x86_64/sync.hpp>
#include <lib/string.hpp>
#include <stdint.h>


namespace NArch {
    namespace CPU {

        // Interrupt Stack Table, 64-bit "TSS".
        struct ist {
            uint32_t rsvd0;
            uint64_t rsp0;
            uint64_t rsp1;
            uint64_t rsp2;
            uint64_t rsvd1;
            uint64_t ist1;
            uint64_t ist2;
            uint64_t ist3;
            uint64_t ist4;
            uint64_t ist5;
            uint64_t ist6;
            uint64_t ist7;
            uint32_t rsvd2[3];
            uint32_t iopb;
        } __attribute__((packed));

        static inline uint64_t rdmsr(uint32_t base) {
            uint32_t lo;
            uint32_t hi;
            asm volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(base) : "memory");
            return ((uint64_t)hi << 32) | lo;
        }

        static inline void wrmsr(uint32_t base, uint64_t value) {
            uint32_t lo = (value & 0xffffffff);
            uint32_t hi = (value >> 32) & 0xffffffff;
            asm volatile("wrmsr" : : "a"(lo), "d"(hi), "c"(base));
        }

        static const uint32_t MSRAPICBASE   = 0x0000001b;

        static const uint32_t MSREFER       = 0xc0000080;

        static const uint32_t MSRSTAR       = 0xc0000081;
        static const uint32_t MSRLSTAR      = 0xc0000082;
        static const uint32_t MSRCSTAR      = 0xc0000083;

        static const uint32_t MSRFMASK      = 0xc0000084;

        static const uint32_t MSRFSBASE     = 0xc0000100;
        static const uint32_t MSRGSBASE     = 0xc0000101; // GS.
        static const uint32_t MSRKGSBASE    = 0xc0000102; // Kernel GS.

        class CPUInst {
            public:
                struct MCSSpinlock::state mcsstate;
                struct ist ist;
                uint64_t gdt[7];
                struct Interrupts::isr isrtable[256];
                uint32_t id;
                uint32_t lapicid;
                bool intstatus = false; // Interrupts enabled?

                CPUInst(void) {

                }

                bool setint(bool status) {
                    asm volatile("cli");
                    bool old = this->intstatus;
                    this->intstatus = status;

                    if (status) {
                        asm volatile("sti");
                    }

                    return old;
                }
        };

        CPUInst *getbsp(void);

        // Set the current CPU in GS.
        static inline void set(CPUInst *ptr) {
            // Write to MSR GS with pointer to instance.
            wrmsr(MSRGSBASE, (uint64_t)ptr);
        }

        // Get current CPU from GS.
        static inline CPUInst *get(void) {

            return (CPUInst *)rdmsr(MSRGSBASE);
        }

        void init(void);
    }
}

#endif
