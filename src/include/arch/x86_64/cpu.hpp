#ifndef _ARCH__X86_64__CPU_HPP
#define _ARCH__X86_64__CPU_HPP

#include <arch/x86_64/interrupts.hpp>
#include <arch/x86_64/sync.hpp>
#include <lib/string.hpp>
#include <sched/sched.hpp>
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

        // Userspace per-CPU local. Mapped into read-only trampoline pages.
        struct ulocal {
            uintptr_t kcr3; // Kernel CR3.
            uintptr_t stacktop;
            uint64_t gdt[7];
            struct ist ist;
            struct Interrupts::idtentry idt[256]; // XXX: Consider one IDT, the only per-CPU part needs to be the ISR table.
            uint8_t stack[PAGESIZE]; // Temporary stack for usage during context switches.
        } __attribute__((aligned(64))); // Cache-aligned.

        struct cpulocal {
            // Place current thread pointer at the start of the CPU struct, so the offset is easier within the system call assembly.
            NSched::Thread *currthread = NULL; // Currently running thread, if any.
            uint64_t raxtemp; // Temporary location for use by syscall assembly to store RAX.
            uint64_t cr3temp; // Temporary location for use by syscall assembly to store CR3 for context restore.
            uintptr_t ulocalstack; // Reference to the top of the user local stack.
            uint8_t *schedstack = NULL; // Scheduler stack, allocated for this CPU to use during interrupts (when we shouldn't be using a stack that has ANYTHING to do with a thread).

            struct VMM::pagetable *kpt; // Kernel page table instance -> simply aliases the pages from the "core" page table.

            NSched::Thread *idlethread = NULL; // Fallback idle thread, for when trere's no work.
            uint64_t lastschedts; // For runtime delta calculations.

            struct MCSSpinlock::state mcsstate;
            struct ist ist;
            uint64_t gdt[7];
            struct Interrupts::isr isrtable[256];
            uint32_t id;
            uint32_t lapicid;
            uint64_t lapicfreq = 0;
            bool intstatus = false; // Interrupts enabled?

            uint64_t loadweight; // (oldweight * 3 + rqsize * 1024) / 4
            NSched::RBTree runqueue; // Per-CPU queue of threads within a Red-Black tree.
            size_t schedintr; // Incremented every scheduler interrupt. Used for time-based calculations, as we can approximate a scheduled * NSched::QUANTUMMS = milliseconds conversion.


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

        struct cpulocal *getbsp(void);

        // Set the current CPU in GS.
        static inline void set(struct cpulocal *ptr) {
            // Write to MSR GS with pointer to instance.
            wrmsr(MSRGSBASE, (uint64_t)ptr);
        }

        // Get current CPU from GS.
        static inline struct cpulocal *get(void) {
            return (struct cpulocal *)rdmsr(MSRGSBASE);
        }

        void init(void);
    }
}

#endif
