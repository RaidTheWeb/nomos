#ifndef _ARCH__X86_64__CPU_HPP
#define _ARCH__X86_64__CPU_HPP

#include <arch/x86_64/interrupts.hpp>
#include <arch/x86_64/io.hpp>
#include <arch/x86_64/sync.hpp>
#include <lib/string.hpp>
#include <sched/sched.hpp>
#include <sched/workqueue.hpp>
#include <stdint.h>
#include <sys/random.hpp>


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

        static inline uint64_t rdcr0(void) {
            uint64_t ret;
            asm volatile("mov %%cr0, %0" : "=r"(ret) : : "memory");
            return ret;
        }

        static inline void wrcr0(uint64_t val) {
            asm volatile("mov %0, %%cr0" : : "r"(val) : "memory");
        }

        static inline uint64_t rdcr4(void) {
            uint64_t ret;
            asm volatile("mov %%cr4, %0" : "=r"(ret) : : "memory");
            return ret;
        }

        static inline void wrcr4(uint64_t val) {
            asm volatile("mov %0, %%cr4" : : "r"(val) : "memory");
        }

        // Read from RDRAND. Returns true on success, false on failure.
        static inline bool rdrand(uint64_t *out) {
            uint8_t ok;
            asm volatile("rdrand %0; setc %1" : "=r"(*out), "=qm"(ok));
            return ok;
        }

        static inline bool rdseed(uint64_t *out) {
            uint8_t ok;
            asm volatile("rdseed %0; setc %1" : "=r"(*out), "=qm"(ok));
            return ok;
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

        struct cpulocal {
            // Place current thread pointer at the start of the CPU struct, so the offset is easier within the system call assembly.
            NSched::Thread *currthread = NULL; // Currently running thread, if any.
            uint64_t raxtemp; // Temporary location for use by syscall assembly to store RAX.
            uint64_t cr3temp; // Temporary location for use by syscall assembly to store CR3 for context restore.
            uintptr_t kcr3; // Kernel CR3.
            uintptr_t schedstacktop;
            uint8_t *schedstack = NULL; // Scheduler stack, allocated for this CPU to use during interrupts (when we shouldn't be using a stack that has ANYTHING to do with a thread).

            uint8_t *ist1stack = NULL;  // IST1: NMI stack.
            uint8_t *ist2stack = NULL;  // IST2: Double Fault stack.

            NSched::Thread *idlethread = NULL; // Fallback idle thread, for when trere's no work.
            uint64_t lastschedts; // For runtime delta calculations.

            struct ist ist;
            uint64_t gdt[7];
            struct Interrupts::isr isrtable[256];
            uint32_t id;
            uint32_t lapicid;
            uint64_t lapicfreq = 0;
            bool intstatus = false; // Interrupts enabled?
            bool ininterrupt = false; // Currently handling an interrupt?
            uint8_t handlingvec = 0; // Vector of currently handling interrupt, for debugging.

            // IRQSpinlock state stack for nested lock acquisition.
            static constexpr size_t IRQSTACKMAX = 16;
            bool irqstatestack[IRQSTACKMAX];
            size_t irqstackdepth = 0;

            volatile size_t tlbgeneration = 0; // Last processed TLB generation for this CPU.

            volatile uint64_t loadweight = 0; // (oldweight * 3 + rqsize * 1024) / 4
            NSched::RBTree runqueue; // Per-CPU queue of threads within a Red-Black tree.
            size_t schedintr = 1; // Incremented every scheduler interrupt. Used for time-based calculations, as we can approximate a scheduled * NSched::QUANTUMMS = milliseconds conversion.
            uint64_t quantumdeadline = 0; // TSC deadline for quantum expiry.
            volatile uint64_t minvruntime = 0; // Minimum virtual runtime on this CPU. Used for scheduling decisions.
#ifdef TSTATE_DEBUG
            volatile uint64_t idlecount = 0; // Count of consecutive idle thread selections.
#endif

            size_t fpusize = 0; // Size of FPU storage. Determines how FPU storage will be allocated when needed.
            bool hasxsave = false; // Does this CPU support XSAVE? (AVX-* systems).
            uint64_t xsavemask = 0;

            bool hasrdrand = false; // Does this CPU support RDRAND?
            bool hasrdseed = false; // Does this CPU support RDSEED?
            NSys::Random::EntropyPool *entropypool = NULL; // Per-CPU entropy pool.
            size_t intcntr = 0; // Count of interrupts handled, for random seeding rate limiting.

            NSched::WorkerPool *workpool = NULL; // Per-CPU worker pool.
            NSched::WorkerPool *prioworkpool = NULL; // Per-CPU high-priority worker pool.

            volatile bool preemptdisabled = true; // Is preemption disabled on this CPU?
            volatile bool inschedule = false; // Is this CPU currently in the scheduler? Prevents nested scheduler invocations.

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
