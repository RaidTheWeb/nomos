#include <arch/x86_64/apic.hpp>
#include <arch/x86_64/cpu.hpp>
#include <arch/x86_64/interrupts.hpp>
#include <arch/x86_64/tsc.hpp>
#include <sys/clock.hpp>
#include <sys/timer.hpp>

namespace NSched {
    extern void schedule(struct NArch::Interrupts::isr *isr, struct NArch::CPU::context *ctx);
}

namespace NArch {
    namespace Timer {
        void rearm(void) {
            // Re-arm LAPIC timer for next timer quantum.
            APIC::lapiconeshot(1000, 0xfb);
        }

        static void sched(struct Interrupts::isr *isr, struct CPU::context *ctx) {
            if (CPU::get()->preemptdisabled) {
                // Timer interrupts are usually scheduled by the scheduler, but if preemption is disabled we need to re-arm the timer here.
                rearm();
                return; // Preemption is disabled, do not attempt to reschedule.
            }

            uint64_t now = TSC::query();
            uint64_t deadline = CPU::get()->quantumdeadline;
            if (deadline != 0) { // Deadline of 0 means no quantum expiry (never reschedules).
                if (now > deadline) {
                    NSched::schedule(isr, ctx);
                    return;
                }
            }
            rearm();
        }

        // Scheduler timer ISR for the BSP.
        static void timerisr(struct Interrupts::isr *isr, struct CPU::context *ctx) {
            (void)isr;
            (void)ctx;

            uint64_t current = (TSC::query() * 1000) / TSC::hz;
            NSys::Timer::update(current); // Update timer subsystem with current time in milliseconds

            sched(isr, ctx);
        }

        // Scheduler timer ISR for other CPUs in SMP systems.
        static void schedisr(struct Interrupts::isr *isr, struct CPU::context *ctx) {
            (void)isr;
            (void)ctx;

            sched(isr, ctx);
        }

        void setisr(void) {
            Interrupts::regisr(0xfb, CPU::get() == CPU::getbsp() ? timerisr : schedisr, true);
        }

        void init(void) {
            setisr();
            NSys::Clock::init(); // Initialise clock subsystem after TSC calibration.
            NUtil::printf("[arch/x86_64/timer]: Timer subsystem initialised.\n");
        }
    }
}