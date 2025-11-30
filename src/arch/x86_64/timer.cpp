#include <arch/x86_64/apic.hpp>
#include <arch/x86_64/cpu.hpp>
#include <arch/x86_64/interrupts.hpp>
#include <arch/x86_64/tsc.hpp>
#include <sys/timer.hpp>

namespace NArch {
    namespace Timer {
        static void timerisr(struct Interrupts::isr *isr, struct CPU::context *ctx) {
            (void)isr;
            (void)ctx;

            uint64_t current = (TSC::query() * 1000) / TSC::hz;
            NSys::Timer::update(current); // Update timer subsystem with current time in milliseconds.

            if (--CPU::get()->quantum_left <= 0) {
                CPU::get()->quantum_left = NSched::QUANTUMMS;
                // Trigger the scheduler interrupt ourselves.
                APIC::sendipi(CPU::get()->lapicid, 0xfe, APIC::IPIFIXED, APIC::IPIPHYS, APIC::IPISELF);
            }
        }

        void init(void) {
            NSys::Timer::init();

            uint8_t vec = Interrupts::allocvec();
            Interrupts::regisr(vec, timerisr, true);

            // Setup periodic LAPIC timer
            uint64_t us = 1000; // 1ms.
            uint64_t ticks = us * (CPU::get()->lapicfreq / 1000000);

            CPU::get()->quantum_left = NSched::QUANTUMMS;

            APIC::writelapic(APIC::LAPICLVTT, vec | (1 << 17)); // Periodic mode
            APIC::writelapic(APIC::LAPICDCR, 0b1011); // Divide by 1
            APIC::writelapic(APIC::LAPICICR, ticks);
        }
    }
}