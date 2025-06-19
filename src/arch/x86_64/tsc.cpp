#include <arch/x86_64/hpet.hpp>
#include <arch/x86_64/io.hpp>
#include <arch/x86_64/tsc.hpp>
#include <lib/assert.hpp>

namespace NArch {
    namespace TSC {
        uint64_t hz = 0;

        uint64_t query(void) {
            uint32_t lo;
            uint32_t hi;
            asm volatile("mfence" : : : "memory"); // Serialise the RDTSC instruction.
            asm volatile("rdtsc" : "=a"(lo), "=d"(hi) : : "rbx", "rcx"); // Read into hi and lo, clobbering rbx and rcx.
            return ((uint64_t)hi << 32) | lo;
        }

        void setup(void) {
            uint32_t supported;
            asm volatile(
                "cpuid"
                : "=d"(supported)
                : "a"(1) // Check for features.
            );

            assert(supported & (1 << 4), "Host CPU does NOT support RDTSC instruction.\n");

            if (ACPI::hpet != NULL) {
                NUtil::printf("[tsc]: Calibrating TSC on CPU%lu with HPET.\n", CPU::get()->id);
                hz = HPET::calibratetsc();
            } else {
                NUtil::printf("[tsc]: Calibrating TSC on CPU%lu with PIT.\n", CPU::get()->id);

                outb(0x43, 0x30); // Mode 0, binary counter.
                uint16_t count = 1193182 / 200000; // Same 200ms calibration time.
                outb(0x40, count & 0xff);
                outb(0x40, (count >> 8) & 0xff);

                asm volatile("nop; nop; nop; nop;"); // Pad with NOPs to give the PIT some time to start up.

                uint64_t start = TSC::query();
                while (!(inb(0x61) & 0x20)); // Wait until PIT signals it has reached zero.

                uint64_t end = TSC::query();
                hz = (end - start) * 200000; // We have calibrated.
            }
            NUtil::printf("[tsc]: TSC on CPU%lu calibrated to %lu Hz.\n", CPU::get()->id, hz);
        }
    }
}
