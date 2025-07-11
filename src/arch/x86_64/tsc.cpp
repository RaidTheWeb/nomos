#include <arch/x86_64/arch.hpp>
#include <arch/x86_64/acpi.hpp>
#include <arch/x86_64/cpu.hpp>
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

            if (ACPI::hpet != NULL && !cmdline.get("nohpet")) {
                NUtil::printf("[arch/x86_64/tsc]: Calibrating TSC on CPU%lu with HPET.\n", CPU::get()->id);
                hz = HPET::calibratetsc();
            } else {
                NUtil::printf("[arch/x86_64/tsc]: Calibrating TSC on CPU%lu with PIT.\n", CPU::get()->id);

                constexpr uint32_t freq = 1193182;
                constexpr uint32_t count = freq / (1000 / 200);
                constexpr size_t maxattempts = 5;

                uint64_t measurements[maxattempts];
                size_t validmeasurements = 0;

                for (size_t i = 0; i < maxattempts; i++) {


                    outb(0x43, 0x34);
                    outb(0x40, count & 0xff);
                    outb(0x40, (count >> 8) & 0xff);

                    TSC::query();
                    TSC::query();

                    while (!(inb(0x61) & 0x20)) {
                        asm volatile("pause");
                    }

                    uint64_t start = TSC::query();

                    while ((inb(0x61) & 0x20)) {
                        asm volatile("pause");
                    }

                    uint64_t end = TSC::query();

                    measurements[validmeasurements++] = (end - start) * (1000 / 200);
                }
                assert(validmeasurements, "Failed to calibrate the TSC.\n");

                for (size_t i = 0; i < validmeasurements - 1; i++) {
                    for (size_t j = i + 1; j < validmeasurements; j++) {
                        if (measurements[i] > measurements[j]) {
                            uint64_t tmp = measurements[i];
                            measurements[i] = measurements[j];
                            measurements[j] = tmp;
                        }
                    }
                }

                hz = measurements[validmeasurements / 2];
            }
            NUtil::printf("[arch/x86_64/tsc]: TSC on CPU%lu calibrated to %lu Hz.\n", CPU::get()->id, hz);
        }
    }
}
