#include <arch/x86_64/hpet.hpp>
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

            hz = HPET::calibratetsc();
            NUtil::printf("[tsc]: TSC on CPU%lu calibrated to %lu Hz.\n", CPU::get()->id, hz);
        }
    }
}
