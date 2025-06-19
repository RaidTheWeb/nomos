#include <arch/x86_64/acpi.hpp>
#include <arch/x86_64/arch.hpp>
#include <arch/x86_64/cpu.hpp>
#include <arch/x86_64/hpet.hpp>
#include <arch/x86_64/tsc.hpp>
#include <lib/assert.hpp>
#include <util/kprint.hpp>

namespace NArch {
    namespace HPET {

        uint8_t *hpet = NULL; // Memory mapped HPET registers.
        uint64_t tickspassed = 0;
        uint64_t hz = 0;

        static uint64_t read(uint32_t reg) {
            volatile uint64_t *loc = (volatile uint64_t *)((uintptr_t)hpet + reg);
            return *loc;
        }

        static void write(uint32_t reg, uint64_t value) {
            volatile uint64_t *loc = (volatile uint64_t *)((uintptr_t)hpet + reg);
            *loc = value;
        }

        uint64_t query(void) {
            return read(MAINCOUNTER);
        }

        uint64_t calibratetsc(void) {
            uint64_t ttl = (200000 * hz) / 1000000;
            uint64_t start = TSC::query();

            uint64_t target = query() + ttl; // Determine a "future", for when we have elapsed all the time.

            uint64_t end = TSC::query();

            while (query() < target) {
                end = TSC::query();
            }

            return ((end - start) * 1000000) / 200000; // Divide elapsed time by the known wait constant we input, so we know the number of ticks it took for the TSC to get to this point.
        }

        void setup(void) {
            if (ACPI::hpet == NULL) {
                return; // No HPET exists on this hardware. Skip.
            }

            if (cmdline.get("nohpet")) {
                NUtil::printf("[hpet]: HPET disabled due to `nohpet` command line argument.\n");
                return;
            }

            NUtil::printf("[hpet]: Initialising HPET%lu...\n", ACPI::hpet->number);
            assert(ACPI::hpet->address.address_space_id == ACPI_AS_ID_SYS_MEM, "HPET MMIO address space is not within system memory.\n");

            hpet = (uint8_t *)ACPI::hpet->address.address;

            // Memory map whatever we're using.
            uintptr_t virt = (uintptr_t)VMM::kspace.vmaspace->alloc(PAGESIZE, NMem::Virt::VIRT_RW | NMem::Virt::VIRT_NX);
            assert(VMM::mappage(&VMM::kspace, virt, ACPI::hpet->address.address, VMM::PRESENT | VMM::WRITEABLE | VMM::NOEXEC), "Failed to memory map HPET base address.\n");
            hpet = (uint8_t *)virt;

            uint64_t caps = read(GENERALCAPS); // Read capabilities.
            // 10^15 / period -> Where period is the last 32 bits of the capabilities register.
            hz = 1000000000000000lu / ((caps >> 32) & 0xffffffff);
            NUtil::printf("[hpet]: HPET%lu has a frequency of %lu Hz.\n", ACPI::hpet->number, hz);
            assert(hz, "Failed to calculate HPET timer frequency.\n");

            // Initialisation:
            write(GENERALCONF, 0); // Reset config.
            write(MAINCOUNTER, 0); // Reset counter.

            assertarg(caps & (1 << 13), "HPET%lu does not support 64-bit main counter.\n", ACPI::hpet->number); // XXX: We might want to consider enabling 32-bit counters for older hardware.

            write(GENERALCONF, 1); // Enable CNF bit. Overall enable!

            NUtil::printf("[hpet]: HPET%lu initialised.\n", ACPI::hpet->number);
            // Counter is working by now.
            // We may query the timer ticks with read(MAINCOUNTER).
        }
    }
}
