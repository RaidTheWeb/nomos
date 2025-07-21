#include <arch/x86_64/panic.hpp>
#include <arch/x86_64/smp.hpp>

namespace NArch {
    void panic(const char *msg) {
        APIC::lapicstop(); // Prevent any scheduling work from jumping a CPU out of the panic state.
        if (SMP::initialised) { // If we have other CPUs to stop:
            // Halt all other CPUs.
            APIC::sendipi(0, 0xfd, APIC::IPIFIXED, APIC::IPIPHYS, APIC::IPIOTHER);
        }

        CPU::get()->setint(false); // Disable interrupts. We don't want to be woken up.

        NUtil::oprintlock();
        NUtil::canmutex = false; // Prevent usage of mutexes during panic.

        NUtil::printf("[\x1b[1;31mPANIC\x1b[0m]: %s", msg);
        for (;;) {
            asm volatile("hlt");
        }

        __builtin_unreachable();
    }
}
