#include <arch/x86_64/panic.hpp>

namespace NArch {
    void panic(const char *msg) {

        NUtil::printf("[\x1b[1;31mPANIC\x1b[0m]: %s", msg);


        // Halt all other CPUs.
        APIC::sendipi(0, 0xfd, APIC::IPIFIXED, APIC::IPIPHYS, APIC::IPIOTHER);

        CPU::get()->setint(false); // Disable interrupts. We don't want to be woken up.
        for (;;) {
            asm volatile("hlt");
        }

        __builtin_unreachable();
    }
}
