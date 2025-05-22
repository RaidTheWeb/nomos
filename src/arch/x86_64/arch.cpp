#include <arch/limine/arch.hpp>
#include <arch/x86_64/arch.hpp>
#include <arch/x86_64/gdt.hpp>
#include <arch/x86_64/interrupts.hpp>
#include <arch/x86_64/serial.hpp>
#include <util/kprint.hpp>

namespace NArch {
    bool hypervisor_enabled = false;
    bool hypervisor_checked = false;

    void init(void) {
        NUtil::printf("[arch/x86_64]: x86_64 init()\n");

        uint32_t supported;
        asm volatile(
            "cpuid"
            : "=c"(supported)
            : "a"(1) // Check for features.
        );

        // Is hypervisor detection supported?
        if (supported & (1 << 31)) {

            char vendor[13] = { 0 };
            uint32_t *vcpu1 = (uint32_t *)vendor;
            uint32_t *vcpu2 = (uint32_t *)(vendor + 4);
            uint32_t *vcpu3 = (uint32_t *)(vendor + 8);
            asm volatile(
                "cpuid"
                : "=b"(*vcpu1), "=c"(*vcpu2), "=d"(*vcpu3)
                : "a"(0x40000000)
            );

            NUtil::printf("[arch/x86_64]: Hypervisor %s Detected.\n", vendor);
            hypervisor_enabled = true;

            NUtil::printf("[arch/x86_64]: Enable UART in Hypervisor.\n");
            NArch::serial_init();
        } else {
            NUtil::printf("[arch/x86_64]: No Hypervisor Detected. Assuming real hardware.\n");
        }
        hypervisor_checked = true;

        NLimine::init();

        GDT gdt = GDT();
        gdt.setup();
        gdt.reload();

        InterruptTable table = InterruptTable();
        table.setup();
        table.reload();


    }
}
