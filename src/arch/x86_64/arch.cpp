#include <arch/limine/arch.hpp>
#include <arch/limine/requests.hpp>
#include <arch/x86_64/acpi.hpp>
#include <arch/x86_64/apic.hpp>
#include <arch/x86_64/arch.hpp>
#include <arch/x86_64/gdt.hpp>
#include <arch/x86_64/interrupts.hpp>
#include <arch/x86_64/io.hpp>
#include <arch/x86_64/pmm.hpp>
#include <arch/x86_64/serial.hpp>
#include <arch/x86_64/vmm.hpp>
#include <lib/assert.hpp>
#include <lib/cmdline.hpp>
#include <lib/string.hpp>
#include <mm/slab.hpp>
#include <util/kprint.hpp>

#define EARLYSERIAL 0

namespace NArch {
    bool hypervisor_enabled = false;
    bool hypervisor_checked = false;

    NLib::CmdlineParser cmdline;

    void init(void) {
        NUtil::printf("[arch/x86_64]: x86_64 init().\n");

        char vendor[13] = { 0 };
        uint32_t *vcpu1 = (uint32_t *)vendor;
        uint32_t *vcpu2 = (uint32_t *)(vendor + 4);
        uint32_t *vcpu3 = (uint32_t *)(vendor + 8);
        asm volatile(
            "cpuid"
            : "=b"(*vcpu1), "=d"(*vcpu2), "=c"(*vcpu3)
            : "a"(0) // Get vendor string.
        );

        NUtil::printf("[arch/x86_64]: CPU Vendor: %s.\n", vendor);

        char procname[48] = { 0 };
        uint32_t *vprocname = (uint32_t *)procname;

        size_t procidx = 0;
        for (size_t i = 0; i < 3; i++) {
            uint32_t eax, ebx, ecx, edx;
            asm volatile(
                "cpuid"
                : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
                : "a"(0x80000002 + i) // Processor Name -> Supported by both AMD64 and Intel 64.
            );
            vprocname[procidx++] = eax;
            vprocname[procidx++] = ebx;
            vprocname[procidx++] = ecx;
            vprocname[procidx++] = edx;
        }

        NUtil::printf("[arch/x86_64]: CPU Name: %s.\n", NLib::strtrim(procname));

        uint32_t supported;
        asm volatile(
            "cpuid"
            : "=c"(supported)
            : "a"(1) // Check for features.
        );

        // If this bit exists within the ECX features, a Hypervisor is supervising this system.
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

            char vendorfn[32];
            if (!NLib::strcmp(vendor, "KVMKVMKVM\0\0\0")) {
                NUtil::snprintf(vendorfn, sizeof(vendorfn), "QEMU/KVM");
            } else if (!NLib::strcmp(vendor, "TCGTCGTCGTCG")) {
                NUtil::snprintf(vendorfn, sizeof(vendorfn), "QEMU");
            } else if (!NLib::strcmp(vendor, "VMwareVMware")) {
                NUtil::snprintf(vendorfn, sizeof(vendorfn), "VMware");
            } else if (!NLib::strcmp(vendor, "VBoxVBoxVBox")) {
                NUtil::snprintf(vendorfn, sizeof(vendorfn), "VirtualBox");
            } else {
                NUtil::snprintf(vendorfn, sizeof(vendorfn), "Unknown");
            }


            NUtil::printf("[arch/x86_64]: Hypervisor %s Detected.\n", vendorfn);
            hypervisor_enabled = true;

#if EARLYSERIAL == 1
            NUtil::printf("[arch/x86_64]: Enable UART in Hypervisor.\n");
            NArch::Serial::setup();
#endif
        } else {
            NUtil::printf("[arch/x86_64]: No Hypervisor Detected. Assuming real hardware.\n");
        }
        hypervisor_checked = true;

        NLimine::init();

        // gdt = GDT();
        GDT::setup();
        GDT::reload();

        // idt = InterruptTable();
        Interrupts::setup();
        Interrupts::reload();

        // pmm = PMM();
        PMM::setup();

        NMem::allocator.setup();

        // Setup command line.
        cmdline.setup(NLimine::ecreq.response->cmdline);

        if (cmdline.get("serialcom1") != NULL) {
            NUtil::printf("[arch/x86_64]: Serial enabled via serialcom1 command line argument.\n");
            NArch::Serial::setup();
            NArch::Serial::serialenabled = true;
        }
        NArch::Serial::serialchecked = true;

        VMM::setup();

        ACPI::setup();

        APIC::setup();

        APIC::lapicinit();
    }
}
