#include <arch/limine/arch.hpp>
#include <arch/limine/module.hpp>
#include <arch/limine/requests.hpp>
#include <arch/x86_64/acpi.hpp>
#include <arch/x86_64/apic.hpp>
#include <arch/x86_64/arch.hpp>
#include <arch/x86_64/gdt.hpp>
#include <arch/x86_64/hpet.hpp>
#include <arch/x86_64/interrupts.hpp>
#include <arch/x86_64/io.hpp>
#include <arch/x86_64/pmm.hpp>
#include <arch/x86_64/serial.hpp>
#include <arch/x86_64/smp.hpp>
#include <arch/x86_64/tsc.hpp>
#include <arch/x86_64/vmm.hpp>
#include <fs/ustar.hpp>
#include <lib/assert.hpp>
#include <lib/cmdline.hpp>
#include <lib/string.hpp>
#include <mm/slab.hpp>
#include <sched/sched.hpp>
#include <util/kprint.hpp>

#define EARLYSERIAL 0

extern void kpostarch(void);

namespace NArch {
    bool hypervisor_enabled = false;
    bool hypervisor_checked = false;

    NLib::CmdlineParser cmdline;

    extern "C" void uentry(void);

    // This function runs as a thread, post scheduler initialisation.
    void archthreadinit(void) {
        kpostarch();

        NSched::exit();
    }

    void init(void) {
        NUtil::printf("[arch/x86_64]: x86_64 init().\n");

        CPU::set(CPU::getbsp()); // Set BSP's instance.

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
            NArch::Serial::serialchecked = true;
            NArch::Serial::serialenabled = true;
            NArch::Serial::setup();
#endif
        } else {
            NUtil::printf("[arch/x86_64]: No Hypervisor Detected. Assuming real hardware.\n");
        }
        hypervisor_checked = true;

        NLimine::init();

        PMM::setup();

        // GDT needs to be initialised and loaded before the IDT.
        GDT::setup();
        GDT::reload();
        NUtil::printf("[arch/x86_64/gdt]: GDT Reloaded.\n");

        Interrupts::setup();
        Interrupts::reload();
        NUtil::printf("[arch/x86_64/idt]: Interrupts Reloaded.\n");

        NMem::allocator.setup();

        // Setup command line, must happen after slab allocator is set up.
        cmdline.setup(NLimine::ecreq.response->cmdline);

        // Command line argument enables memory sanitisation upon slab allocator free. Helps highlight memory management issues, and protect against freed memory inspection.
        NMem::sanitisefreed = cmdline.get("mmsan") != NULL;

        // Debug fill allocations with garbage 0xAA before allocation. Catches UBs on QEMU, where memory may not be filled with garbage initially.
        NMem::nonzeroalloc = cmdline.get("nzalloc") != NULL;

        if (cmdline.get("serialcom1") != NULL) {
            NUtil::printf("[arch/x86_64]: Serial enabled via `serialcom1` command line argument.\n");

            Serial::serialchecked = true;
            Serial::serialenabled = true;
            Serial::setup();
        }
        Serial::serialchecked = true;

        VMM::setup();

        // Test VMA.
        uintptr_t test = (uintptr_t)VMM::kspace.vmaspace->alloc(4096, NMem::Virt::VIRT_RW | NMem::Virt::VIRT_NX);
        void *p = PMM::alloc(4096);
        *((uint8_t *)((uintptr_t)p + NLimine::hhdmreq.response->offset)) = 0xab;

        VMM::mappage(&VMM::kspace, test, (uintptr_t)p, VMM::PRESENT | VMM::WRITEABLE | VMM::NOEXEC);
        void *virtptr = (void *)test;
        assert(*((uint8_t *)virtptr) == 0xab, "VMA allocator + VMM mapping self-test failed.\n");
        VMM::unmappage(&VMM::kspace, test);
        VMM::kspace.vmaspace->free(virtptr, 4096);

        ACPI::setup(); // Initialise uACPI and load relevant tables.

        HPET::setup(); // Initialise timer, needed for later calibrations.

        TSC::setup(); // Initialise lower overhead timer, useful for calibrations, but also for logging.

        APIC::setup(); // Set up IOAPIC using ACPI tables.

        APIC::lapicinit(); // Initialise BSP using LAPIC init.

        NSched::setup();

        SMP::setup();

        CPU::init(); // Initialise BSP state.

        NUtil::canmutex = true; // We're allowed to print mutex now.

        NSched::Thread *kthread = new NSched::Thread(NSched::kprocess, NSched::DEFAULTSTACKSIZE, (void *)archthreadinit);
        NSched::schedulethread(kthread);

        NUtil::printf("[arch/x86_64]: Jump into scheduler on kernel main.\n");

        NSched::await(); // End here. Any work afterwards occurs within the kernel thread.
    }
}
