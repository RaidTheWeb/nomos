#include <arch/limine/arch.hpp>
#include <arch/limine/requests.hpp>
#include <arch/x86_64/acpi.hpp>
#include <arch/x86_64/apic.hpp>
#include <arch/x86_64/arch.hpp>
#include <arch/x86_64/gdt.hpp>
#include <arch/x86_64/hpet.hpp>
#include <arch/x86_64/interrupts.hpp>
#include <arch/x86_64/io.hpp>
#include <arch/x86_64/kpti.hpp>
#include <arch/x86_64/pmm.hpp>
#include <arch/x86_64/serial.hpp>
#include <arch/x86_64/smp.hpp>
#include <arch/x86_64/tsc.hpp>
#include <arch/x86_64/vmm.hpp>
#include <lib/assert.hpp>
#include <lib/cmdline.hpp>
#include <lib/string.hpp>
#include <mm/slab.hpp>
#include <sched/sched.hpp>
#include <util/kprint.hpp>

#define EARLYSERIAL 0

extern void kinit1(void);

extern void *__trampoline_start;
extern void *__trampoline_end;
extern "C" void trampoline_entry(void);
namespace NArch {
    bool hypervisor_enabled = false;
    bool hypervisor_checked = false;

    NLib::CmdlineParser cmdline;


    static int i = 0;

    extern "C" void uentry(int *i);

    // This function runs as a thread, post scheduler initialisation.
    void archthreadinit(void) {
        NUtil::printf("Hello kernel thread!\n");

        kinit1();

        struct VMM::addrspace uspace;
        uspace.ref = 1;
        uspace.pml4 = (struct VMM::pagetable *)PMM::alloc(PAGESIZE);
        uspace.pml4phy = (uintptr_t)uspace.pml4;
        uspace.pml4 = (struct VMM::pagetable *)hhdmoff(uspace.pml4);
        NLib::memset(uspace.pml4, 0, PAGESIZE);

        uspace.vmaspace = new NMem::Virt::VMASpace(0x0000000000001000, 0x0000800000000000); // Provide userspace VMA.

        for (size_t i = 0; i < 256; i++) {
            uint64_t *entry = (uint64_t *)PMM::alloc(PAGESIZE);
            assert(entry != NULL, "Failed to allocate intermediate entries.\n");
            NLib::memset(hhdmoff(entry), 0, PAGESIZE);
            uspace.pml4->entries[i] = (uint64_t)entry | VMM::PRESENT | VMM::WRITEABLE | VMM::USER;
        }

        NSched::Process *proc = new NSched::Process(&uspace);

        NSched::Thread *uthread = new NSched::Thread(proc, NSched::DEFAULTSTACKSIZE, (void *)uentry, (void *)&i);
        uintptr_t ustack = (uintptr_t)PMM::alloc(NSched::DEFAULTSTACKSIZE); // Allocate user stack, and point RSP to the top.
        uintptr_t virt = (uintptr_t)uspace.vmaspace->alloc(NSched::DEFAULTSTACKSIZE, NMem::Virt::VIRT_NX | NMem::Virt::VIRT_RW | NMem::Virt::VIRT_USER);
        VMM::maprange(&uspace, virt, ustack, VMM::NOEXEC | VMM::WRITEABLE | VMM::USER | VMM::PRESENT, NSched::DEFAULTSTACKSIZE); // Map stack.

        VMM::maprange(&uspace, KPTI::ULOCALVIRT, KPTI::ulocalphy, VMM::PRESENT | VMM::NOEXEC | VMM::USER, KPTI::ULOCALVIRTTOP - KPTI::ULOCALVIRT); // Map CPU locals into constant mapped memory.
        VMM::maprange(&uspace, KPTI::TRAMPOLINEVIRT, (uintptr_t)(trampoline_entry) - NLimine::eareq.response->virtual_base + NLimine::eareq.response->physical_base, VMM::PRESENT | VMM::USER, PAGESIZE * 2); // Read-only + Executable + User.

        uintptr_t evirt = (uintptr_t)uspace.vmaspace->alloc(PAGESIZE, NMem::Virt::VIRT_USER);
        uintptr_t ephy = (uintptr_t)uentry - NLimine::eareq.response->virtual_base + NLimine::eareq.response->physical_base;
        size_t off = ephy % PAGESIZE;
        uthread->ctx.rip = evirt + off;
        VMM::mappage(&uspace, evirt, (uintptr_t)uentry - NLimine::eareq.response->virtual_base + NLimine::eareq.response->physical_base, VMM::PRESENT | VMM::USER);



        uthread->ctx.rsp = virt + NSched::DEFAULTSTACKSIZE;

        NSched::schedulethread(uthread);

        size_t deadline = TSC::query() + 400000000;
        while (TSC::query() < deadline) {
            asm ("pause");
        }

        NUtil::printf("0x%08x.\n", i);

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

        uint8_t *stack = (uint8_t *)PMM::alloc(64 * 1024 * 1024);
        CPU::getbsp()->ist.rsp0 = (uint64_t)NArch::hhdmoff((void *)stack) + (64 * 1024 * 1024);

        // GDT needs to be initialised and loaded before the IDT.
        GDT::setup();
        GDT::reload();
        NUtil::printf("[gdt]: GDT Reloaded.\n");

        Interrupts::setup();
        Interrupts::reload();
        NUtil::printf("[idt]: Interrupts Reloaded.\n");

        NMem::allocator.setup();

        // Setup command line, must happen after slab allocator is set up.
        cmdline.setup(NLimine::ecreq.response->cmdline);

        if (cmdline.get("serialcom1") != NULL) {
            NUtil::printf("[arch/x86_64]: Serial enabled via serialcom1 command line argument.\n");

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

        KPTI::setup(); // Initialise KPTI protections, must be done before SMP is initialised to have the ulocals mapped.

        SMP::setup();

        CPU::init(); // Initialise BSP state.

        NSched::Thread *kthread = new NSched::Thread(NSched::kprocess, NSched::DEFAULTSTACKSIZE, (void *)archthreadinit);
        NSched::schedulethread(kthread);

        NUtil::printf("[arch/x86_64]: Jump into scheduler on kernel main.\n");

        NSched::await(); // End here. Any work afterwards occurs within the kernel thread.
    }
}
