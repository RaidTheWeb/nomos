#include <arch/x86_64/arch.hpp>
#include <arch/x86_64/gdt.hpp>
#include <arch/x86_64/kpti.hpp>
#include <arch/x86_64/smp.hpp>
#include <arch/x86_64/vmm.hpp>
#include <lib/assert.hpp>

namespace NArch {
    namespace KPTI {
        uintptr_t ulocalphy = 0;
        struct CPU::ulocal *ulocals;

        extern "C" void gdt_flush(void *);
        extern "C" const uint64_t isr_table[256];
        extern "C" void trampoline_entry(void);

        void apsetup(void) {
            // Set MSR Kernel GS base, this will be swapped into the normal GS on user entry.
            CPU::wrmsr(CPU::MSRKGSBASE, ULOCALVIRT + (CPU::get()->id * sizeof(struct CPU::ulocal)));
            struct CPU::ulocal *ulocal = &ulocals[CPU::get()->id];
            assertarg(ulocal->stack, "Failed to allocate memory for User Local temporary stack on CPU%lu.\n", CPU::get()->id);
            ulocal->stacktop = (uintptr_t)ulocal->stack + PAGESIZE; // Point to top of stack.

            CPU::get()->ulocalstack = ulocal->stacktop; // Copy to kernel CPU local.

            NLib::memcpy(&ulocal->gdt[0], &CPU::get()->gdt[0], sizeof(ulocal->gdt)); // Copy GDT.

            NLib::memcpy(&ulocal->ist, &CPU::get()->ist, sizeof(ulocal->ist)); // Copy IST.

            uintptr_t istaddr = (uintptr_t)&ulocal->ist;
            ulocal->gdt[5] = 0x0020890000000000 | (((istaddr & 0xff000000) << 32) | ((istaddr & 0xff0000) << 16) | ((istaddr & 0xffff) << 16) | sizeof(struct CPU::ist));
            ulocal->gdt[6] = 0 | ((istaddr >> 32) & 0xffffffff);

            struct GDT::gdtr gdtr = {
                .size = sizeof(ulocal->gdt) - 1,
                .offset = (uint64_t)&ulocal->gdt[0]
            };

            asm volatile("lgdt %0" : : "m"(gdtr) : "memory"); // Swap to globally mapped GDT. Same data, so no need to do a full reload.
            asm volatile("ltr %0" : : "rm"(0x28) : "memory"); // Reload TSS.


            NLib::memcpy(&ulocal->idt[0], &Interrupts::idt[0], sizeof(Interrupts::idt));

            bool old = CPU::get()->setint(false); // Switch off interrupts during this critical section.
            for (size_t i = 0; i < 256; i++) { // Transition interrupt handlers into their globally mapped section.
                uintptr_t orig = isr_table[i];
                size_t offset = (uintptr_t)orig - (uintptr_t)trampoline_entry; // Compute offset from trampoline entry.
                uintptr_t virt = (uint64_t)KPTI::TRAMPOLINEVIRT + offset; // Calculate virtual address of ISR stub using the offset from start of trampoline section.
                ulocal->idt[i].offlow = virt & 0xffff;
                ulocal->idt[i].offmid = (virt >> 16) & 0xffff;
                ulocal->idt[i].offhigh = (virt >> 32) & 0xffffffff;
            }


            struct Interrupts::idtr idtr = {
                .size = sizeof(ulocal->idt) - 1,
                .offset = (uint64_t)&ulocal->idt[0]
            };
            asm volatile("lidt %0" : : "m"(idtr) : "memory"); // Swap to globally mapped IDT. Simply just reload.
            CPU::get()->setint(old);

            ulocal->kcr3 = (uintptr_t)hhdmsub(CPU::get()->kpt); // Reference cloned maps.
        }

        void setup(void) {
            if (cmdline.get("nokpti")) {
                NUtil::printf("[kpti]: Meltdown mitigations disabled due to `nokpti` command line argument.\n");
                return;
            }

            // Makes relative to the number of CPUs SMP states, rather than what is actually awake.
            ulocalphy = (uintptr_t)PMM::alloc(NLimine::mpreq.response->cpu_count * sizeof(struct CPU::ulocal));

            VMM::maprange(&VMM::kspace, ULOCALVIRT, ulocalphy, VMM::PRESENT | VMM::WRITEABLE | VMM::NOEXEC, pagealign(NLimine::mpreq.response->cpu_count * sizeof(struct CPU::ulocal), PAGESIZE));
            ulocals = (struct CPU::ulocal *)ULOCALVIRT; // Referencing using virtual address.

            apsetup(); // On BSP.
            NUtil::printf("[kpti]: Initialised Meltdown mitigation.\n");
        }
    }
}
