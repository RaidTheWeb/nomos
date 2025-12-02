#include <arch/limine/requests.hpp>
#include <arch/x86_64/apic.hpp>
#include <arch/x86_64/arch.hpp>
#include <arch/x86_64/gdt.hpp>
#include <arch/x86_64/interrupts.hpp>
#include <arch/x86_64/smp.hpp>
#include <arch/x86_64/timer.hpp>
#include <arch/x86_64/vmm.hpp>
#include <lib/align.hpp>
#include <lib/assert.hpp>
#include <lib/string.hpp>
#include <sched/sched.hpp>
#include <stdatomic.h>
#include <util/kprint.hpp>

namespace NArch {
    namespace SMP {

        struct CPU::cpulocal **cpulist = NULL;
        size_t awakecpus = 1; // Start at 1, to include BSP.
        bool initialised = false;

        // End of the road interrupt hanbdler for panic IPI.
        static void halt(struct Interrupts::isr *isr, struct CPU::context *ctx) {
            (void)isr;
            (void)ctx;

            APIC::lapicstop(); // Prevent any scheduling work from jumping a CPU out of of the panic state.
            CPU::get()->setint(false);
            for (;;) {
                asm volatile("hlt");
            }
        }

        static void wakeup(struct limine_mp_info *info) {
            CPU::set((struct CPU::cpulocal *)info->extra_argument); // Set from initial argument.

            GDT::reload(); // "Reload" GDT -> Initialise it on this CPU.
            Interrupts::reload(); // "Reload" IDT -> Initialise it on this CPU.

            VMM::swapcontext(&VMM::kspace);

            // Initialise LAPIC.
            APIC::lapicinit();

            // Register an interrupt handler for a panic vector.
            Interrupts::regisr(0xfd, halt, false);
            // Register interrupt handler for tlb shotodown.
            Interrupts::regisr(0xfc, VMM::tlbshootdown, true);

            CPU::init(); // Initialise CPU (Specifics).

            NUtil::printf("[arch/x86_64/smp]: Non-BSP CPU%lu initialised.\n", info->processor_id);

            Timer::setisr(); // Setup periodic timer for this CPU.

            __atomic_add_fetch(&awakecpus, 1, memory_order_seq_cst); // Increment counter, so that we can tell if all CPUs have been initialised.
            NSched::entry();
        }

        void setup(void) {
            Interrupts::regisr(0xfd, halt, false);
            // Register interrupt handler for tlb shootdown.
            Interrupts::regisr(0xfc, VMM::tlbshootdown, true);

            struct limine_mp_response *mpresp = NLimine::mpreq.response;

            struct CPU::cpulocal *phycpus = (struct CPU::cpulocal *)PMM::alloc(NLib::alignup(sizeof(struct CPU::cpulocal) * mpresp->cpu_count, PAGESIZE)); // We'll never free this.

            assert(phycpus, "Failed to allocate memory for CPU instances.\n");

            phycpus = (struct CPU::cpulocal *)NArch::hhdmoff((void *)phycpus);
            NLib::memset(phycpus, 0, NLib::alignup(sizeof(struct CPU::cpulocal) * mpresp->cpu_count, PAGESIZE));

            cpulist = new struct CPU::cpulocal *[mpresp->cpu_count]; // Slab allocate for pointers to pointers, this'll be used for looping on every CPU (for stuff like sending IPIs).
            assert(cpulist, "Failed to allocate memory for list of CPU instances.\n");

            bool nosmp = false;
            if (NArch::cmdline.get("nosmp")) {
                nosmp = true;
                NUtil::printf("[arch/x86_64/smp]: Skipping SMP initialisation due to `nosmp` command line argument.\n");
            } else {
                NUtil::printf("[arch/x86_64/smp]: Initialising SMP on %lu logical processors...\n", mpresp->cpu_count);
            }

            for (size_t i = 0; i < mpresp->cpu_count; i++) {
                if (mpresp->cpus[i]->lapic_id == mpresp->bsp_lapic_id) {
                    cpulist[i] = CPU::getbsp();

                    cpulist[i]->id = mpresp->cpus[i]->processor_id;
                    cpulist[i]->lapicid = mpresp->cpus[i]->lapic_id;

                    if (nosmp) {
                        return; // We're done here. Exit.
                    }

                    continue; // Skip BSP initialisation.
                }

                if (!nosmp) {
                    mpresp->cpus[i]->extra_argument = (uint64_t)&phycpus[i];
                    cpulist[i] = &phycpus[i]; // Update cpu list with physical instance.

                    cpulist[i]->id = mpresp->cpus[i]->processor_id;
                    cpulist[i]->lapicid = mpresp->cpus[i]->lapic_id;

                    __atomic_store_n(&mpresp->cpus[i]->goto_address, (void (*)(struct limine_mp_info *))wakeup, memory_order_seq_cst); // Atomic write to goto address, calls
                }
            }

            NUtil::printf("[arch/x86_64/smp]: Awaiting on SMP wakeup of non-BSP CPUs.\n");
            while (__atomic_load_n(&awakecpus, memory_order_seq_cst) != mpresp->cpu_count) { // Wait until all cpus are awake. After the CPU is awoken, it will increment this counter (atomically).
                asm volatile("pause" : : : "memory");
            }

            initialised = true; // Mark for other kernel subsystems.
            NUtil::printf("[arch/x86_64/smp]: SMP initialised.\n");
        }
    }
}
