#include <arch/x86_64/apic.hpp>
#include <arch/x86_64/cpu.hpp>
#include <arch/x86_64/interrupts.hpp>
#include <arch/x86_64/io.hpp>
#include <arch/x86_64/panic.hpp>
#include <lib/assert.hpp>
#include <util/kprint.hpp>

namespace NArch {
    namespace Interrupts {
        // Reference ISR table from assembly. This is for stubs, not handlers.
        extern "C" const uint64_t isr_table[256];

        struct idtentry idt[256];
        static struct idtr idtr;

        static const char *exceptions[] = {
            "Division Error (#DE)",
            "Debug (#DB)",
            "Non-Maskable Interrupt",
            "Breakpoint (#BP)",
            "Overflow (#OF)",
            "Bound Range Exceeded (#BR)",
            "Invalid Opcode (#UD)",
            "Device Not Available (#NM)",
            "Double Fault (#DF)",
            "???",
            "Invalid TSS (#TS)",
            "Segment Not Present (#NP)",
            "Stack Segment Fault (#SS)",
            "General Protection Fault (#GP)",
            "Page Fault (#PF)",
            "???",
            "x87 Floating Point Exception (#MF)",
            "Alignment Check (#AC)",
            "Machine Check (#MC)",
            "SIMD Floating Point Exception (#XM)",
            "Virtualisation Exception (#VE)",
            "Control Protection Exception (#CP)",
            "???",
            "???",
            "???",
            "???",
            "???",
            "???",
            "Hypervisor Injection Exception (#HV)",
            "VMM Communication Exception (#VC)",
            "Security Exception (#SX)",
            "???"
        };

        struct isr *regisr(uint8_t vec, void (*func)(struct isr *self, struct CPU::context *ctx), bool eoi) {
            bool old = CPU::get()->setint(false); // Clear. XXX: Should be only clearing if not already cleared (record interrupt state for current CPU).

            struct isr *isr = &CPU::get()->isrtable[vec];
            isr->eoi = eoi;
            isr->func = func;
            isr->id = ((uint64_t)CPU::get()->lapicid << 32) | vec; // XXX: Encode ISR ID.

            CPU::get()->setint(old); // Restore.
            return isr;
        }

        uint8_t allocvec(void) {
            bool old = CPU::get()->setint(false); // Clear.

            for (size_t i = 0; i < 256; i++) {
                if (!CPU::get()->isrtable[i].func) {
                    CPU::get()->setint(old);
                    return i;
                }
            }
            assert(false, "Could not find a vector to allocate.\n");
            return 0;
        }

        extern "C" void isr_handle(uint64_t vec, struct CPU::context *ctx) {
            struct isr *isr = &CPU::get()->isrtable[vec];
            CPU::get()->intstatus = false;

            if (isr->func != NULL) { // If this ISR has been allocated.

                if (isr->eoi) { // Should this ISR trigger an EOI?
                    APIC::eoi();
                }
                isr->func(isr, ctx); // Call ISR function.
            }

            CPU::get()->intstatus = ctx->rflags & 0x200 ? true : false;
        }

        void exception_handler(struct isr *isr, struct CPU::context *ctx) {
            (void)ctx;
            char errbuffer[2048];
            if ((isr->id & 0xffffffff) == 14) { // #PF
                uintptr_t addr = 0;
                asm volatile(
                    "mov %%cr2, %0"
                    : "=r"(addr) : : "memory"
                );
                NUtil::snprintf(errbuffer, sizeof(errbuffer), "CPU Exception: %s.\nPage fault at %p occurred due to %s %s in %p during %s as %s.\n", exceptions[isr->id & 0xffffffff], ctx->rip, ctx->err & (1 << 1) ? "Write" : "Read", ctx->err & (1 << 0) ? "Page protection violation" : "Non-present page violation", addr, ctx->err & (1 << 4) ? "Instruction Fetch" : "Normal Operation", ctx->err & (1 << 2) ? "User" : "Supervisor");
            } else if ((isr->id & 0xffffffff) == 13) { // #GP
                NUtil::snprintf(errbuffer, sizeof(errbuffer), "CPU Exception: %s.\nGeneral Protection Fault occurred at %p.\n", exceptions[isr->id & 0xffffffff], ctx->rip);
            } else if ((isr->id & 0xffffffff) == 7) { // #NM
                NUtil::snprintf(errbuffer, sizeof(errbuffer), "#NM at %p.\n", ctx->rip);
                NLimine::console_write(errbuffer, NLib::strlen(errbuffer));
                NSched::handlelazyfpu();
                return;
            } else {
                NUtil::snprintf(errbuffer, sizeof(errbuffer), "CPU Exception: %s.\nOccurred at %p.\n", exceptions[isr->id & 0xffffffff], ctx->rip);
            }

            panic(errbuffer);
        }

        void setup(void) {
            idtr = {
                .size = sizeof(idt) - 1,
                .offset = (uint64_t)&idt[0]
            };

        // Register the entire set of 256 vectors for the sake of directing them towards a generic handler.
            for (size_t i = 0; i < 256; i++) {
                // Offset to handler:
                idt[i].offlow = isr_table[i] & 0xffff;
                idt[i].offmid = (isr_table[i] >> 16) & 0xffff;
                idt[i].offhigh = (isr_table[i] >> 32) & 0xffffffff;
                idt[i].ist = 0;
                idt[i].flags = 0x8e;
                idt[i].cs = 0x08; // Kernel code segment -> We want the kernel to be handling all interrupts.
                idt[i].rsvd = 0;
            }
        }

        void reload(void) {
            asm volatile("lidt (%%rax)" : : "a"(&idtr));

            for (size_t i = 0; i < 32; i++) { // Register ISRs for exceptions.
                regisr(i, exception_handler, false);
            }

            CPU::get()->setint(true);
        }
    }
}
