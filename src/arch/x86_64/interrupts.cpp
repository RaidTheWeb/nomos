#include <arch/x86_64/apic.hpp>
#include <arch/x86_64/cpu.hpp>
#include <arch/x86_64/interrupts.hpp>
#include <arch/x86_64/io.hpp>
#include <lib/assert.hpp>
#include <util/kprint.hpp>

namespace NArch {
    namespace Interrupts {
        // Reference ISR table from assembly. This is for stubs, not handlers.
        extern "C" const uint64_t isr_table[256];

        static struct idtentry idt[256];
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

        static const char scancode_to_ascii[256] = {
            '\0', '\0',
            '1', '2', '3', '4', '5',
            '6', '7', '8', '9', '0',
            '\0', '\0', '\b', '\0',
            'q', 'w', 'e', 'r', 't',
            'y', 'u', 'i', 'o', 'p',
            '\0', '\0', '\n', '\0',
            'a', 's', 'd', 'f', 'g',
            'h', 'j', 'k', 'l',
            '\0', '\0', '\0', '\0', '\0',
            'z', 'x', 'c', 'v', 'b',
            'n', 'm', ',', '.', '/',
            '\0', '\0', '\0',
            ' '
        };

        struct isr isrtable[256];

        struct isr *regisr(uint8_t vec, void (*func)(struct isr *self, struct CPU::context *ctx), bool eoi) {
            asm volatile("cli"); // Clear. XXX: Should be only clearing if not already cleared (record interrupt state for current CPU).

            struct isr *isr = &isrtable[vec];
            isr->eoi = eoi;
            isr->func = func;
            isr->id = ((uint64_t)0 << 32) | vec; // XXX: Encode ISR ID.

            asm volatile("sti"); // Reenable.
            return isr;
        }

        uint8_t allocvec(void) {
            asm volatile("cli"); // Clear.

            for (size_t i = 0; i < 256; i++) {
                if (!isrtable[i].func) {
                    asm volatile("sti");
                    return i;
                }
            }
            assert(false, "Could not find a vector to allocate.\n");
            return 0;
        }

        extern "C" void isr_handle(uint64_t vec, struct CPU::context *ctx) {
            struct isr *isr = &isrtable[vec];

            if (isr->func != NULL) { // If this ISR has been allocated.

                isr->func(isr, ctx); // Call ISR function.

                if (isr->eoi) { // Should this ISR trigger an EOI?
                    APIC::eoi();
                }
            }
        }

        void exception_handler(struct isr *isr, struct CPU::context *ctx) {
            (void)ctx;
            NUtil::printf("[\x1b[1;31mPANIC\x1b[0m]: CPU Exception: %s.\n", exceptions[isr->id & 0xffffffff]);

            if ((isr->id & 0xffffffff) == 14) {
                uintptr_t addr = 0;
                asm volatile(
                    "mov %%cr2, %0"
                    : "=r"(addr) : : "memory"
                );
                NUtil::printf("Page fault at %p occurred due to %s %s in %p during %s.\n", ctx->rip, ctx->err & (1 << 1) ? "Write" : "Read", ctx->err & (1 << 0) ? "Page protection violation" : "Non-present page violation", addr, ctx->err & (1 << 4) ? "Instruction Fetch" : "Normal Operation");
            }

            for (;;) { // "Unrecoverable"
                asm("cli");
                asm("hlt");
            }
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

            for (size_t i = 0; i < 32; i++) { // Register ISRs for exceptions.
                regisr(i, exception_handler, false);
            }
        }

        void reload(void) {
            asm volatile("lidt (%%rax)" : : "a"(&idtr));

            asm volatile("sti");
            NUtil::printf("[idt]: Interrupts Reloaded.\n");
        }
    }
}
