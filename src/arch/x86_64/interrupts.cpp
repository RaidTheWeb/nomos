#include <arch/x86_64/interrupts.hpp>
#include <util/kprint.hpp>

namespace NArch {
    // Reference ISR table from assembly. This is for stubs, not handlers.
    extern "C" const uint64_t isr_table[256];


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

    extern "C" void isr_handle(uint64_t vec, void *ctx) {
        if (vec < 32) { // Exceptions.
            NUtil::printf("[\x1b[1;31mPANIC\x1b[0m]: CPU Exception: %s.\n", exceptions[vec]);
            for (;;) {
                asm("hlt");
            }
        }
    }

    void InterruptTable::regint(uint8_t vector, void *isr, uint8_t flags) {

    }

    void InterruptTable::setup(void) {
    // Register the entire set of 256 vectors for the sake of directing them towards a generic handler.
        for (size_t i = 0; i < 256; i++) {
            // Offset to handler:
            this->idt[i].offlow = isr_table[i] & 0xffff;
            this->idt[i].offmid = (isr_table[i] >> 16) & 0xffff;
            this->idt[i].offhigh = (isr_table[i] >> 32) & 0xffffffff;
            this->idt[i].ist = 0;
            this->idt[i].flags = 0x8e;
            this->idt[i].cs = 0x08; // Kernel code segment -> We want the kernel to be handling all interrupts.
            this->idt[i].rsvd = 0;
        }
    }

    void InterruptTable::reload(void) {
        asm volatile("lidt (%%rax)" : : "a"(&this->idtr));

        asm volatile("sti");
        NUtil::printf("[idt]: Interrupts Reloaded.\n");
    }
}
