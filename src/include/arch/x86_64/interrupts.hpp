#ifndef _ARCH__X86_64__INTERRUPTS_HPP
#define _ARCH__X86_64__INTERRUPTS_HPP

#include <arch/x86_64/cpu.hpp>
#include <stdint.h>

namespace NArch {
    namespace Interrupts {
        struct idtentry {
            uint16_t offlow; // Lower 16-bit offset.
            uint16_t cs;
            uint8_t ist;
            uint8_t flags;
            uint16_t offmid; // Higher 16-bit offset -> to form 32-bit offset.
            uint32_t offhigh; // Highest 32-bit offset -> to form 64-bit offset.
            uint32_t rsvd;
        } __attribute__((packed));

        struct idtr {
            uint16_t size; // IDT size.
            uint64_t offset; // IDT offset.
        } __attribute__((packed));

        // Entry for an interrupt service routine.
        struct isr {
            uint64_t id; // Combination of both the cpu id (upper 32-bits), and the vector (lower 32-bits).
            bool eoi; // Should this ISR trigger a LAPIC EOI acknowledgement, following its work.

            // Function to call when the interrupt handler is triggered.
            void (*func)(struct isr *self, struct CPU::context *ctx);
        };

        // Register an ISR.
        struct isr *regisr(uint8_t vec, void (*func)(struct isr *self, struct CPU::context *ctx), bool eoi);

        // Allocate a free vector for interrupt handler usage.
        uint8_t allocvec(void);

        void setup(void);
        void reload(void);
    }
}

#endif
