#ifndef _ARCH__X86_64__INTERRUPTS_HPP
#define _ARCH__X86_64__INTERRUPTS_HPP

#include <stdint.h>

namespace NArch {
    class InterruptTable {
        private:
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

            struct idtentry idt[256];

            struct idtr idtr;
        public:
            InterruptTable(void) {
                this->idtr = {
                    .size = sizeof(this->idt) - 1,
                    .offset = (uint64_t)&this->idt[0]
                };
            }

            void regint(uint8_t vector, void *isr, uint8_t flags);
            void setup(void);
            void reload(void);
    };
}

#endif
