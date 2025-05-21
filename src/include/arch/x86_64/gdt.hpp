#ifndef _ARCH__X86_64__GDT_HPP
#define _ARCH__X86_64__GDT_HPP

#include <stdint.h>

namespace NArch {
    class GDT {
        private:
            struct gdtr {
                uint16_t size; // GDT size.
                uint64_t offset; // IDT offset.
            } __attribute__((packed));

            uint64_t gdt[5];
            struct gdtr gdtr;
        public:
            GDT(void) {
                this->gdtr = {
                    .size = sizeof(this->gdt) - 1,
                    .offset = (uint64_t)&this->gdt[0]
                };
            }

            void setup(void);
            void reload(void);
    };
}

#endif
