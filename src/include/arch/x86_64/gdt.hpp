#ifndef _ARCH__X86_64__GDT_HPP
#define _ARCH__X86_64__GDT_HPP

#include <stdint.h>

namespace NArch {
    namespace GDT {
        struct gdtr {
            uint16_t size; // GDT size.
            uint64_t offset; // IDT offset.
        } __attribute__((packed));

        void setup(void);
        void reload(void);
    }
}

#endif
