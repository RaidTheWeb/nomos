#include <arch/x86_64/gdt.hpp>
#include <util/kprint.hpp>

namespace NArch {
    void GDT::setup(void) {

        // This is a basic 64-bit long mode GDT structure.
        // It initialises kernel and user segments, but it does NOT set up protected areas of memory for these segments.

        // NULL
        this->gdt[0] = 0;

        // Kernel Code 64
        // Limit 0xffff
        // Base 0x00000000
        // Access 0xb9
        // Granularity 0xfa
        this->gdt[1] = 0x00af9b000000ffff;

        // Kernel Data 64
        // Limit 0xffff
        // Base 0x00000000
        // Access 0x39
        // Granularity 0xfa
        this->gdt[2] = 0x00af93000000ffff;

        // User Code 64
        // Limit 0xffff
        // Base 0x00000000
        // Access 0x3f
        // Granularity 0xfa
        this->gdt[3] = 0x00aff3000000ffff;

        // User Data 64
        // Limit 0xffff
        // Base 0x00000000
        // Access 0xbf
        // Granularity 0xfa
        this->gdt[4] = 0x00affb000000ffff;
    }

    extern "C" void gdt_flush(void *);

    void GDT::reload(void) {
        gdt_flush(&this->gdtr);
        NUtil::printf("[gdt]: GDT Reloaded.\n");
    }
}
