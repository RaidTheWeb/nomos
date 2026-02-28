#include <arch/x86_64/cpu.hpp>
#include <arch/x86_64/gdt.hpp>
#include <lib/string.hpp>
#include <util/kprint.hpp>

namespace NArch {
    namespace GDT {
        static uint64_t gdtt[7];

        void setup(void) {


            // This is a basic 64-bit long mode GDT structure.
            // It initialises kernel and user segments, but it does NOT set up protected areas of memory for these segments.

            // NULL
            gdtt[0] = 0;

            // Kernel Code 64
            // Limit 0xffff
            // Base 0x00000000
            // Access 0x9b
            // Granularity 0xaf
            gdtt[1] = 0x00af9b000000ffff;

            // Kernel Data 64
            // Limit 0xffff
            // Base 0x00000000
            // Access 0x93
            // Granularity 0xaf
            gdtt[2] = 0x00af93000000ffff;

            // User Data 64
            // Limit 0xffff
            // Base 0x00000000
            // Access 0xf3
            // Granularity 0xaf
            gdtt[3] = 0x00aff3000000ffff;

            // User Code 64
            // Limit 0xffff
            // Base 0x00000000
            // Access 0xfb
            // Granularity 0xaf
            gdtt[4] = 0x00affb000000ffff;

            // IST 64 Low
            // Access 0x89
            // Granularity 0x20
            gdtt[5] = 0x0020890000000000;

            // IST 64 High
            gdtt[6] = 0x0000000000000000;
        }

        extern "C" void gdt_flush(void *);

        void reload(void) {
            NLib::memcpy(&CPU::get()->gdt[0], &gdtt[0], sizeof(gdtt));

            struct gdtr gdtr = {
                .size = sizeof(gdtt) - 1,
                .offset = (uint64_t)&CPU::get()->gdt[0]
            };

            uintptr_t istaddr = (uintptr_t)&CPU::get()->ist;

            // Compute IST address. Built from scratch on reload.
            CPU::get()->gdt[5] |= ((istaddr & 0xff000000) << 32) | ((istaddr & 0xff0000) << 16) | ((istaddr & 0xffff) << 16) | sizeof(struct CPU::ist);
            CPU::get()->gdt[6] = (istaddr >> 32) & 0xffffffff;

            gdt_flush(&gdtr);
        }
    }
}
