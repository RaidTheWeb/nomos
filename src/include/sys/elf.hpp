#ifndef _SYS__ELF_HPP
#define _SYS__ELF_HPP

#ifdef __x86_64__
#include <arch/x86_64/vmm.hpp>
#endif
#include <fs/vfs.hpp>

#include <stddef.h>
#include <stdint.h>

namespace NSys {
    namespace ELF {

        enum type {
            ET_RELOCATABLE     = 1,
            ET_EXECUTABLE       = 2,
            ET_DYNAMIC          = 3,
            ET_CORE             = 4
        };

        enum flag {
            EF_EXEC            = (1 << 0),
            EF_WRITE           = (1 << 1),
            EF_READ            = (1 << 2)
        };

        __attribute__((used))
        static const uint32_t MAGIC = 0x464c457f;

        struct header {
            uint32_t magic; // 0x464c457f. FLE(7F)
            uint8_t bits; // 1 - 32-bit, 2 - 64-bit.
            uint8_t endianness; // 1 - Little Endian, 2 - Big Endian.
            uint8_t version; // Header version.
            uint8_t abi; // 0 - System-V.
            char rsvd0[8];
            uint16_t type; // 1 - Relocatable, 2 - Executable, 3 - Shared, 4 - Core.
            uint16_t isa; // Instruction Set. 0x00 - Generic, 0x02 - SPARC, 0x03 - x86, 0x08 - MIPS, 0x14 - PowerPC, 0x28 - ARM, 0x2a - SuperH, 0x32 - IA-64, 0x3e - x86-64, 0xb7 - AArch64, 0xf3 - RISC-V.
            uint32_t elfver;
            uint64_t entryoff; // Program entry offset.
            uint64_t phoff; // Program header table offset.
            uint64_t shoff; // Section header table offset.
            uint32_t flags;
            uint16_t hsize; // ELF header size.
            uint16_t phsize; // Program header size.
            uint16_t phcount; // Program header size.
            uint16_t shsize; // Section header size.
            uint16_t shcount; // Number of section headers.
            uint16_t shnames; // Index in section header table that contains the names of each section.
        } __attribute__((packed));

        enum segtype {
            PH_LOAD         = 1,
            PH_DYNAMIC      = 2,
            PH_INTERPRETER  = 3,
            PH_NOTE         = 4,
            PH_SHLIB        = 5,
            PH_PHDR         = 6
        };

        struct pheader { // 64-bit program header.
            uint32_t type;
            uint32_t flags;
            uint64_t doff; // Data offset.
            uint64_t vaddr; // Desired virtual address placement of data.
            char rsvd0[8];
            uint64_t fsize; // Segment file size.
            uint64_t msize; // Segment memory size.
            uint64_t align; // Required segment data alignment.
        } __attribute__((packed));

        enum auxvtype {
            PHDR        = 3,
            PHENT       = 4,
            PHNUM       = 5,
            PAGESZ      = 6,
            BASE        = 7,
            ENTRY       = 9,
            UID         = 11,
            EUID        = 12,
            GID         = 13,
            EGID        = 14,
            SECURE      = 23,
            RAND        = 25,
            EXECFN      = 31
        };

        struct auxv {
            uint64_t type;
            uint64_t value;
        } __attribute__((packed));

        bool verifyheader(struct header *hdr);


        struct execinfo {
            uint64_t random[2]; // Random data for AT_RANDOM.
            bool secure; // Is this a secure exec?

            int uid; // Real UID.
            int euid; // Effective UID.
            int gid; // Real GID.
            int egid; // Effective GID.

            char **argv; // Argument vector.
            char **envp; // Environment pointer.
            const char *execpath; // Resolved absolute path to executable.

            uintptr_t entry; // Program entry point.
            uintptr_t lnbase; // Load base for interpreter.
            uintptr_t phdraddr; // Program header address.
        };

        // Prepare userspace stack for ELF executable. stacktop is the HHDM mapped top, while virttop is the virtual mapped top.
        void *preparestack(uintptr_t stacktop, struct header *elfhdr, uintptr_t virttop, struct execinfo *info);
        char *getinterpreter(struct header *hdr, NFS::VFS::INode *node);
        bool loadfile(struct header *hdr, NFS::VFS::INode *node, struct NArch::VMM::addrspace *space, void **entry, uintptr_t base, uintptr_t *phdraddr);
    }
}

#endif
