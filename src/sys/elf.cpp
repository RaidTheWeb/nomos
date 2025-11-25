#include <lib/align.hpp>
#include <sys/elf.hpp>

namespace NSys {
    namespace ELF {

        bool verifyheader(struct header *hdr) {
#ifdef __x86_64__
            const uint8_t endianness = 1;
            const uint8_t bits = 2;
            const uint8_t isa = 0x3e;
#endif

            if (hdr->magic != MAGIC) {
                return false;
            }

            if (hdr->bits != bits) {
                return false;
            }

            if (hdr->endianness != endianness) {
                return false;
            }

            if (hdr->isa != isa) {
                return false;
            }

            return true;
        }

        void *preparestack(uintptr_t stacktop, char **argv, char **envp, struct header *elfhdr, uintptr_t virttop) {
            size_t argc = 0;
            size_t argvsize = 0;
            size_t envc = 0;
            size_t envpsize = 0;

            while (argv[argc]) { // Read until NULL is reached in argv.
                argvsize += NLib::strlen(argv[argc++]) + 1;
            }

            if (envp) {
                while (envp[envc]) { // Read until NULL is reached in envp.
                    envpsize += NLib::strlen(envp[envc++]) + 1;
                }
            }

            struct auxv auxv[] = {
                { 0, 0 }, // NULL entry terminator.
                { auxvtype::PHDR, 0 },
                { auxvtype::PHENT, elfhdr->phsize },
                { auxvtype::PHNUM, elfhdr->phcount },
                { auxvtype::PAGESZ, NArch::PAGESIZE },
                { auxvtype::ENTRY, elfhdr->entryoff },
                { auxvtype::RAND, stacktop - 16 }
            };
            size_t auxvsize = sizeof(auxv);

            size_t totalsize = 0;
            totalsize += sizeof(uint64_t); // argc.
            totalsize += (argc + 1) * sizeof(uint64_t); // argv pointers + NULL.
            totalsize += (envc + 1) * sizeof(uint64_t); // envp pointers + NULL.

            totalsize += argvsize;
            totalsize += envpsize;
            totalsize += auxvsize;

            totalsize = NLib::alignup(totalsize, 16); // 16-byte align.

            uintptr_t sp = stacktop - totalsize;
            uintptr_t stackptr = sp; // Stack pointer should start at the bottom of our data, so we can grow upwards towards the stack top. SP is ultimately returned, as it'll be the stack reference we give to user programs.

            *((uint64_t *)stackptr) = argc;
            stackptr += sizeof(uint64_t);

            uintptr_t argvptrs = stackptr; // Save location in stack where argv pointers exist.
            stackptr += (argc + 1) * sizeof(uint64_t);

            uint64_t envpptrs = stackptr; // Save location in stack where envp pointers exist.
            stackptr += (envc + 1) * sizeof(uint64_t);

            NLib::memcpy((void *)stackptr, auxv, auxvsize); // Copy auxiliary vector.
            stackptr += auxvsize;

            for (size_t i = 0; i < argc; i++) {
                size_t len = NLib::strlen(argv[i]) + 1;
                NLib::memcpy((void *)stackptr, argv[i], len); // Copy argv element into stack.
                stackptr += len;
                uintptr_t calc = virttop - (stacktop - stackptr); // Calculate our offset from the hhdm offset stack top, and subtract that from the virtual mapped stack top. Ultimately, we want the pointer to refer to the virtual memory version of this.
                ((uint64_t *)argvptrs)[i] = calc; // Point the associated argv pointer to the stack location of the element.
            }
            ((uint64_t *)argvptrs)[argc] = NULL; // NULL terminator.

            if (envp) {
                for (size_t i = 0; i < envc; i++) {
                    size_t len = NLib::strlen(envp[i]) + 1;
                    NLib::memcpy((void *)stackptr, envp[i], len); // Copy envp element into stack.

                    stackptr += len;
                    uintptr_t calc = virttop - (stacktop - stackptr); // Calculate our offset from the hhdm offset stack top, and subtract that from the virtual mapped stack top. Ultimately, we want the pointer to refer to the virtual memory version of this.
                    ((uint64_t *)envpptrs)[i] = calc; // Point the associated envp pointer to the stack location of the element.
                }
            }
            ((uint64_t *)envpptrs)[envc] = NULL; // NULL terminator. Needs to be here, regardless of whether we have any environment variables or not.

            if ((sp & 0xf) != 0) {
                return NULL; // Failed to align stack.
            }

            return (void *)(virttop - (stacktop - sp)); // Points to the beginning of the stack (argc).
        }

        bool loadfile(struct header *hdr, NFS::VFS::INode *node, struct NArch::VMM::addrspace *space, void **entry) {
            struct pheader *phdrs = new struct pheader[hdr->phcount];
            if (!phdrs) {
                return false;
            }

            if (node->read(phdrs, sizeof(struct pheader) * hdr->phcount, hdr->phoff, 0) != sizeof(struct pheader) * hdr->phcount) {
                return false;
            }

            for (size_t i = 0; i < hdr->phcount; i++) {
                if (!phdrs[i].type) {
                    continue;
                }

                if (phdrs[i].type == PH_LOAD) {
                    size_t misalign = phdrs[i].vaddr % NArch::PAGESIZE;

                    void *phys = NArch::PMM::alloc(phdrs[i].msize + misalign); // We should allocate enough to work around the misalignment, so we can place the data at the right location. Aside from the file data copy, this is the only place we need to account for misalignment.
                    if (!phys) {
                        // Failed. Free everything we've currently acquired.
                        delete[] phdrs;
                        return false;
                    }

                    // Reserve region in VMA space.
                    space->vmaspace->reserve(
                        NLib::aligndown(phdrs[i].vaddr, NArch::PAGESIZE),
                        NLib::alignup(phdrs[i].vaddr + phdrs[i].msize, NArch::PAGESIZE),
                        NMem::Virt::VIRT_USER |
                        (phdrs[i].flags & flag::ELF_EXEC ? 0 : NMem::Virt::VIRT_NX) |
                        (phdrs[i].flags & flag::ELF_WRITE ? NMem::Virt::VIRT_RW : 0)
                    );

                    if(!NArch::VMM::maprange(space, phdrs[i].vaddr, (uintptr_t)phys,
                        NArch::VMM::PRESENT | NArch::VMM::USER |
                        (phdrs[i].flags & flag::ELF_EXEC ? 0 : NArch::VMM::NOEXEC) |
                        (phdrs[i].flags & flag::ELF_WRITE ? NArch::VMM::WRITEABLE : 0),
                        phdrs[i].msize
                    )) {
                        // Failed. Free everything we've currently acquired.
                        delete[] phdrs;
                        NArch::PMM::free(phys, phdrs[i].msize + misalign);
                        return false;
                    }

                    if (node->read((void *)((uintptr_t)NArch::hhdmoff(phys) + misalign), phdrs[i].fsize, phdrs[i].doff, 0) != (ssize_t)phdrs[i].fsize) {
                        // Failed. Free everything we've currently acquired.
                        NArch::VMM::unmaprange(space, phdrs[i].vaddr, phdrs[i].msize); // Unmap range in space.
                        delete[] phdrs;
                        NArch::PMM::free(phys, phdrs[i].msize + misalign);
                        return false;
                    }

                    if (phdrs[i].msize > phdrs[i].fsize) {
                        // Fill remaining region of allocation with zeroes.
                        NLib::memset((void *)((uintptr_t)NArch::hhdmoff(phys) + phdrs[i].fsize + misalign), 0, (phdrs[i].msize - phdrs[i].fsize));
                    }
                }
            }

            *entry = (void *)hdr->entryoff;
            return true;
        }
    }
}
