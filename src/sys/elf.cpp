#include <lib/align.hpp>
#include <sys/elf.hpp>
#include <util/kprint.hpp>

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

            // Validate ELF type.
            if (hdr->type != ET_EXECUTABLE && hdr->type != ET_DYNAMIC) {
                return false;
            }

            // Validate program header table.
            if (hdr->phcount == 0) {
                return false; // Must have at least one program header.
            }

            if (hdr->phsize < sizeof(struct pheader)) {
                return false; // Program header size too small.
            }

            return true;
        }

        void *preparestack(uintptr_t stacktop, struct header *elfhdr, uintptr_t virttop, struct execinfo *info) {

            char **argv = info->argv;
            char **envp = info->envp;
            const char *execpath = info->execpath;

            uintptr_t entry = info->entry;
            uintptr_t lnbase = info->lnbase;
            uintptr_t phdraddr = info->phdraddr;

            bool secure = info->secure;
            uint64_t *random = info->random;

            size_t argc = 0;
            size_t argvsize = 0;
            size_t envc = 0;
            size_t envpsize = 0;
            size_t execpathsize = 0;

            while (argv[argc]) { // Read until NULL is reached in argv.
                argvsize += NLib::strlen(argv[argc++]) + 1;
            }

            if (envp) {
                while (envp[envc]) { // Read until NULL is reached in envp.
                    envpsize += NLib::strlen(envp[envc++]) + 1;
                }
            }

            if (execpath) {
                execpathsize = NLib::strlen(execpath) + 1;
            }

            // XXX: Integrate with /dev/random entropy "pool" at some point.

            struct auxv auxv[] = {
                { auxvtype::PHDR, phdraddr },
                { auxvtype::PHENT, elfhdr->phsize },
                { auxvtype::PHNUM, elfhdr->phcount },
                { auxvtype::PAGESZ, NArch::PAGESIZE },
                { auxvtype::BASE, lnbase },
                { auxvtype::RAND, 0 }, // Placeholder, will be set to point to random data on stack.
                { auxvtype::EXECFN, 0 }, // Placeholder, will set below.
                { auxvtype::ENTRY, entry },
                { auxvtype::SECURE, secure ? 1 : 0 },
                { auxvtype::UID, info->uid },
                { auxvtype::EUID, info->euid },
                { auxvtype::GID, info->gid },
                { auxvtype::EGID, info->egid },
                { 0, 0 } // NULL entry terminator - MUST BE LAST
            };
            size_t auxvsize = sizeof(auxv);

            size_t totalsize = 0;
            totalsize += sizeof(uint64_t); // argc.
            totalsize += (argc + 1) * sizeof(uint64_t); // argv pointers + NULL.
            totalsize += (envc + 1) * sizeof(uint64_t); // envp pointers + NULL.

            totalsize += argvsize;
            totalsize += envpsize;
            totalsize += execpathsize;
            totalsize += auxvsize;
            totalsize += 16; // 16 bytes for AT_RANDOM data.

            totalsize = NLib::alignup(totalsize, 16); // 16-byte align.

            uintptr_t sp = stacktop - totalsize;
            uintptr_t stackptr = sp; // Stack pointer should start at the bottom of our data, so we can grow upwards towards the stack top. SP is ultimately returned, as it'll be the stack reference we give to user programs.

            *((uint64_t *)stackptr) = argc;
            stackptr += sizeof(uint64_t);

            uintptr_t argvptrs = stackptr; // Save location in stack where argv pointers exist.
            stackptr += (argc + 1) * sizeof(uint64_t);

            uint64_t envpptrs = stackptr; // Save location in stack where envp pointers exist.
            stackptr += (envc + 1) * sizeof(uint64_t);

            size_t auxvoff = stackptr;
            // Simply advance the stack pointer by the size of the auxiliary vector, we'll fill it in later.
            stackptr += auxvsize;

            // Place random data on stack for AT_RANDOM.
            uintptr_t randoff = stackptr;
            NLib::memcpy((void *)randoff, random, 16); // Copy 16 bytes of random data.
            stackptr += 16;

            for (size_t i = 0; i < argc; i++) {
                size_t len = NLib::strlen(argv[i]) + 1;
                NLib::memcpy((void *)stackptr, argv[i], len); // Copy argv element into stack.
                uintptr_t calc = virttop - (stacktop - stackptr); // Calculate our offset from the hhdm offset stack top, and subtract that from the virtual mapped stack top. Ultimately, we want the pointer to refer to the virtual memory version of this.
                ((uint64_t *)argvptrs)[i] = calc; // Point the associated argv pointer to the stack location of the element.
                stackptr += len;
            }
            ((uint64_t *)argvptrs)[argc] = NULL; // NULL terminator.

            // Place execpath on stack for AT_EXECFN.
            uintptr_t execpathoff = stackptr;
            if (execpath && execpathsize > 0) {
                NLib::memcpy((void *)stackptr, (void *)execpath, execpathsize);
                stackptr += execpathsize;
            }

            // Point AT_RAND to the random data on stack (virtual address).
            auxv[5].value = virttop - (stacktop - randoff);
            // Point AT_EXECFN to the resolved executable path on stack.
            if (execpath && execpathsize > 0) {
                auxv[6].value = virttop - (stacktop - execpathoff);
            } else {
                // Fallback to argv[0] if no execpath provided.
                auxv[6].value = ((uint64_t *)argvptrs)[0];
            }

            NLib::memcpy((void *)auxvoff, auxv, auxvsize); // Copy auxiliary vector.

            if (envp) {
                for (size_t i = 0; i < envc; i++) {
                    size_t len = NLib::strlen(envp[i]) + 1;
                    NLib::memcpy((void *)stackptr, envp[i], len); // Copy envp element into stack.

                    uintptr_t calc = virttop - (stacktop - stackptr); // Calculate our offset from the hhdm offset stack top, and subtract that from the virtual mapped stack top. Ultimately, we want the pointer to refer to the virtual memory version of this.
                    ((uint64_t *)envpptrs)[i] = calc; // Point the associated envp pointer to the stack location of the element.
                    stackptr += len;
                }
            }
            ((uint64_t *)envpptrs)[envc] = NULL; // NULL terminator. Needs to be here, regardless of whether we have any environment variables or not.

            if ((sp & 0xf) != 0) {
                return NULL; // Failed to align stack.
            }

            return (void *)(virttop - (stacktop - sp)); // Points to the beginning of the stack (argc).
        }

        char *getinterpreter(struct header *hdr, NFS::VFS::INode *node) {
            struct pheader *phdrs = new struct pheader[hdr->phcount];
            if (!phdrs) {
                return NULL;
            }

            if (node->read(phdrs, sizeof(struct pheader) * hdr->phcount, hdr->phoff, 0) != sizeof(struct pheader) * hdr->phcount) {
                delete[] phdrs;
                return NULL;
            }

            for (size_t i = 0; i < hdr->phcount; i++) {
                if (phdrs[i].type == PH_INTERPRETER) {
                    // Validate interpreter path size.
                    if (phdrs[i].fsize == 0 || phdrs[i].fsize > 4096) {
                        delete[] phdrs;
                        return NULL; // Invalid interpreter path size.
                    }

                    // Check for overflow in offset + size.
                    if (phdrs[i].doff > __UINT64_MAX__ - phdrs[i].fsize) {
                        delete[] phdrs;
                        return NULL;
                    }

                    char *interp = new char[phdrs[i].fsize + 1];
                    if (!interp) {
                        delete[] phdrs;
                        return NULL;
                    }

                    if (node->read(interp, phdrs[i].fsize, phdrs[i].doff, 0) != (ssize_t)phdrs[i].fsize) {
                        delete[] interp;
                        delete[] phdrs;
                        return NULL;
                    }

                    interp[phdrs[i].fsize] = 0; // Null terminate.

                    // Verify path is actually null-terminated within bounds (no embedded nulls before end).
                    size_t pathlen = NLib::strlen(interp);
                    if (pathlen == 0 || interp[0] != '/') {
                        delete[] interp;
                        delete[] phdrs;
                        return NULL; // Invalid interpreter path (must be absolute).
                    }

                    delete[] phdrs;
                    return interp;
                }
            }

            delete[] phdrs;
            return NULL;
        }

        bool loadfile(struct header *hdr, NFS::VFS::INode *node, struct NArch::VMM::addrspace *space, void **entry, uintptr_t base, uintptr_t *phdraddr) {
            struct pheader *phdrs = new struct pheader[hdr->phcount];
            if (!phdrs) {
                return false;
            }

            if (node->read(phdrs, sizeof(struct pheader) * hdr->phcount, hdr->phoff, 0) != sizeof(struct pheader) * hdr->phcount) {
                delete[] phdrs;
                return false;
            }

            // Track successfully loaded segments for cleanup on failure.
            struct loadedsegment {
                uintptr_t vaddr;
                uintptr_t phys;
                size_t size;
                size_t misalign;
            };
            loadedsegment *loaded = new loadedsegment[hdr->phcount];
            if (!loaded) {
                delete[] phdrs;
                return false;
            }
            size_t loadcount = 0;

            const uintptr_t USERSPACE_LIMIT = 0x0000800000000000ULL;

            for (size_t i = 0; i < hdr->phcount; i++) {
                if (!phdrs[i].type) {
                    continue;
                }

                if (phdrs[i].type == PH_LOAD) {
                    // Validate segment sizes.
                    if (phdrs[i].fsize > phdrs[i].msize) {
                        // File size cannot exceed memory size.
                        goto fail;
                    }

                    // Check for zero-size segments (skip them).
                    if (phdrs[i].msize == 0) {
                        continue;
                    }

                    // Check for overflow in base + vaddr.
                    if (phdrs[i].vaddr > USERSPACE_LIMIT - base) {
                        goto fail;
                    }

                    uintptr_t vaddr = base + phdrs[i].vaddr;

                    // Check for overflow in vaddr + msize.
                    if (phdrs[i].msize > USERSPACE_LIMIT - vaddr) {
                        goto fail;
                    }

                    // Ensure segment is within user address space.
                    if (vaddr + phdrs[i].msize > USERSPACE_LIMIT) {
                        goto fail;
                    }

                    // Check for overflow in doff + fsize.
                    if (phdrs[i].fsize > 0 && phdrs[i].doff > __UINT64_MAX__ - phdrs[i].fsize) {
                        goto fail;
                    }

                    size_t misalign = phdrs[i].vaddr % NArch::PAGESIZE;

                    // Check for overflow in msize + misalign.
                    if (phdrs[i].msize > __SIZE_MAX__ - misalign) {
                        goto fail;
                    }

                    void *phys = NArch::PMM::alloc(NLib::alignup(phdrs[i].msize + misalign, NArch::PAGESIZE)); // We should allocate enough to work around the misalignment, so we can place the data at the right location. Aside from the file data copy, this is the only place we need to account for misalignment.
                    if (!phys) {
                        goto fail;
                    }

                    // Reserve region in VMA space.
                    space->vmaspace->reserve(
                        NLib::aligndown(vaddr, NArch::PAGESIZE),
                        NLib::alignup(vaddr + phdrs[i].msize, NArch::PAGESIZE),
                        NMem::Virt::VIRT_USER |
                        (phdrs[i].flags & flag::EF_EXEC ? 0 : NMem::Virt::VIRT_NX) |
                        (phdrs[i].flags & flag::EF_WRITE ? NMem::Virt::VIRT_RW : 0)
                    );

                    if(!NArch::VMM::maprange(space, vaddr, (uintptr_t)phys,
                        NArch::VMM::PRESENT | NArch::VMM::USER |
                        (phdrs[i].flags & flag::EF_EXEC ? 0 : NArch::VMM::NOEXEC) |
                        (phdrs[i].flags & flag::EF_WRITE ? NArch::VMM::WRITEABLE : 0),
                        phdrs[i].msize
                    )) {
                        // Failed to map. Free physical memory.
                        NArch::PMM::free(phys, phdrs[i].msize + misalign);
                        goto fail;
                    }

                    // Read file data if there is any.
                    if (phdrs[i].fsize > 0) {
                        NUtil::printf("Loading segment %lu: vaddr=0x%lx, phys=0x%lx, fsize=0x%lx, msize=0x%lx, flags=0x%x\n", i, vaddr, (uintptr_t)phys, phdrs[i].fsize, phdrs[i].msize, phdrs[i].flags);
                        if (node->read((void *)((uintptr_t)NArch::hhdmoff(phys) + misalign), phdrs[i].fsize, phdrs[i].doff, 0) != (ssize_t)phdrs[i].fsize) {
                            // Failed. Unmap and free.
                            NArch::VMM::unmaprange(space, vaddr, phdrs[i].msize);
                            NArch::PMM::free(phys, phdrs[i].msize + misalign);
                            goto fail;
                        }
                        NUtil::printf("Loaded segment %lu: vaddr=0x%lx, phys=0x%lx, fsize=0x%lx, msize=0x%lx, flags=0x%x\n", i, vaddr, (uintptr_t)phys, phdrs[i].fsize, phdrs[i].msize, phdrs[i].flags);
                    }

                    if (phdrs[i].msize > phdrs[i].fsize) {
                        // Fill remaining region of allocation with zeroes (BSS).
                        NLib::memset((void *)((uintptr_t)NArch::hhdmoff(phys) + phdrs[i].fsize + misalign), 0, (phdrs[i].msize - phdrs[i].fsize));
                    }

                    // Track this successfully loaded segment.
                    loaded[loadcount].vaddr = vaddr;
                    loaded[loadcount].phys = (uintptr_t)phys;
                    loaded[loadcount].size = phdrs[i].msize;
                    loaded[loadcount].misalign = misalign;
                    loadcount++;
                } else if (phdrs[i].type == PH_PHDR) {
                    if (phdraddr) {
                        *phdraddr = base + phdrs[i].vaddr;
                    }
                }
            }

            // Validate entry point is within user address space.
            if (hdr->entryoff > USERSPACE_LIMIT - base) {
                goto fail;
            }

            if (phdraddr && *phdraddr == 0) { // No PHDR? No Problem.
                for (size_t i = 0; i < hdr->phcount; i++) {
                    if (phdrs[i].type == PH_LOAD && hdr->phoff >= phdrs[i].doff && hdr->phoff < phdrs[i].doff + phdrs[i].fsize) {
                        // Sort of unreliable way to determine PHDR location, but better than nothing.
                        *phdraddr = base + phdrs[i].vaddr + (hdr->phoff - phdrs[i].doff);
                        break;
                    }
                }
            }

            *entry = (void *)(base + hdr->entryoff);
            delete[] loaded;
            delete[] phdrs;
            return true;

        fail:
            // Clean up all successfully loaded segments.
            for (size_t j = 0; j < loadcount; j++) {
                NArch::VMM::unmaprange(space, loaded[j].vaddr, loaded[j].size);
                NArch::PMM::free((void *)loaded[j].phys, loaded[j].size + loaded[j].misalign);
            }
            delete[] loaded;
            delete[] phdrs;
            return false;
        }
    }
}
