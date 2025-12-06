#ifdef __X86_64__
#include <arch/x86_64/pmm.hpp>
#endif

#include <lib/align.hpp>
#include <lib/string.hpp>
#include <mm/vmalloc.hpp>

namespace NMem {
    namespace VMalloc {
        void *alloc(size_t size, uint8_t flags) {
            if (size == 0) {
                return NULL;
            }

            if (size <= NArch::PAGESIZE) {
                // Page-sized allocations that fail wouldn't succeed in cobbling together pages anyway.
                void *alloc = NArch::PMM::alloc(size);
                return alloc ? (void *)NArch::hhdmoff((void *)alloc) : NULL;
            }

            // First, try to allocate a contiguous block of physical memory.
            // XXX: Consider KVMALLOC here later.
            //void *alloc = NArch::PMM::alloc(size);
            //if (alloc) {
                // Successful, return HHDM offset pointer, as PMM returns physical address.
                //return (void *)NArch::hhdmoff((void *)alloc);
            //}

            // Failed, no contiguous physical memory available.
            // Now we've got to cobble together enough pages.
            size_t pagesneeded = NLib::alignup(size, NArch::PAGESIZE) / NArch::PAGESIZE;
            void **pages = new void *[pagesneeded];
            if (!pages) {
                return NULL;
            }
            for (size_t i = 0; i < pagesneeded; i++) {
                pages[i] = NArch::PMM::alloc(NArch::PAGESIZE);
                if (!pages[i]) {
                    // Failed, free previous pages.
                    for (size_t j = 0; j < i; j++) {
                        NArch::PMM::free(pages[j], NArch::PAGESIZE);
                    }
                    delete[] pages;
                    return NULL;
                }
            }
            NLib::ScopeIRQSpinlock guard(&NArch::VMM::kspace.lock);

            // Now we've got all the pages, we need to map them into a contiguous virtual region.
            void *virt = NArch::VMM::kspace.vmaspace->alloc(pagesneeded * NArch::PAGESIZE, Virt::VIRT_RW);
            if (!virt) {
                // Failed, free pages.
                for (size_t i = 0; i < pagesneeded; i++) {
                    NArch::PMM::free(pages[i], NArch::PAGESIZE);
                }
                delete[] pages;
                return NULL;
            }

            for (size_t i = 0; i < pagesneeded; i++) {
                NArch::VMM::_mappage(&NArch::VMM::kspace, (uintptr_t)virt + (i * NArch::PAGESIZE), (uintptr_t)pages[i], NArch::VMM::WRITEABLE | NArch::VMM::PRESENT);
            }

            // Zero the allocated region.
            NLib::memset(virt, 0, pagesneeded * NArch::PAGESIZE);

            delete[] pages;
            return virt;
        }

        void free(void *ptr, size_t size) {
            if (!ptr || size == 0) {
                return;
            }

            size_t pagesneeded = NLib::alignup(size, NArch::PAGESIZE) / NArch::PAGESIZE;

            NLib::ScopeIRQSpinlock guard(&NArch::VMM::kspace.lock);

            // Freeing is easy as we just unmap and free each page individually.
            for (size_t i = 0; i < pagesneeded; i++) {
                uintptr_t virtaddr = (uintptr_t)ptr + (i * NArch::PAGESIZE);
                uintptr_t physaddr = NArch::VMM::virt2phys(&NArch::VMM::kspace, virtaddr);
                if (physaddr) {
                    NArch::VMM::_unmappage(&NArch::VMM::kspace, virtaddr);
                    NArch::PMM::free((void *)physaddr, NArch::PAGESIZE);
                }
            }

            NArch::VMM::kspace.vmaspace->free(ptr, (uintptr_t)ptr + pagesneeded * NArch::PAGESIZE);
        }

        static uint64_t vmatovmm(uint8_t vmaflags) {
            return 0 |
                ((vmaflags & NMem::Virt::VIRT_RW) ? NArch::VMM::WRITEABLE : 0) |
                ((vmaflags & NMem::Virt::VIRT_USER) ? NArch::VMM::USER : 0) |
                ((vmaflags & NMem::Virt::VIRT_NX) ? NArch::VMM::NOEXEC : 0);
        }

        void mapintospace(struct NArch::VMM::addrspace *space, uintptr_t virt, uintptr_t newvirt, size_t size, uint8_t vmaflags) {
            NLib::ScopeIRQSpinlock kguard(&NArch::VMM::kspace.lock);
            NLib::ScopeIRQSpinlock uguard(&space->lock);

            // Map a vmalloc region into a specific address space.
            size_t pagesneeded = NLib::alignup(size, NArch::PAGESIZE) / NArch::PAGESIZE;
            for (size_t i = 0; i < pagesneeded; i++) {
                uintptr_t vmallocvirt = virt + (i * NArch::PAGESIZE);
                uintptr_t physaddr = NArch::VMM::_virt2phys(&NArch::VMM::kspace, vmallocvirt);
                if (physaddr) {
                    NArch::VMM::_mappage(space, newvirt + (i * NArch::PAGESIZE), physaddr, vmatovmm(vmaflags) | NArch::VMM::PRESENT);
                }
            }
            // Map into VMA space as well.
            space->vmaspace->reserve(newvirt, newvirt + pagesneeded * NArch::PAGESIZE, vmaflags);
        }
    }
}