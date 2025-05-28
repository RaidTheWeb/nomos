#ifndef _ARCH__X86_64__VMM_HPP
#define _ARCH__X86_64__VMM_HPP

#include <arch/x86_64/pmm.hpp>
#include <lib/sync.hpp>
#include <stddef.h>
#include <stdint.h>

namespace NArch {

    // Invalid a single page, based on virtual address.
    static inline void invlpg(uintptr_t addr) {
        asm volatile("invlpg (%0)" : : "r"(addr) : "memory");
    }

    // Reload CR3 to invalidate entire TLB.
    static inline void flushtlb(void) {
        uint64_t cr3;
        asm volatile("mov %%cr3, %0" : "=r"(cr3));
        asm volatile("mov %0, %%cr3" : : "r"(cr3));
        asm volatile("mfence" : : : "memory");
    }

    static inline uintptr_t pagealign(uintptr_t addr) {
        return (((addr) + PAGESIZE - 1) & ~(PAGESIZE - 1));
    }

    static inline uintptr_t pagealigndown(uintptr_t addr) {
        return ((addr) + ~(PAGESIZE - 1));
    }

    // Invalidate an entire range of pages.
    // XXX: Slow! With big ranges, we should just be flushing the entire TLB.
    static inline void invlrange(uintptr_t addr, size_t size) {
        size_t len = addr + size;
        for (; addr < len; addr += PAGESIZE) {
            invlpg(addr);
        }
    }


    // Paging
    //
    // PML4 -> PDP -> PD -> PT
    //
    // 0xffff80007ffe0000
    // Translated into the following:
    //
    // 47         39        30       21       12       0
    // +----------+---------+--------+--------+--------+
    // | PML4 IDX | PDP IDX | PD IDX | PT IDX | Offset |
    // +----------+---------+--------+--------+--------+
    //
    // From 47 to 64 is ignored for 4-level paging.
    //
    // Everything other than the offset is just for indirectly referencing the bottom level PT page. Each level of indirection is used, ultimately, to find the physical address of the mapped page.
    //
    // CR3 points to the table of PML4 entries, which the PML4 IDX indexes.
    // PML4 entries point the PDP table, from which the PDP IDX will index an entry.
    // The PDP entries point to the PD table, from which the PD IDX will index an entry.
    // The PD entries point to the PT table, from which the PT IDX will index an entry.
    // The PT entry points to the "frame" of the physical address, which is combined with the offset to fully decode the virtual address.
    //
    //

    class VMM {
        private:
            // Top level mask only up to the 47th bit.
            // Each mask collapses down to the next section of the address.
            static const uint64_t PML4MASK = 0b111111111000000000000000000000000000000000000000;
            static const uint64_t PDPMASK           = 0b111111111000000000000000000000000000000;
            static const uint64_t PDMASK                     = 0b111111111000000000000000000000;
            static const uint64_t PTMASK                              = 0b111111111000000000000;
            static const uint64_t OFFMASK                                      = 0b111111111111;
            static const uint64_t OFFMASK2MB = 0x1FFFFF;
            static const uint64_t OFFMASK1GB = 0x3FFFFFFF;

            // Page table entry bits:
            static const uint64_t PRESENT = (1 << 0); // Is the page currently in physical memory? Triggers pagefault when accessed if not set -> Useful for handling swapped out memory!
            static const uint64_t WRITEABLE = (1 << 1); // Read-only if not set, read if set.
            static const uint64_t USER = (1 << 2); // Set if accessible to userspace.
            static const uint64_t WRITETHROUGH = (1 << 3); // Set for writethrough caching, otherwise it's writeback.
            static const uint64_t DISABLECACHE = (1 << 4); // Disable cache outright.
            static const uint64_t ACCESSED = (1 << 5); // RSVD
            static const uint64_t DIRTY = (1 << 6); // RSVD
            static const uint64_t HUGE = (1 << 7); // 4MiB page enable.
            static const uint64_t GLOBAL = (1 << 8); // Does not invalidate TLB entry for this page when changing CR3 register (changing page tables).
            static const uint64_t NOEXEC = (1ul << 63); // Disables execution on this section of memory.
            static const uint64_t ADDRMASK = 0x000FFFFFFFFFF000; // Standard bitmask for extracting the physical address from an underlying page table entry.
            static const uint64_t ADDRMASK2MB = 0x000FFFFFFFE00000; // Bitmask for addresses from 2MB page table entries.
            static const uint64_t ADDRMASK1GB = 0x000FFFFFC0000000; // Bitmask for addresses from 1GB page table entries.

        public:
            struct pagetable {
                uint64_t entries[PAGESIZE / sizeof(uint64_t)]; // Define access to every entry within a page table (512 entries for 4096 byte pages).
            } __attribute__((aligned(PAGESIZE))); // This will be dynamically allocated on a page-by-page basis with the PMM.

            struct pagetable *walk(uint64_t entry);

            struct addrspace {
                struct pagetable *pml4; // Top level page table for this address space.
                MCSSpinlock lock; // Queued spinlocking, to prevent race conditions on page table modifications. XXX: Fast enough to consider normal spinlocking?
            };

        private:;;
            // (Unlocked) Resolve physical address of a virtual address.
            uintptr_t _virt2phys(struct addrspace *space, uintptr_t virt);

            // (Unlocked) Resolve page table entry of a virtual address.
            uint64_t *_resolvepte(struct addrspace *space, uintptr_t virt);

            // (Unlocked) Map a virtual address with an entry.
            bool _mappage(struct addrspace *space, uintptr_t virt, uintptr_t phys, uint64_t flags, bool user);

            bool _remappage(struct addrspace *space, uintptr_t virt, uintptr_t newphys, uint64_t flags);

            // (Unlocked) Unmap a virtual address.
            void _unmappage(struct addrspace *space, uintptr_t virt);

            bool _maprange(struct addrspace *space, uintptr_t virt, uintptr_t phys, uint64_t flags, size_t size);

            bool _remaprange(struct addrspace *space, uintptr_t virt, uintptr_t newphys, uint64_t flags, size_t size);

            void _unmaprange(struct addrspace *space, uintptr_t virt, size_t size);


        public:

            // Kernel space page table. This is essentially just a page table for the entire useful address space, including an identity map for the lower 4GB of the address space.
            // This is *not* passed to userspace.
            struct addrspace kspace;

            // Resolve physical address of virtual address.
            uintptr_t virt2phys(struct addrspace *space, uintptr_t virt) {
                NLib::ScopeMCSSpinlock guard(&space->lock);
                return this->_virt2phys(space, virt);
            }

            // Resolve page table entry of a virtual address.
            uint64_t *resolvepte(struct addrspace *space, uintptr_t virt) {
                NLib::ScopeMCSSpinlock guard(&space->lock);
                return this->_resolvepte(space, virt);
            }

            // Map a virtual address with an entry.
            bool mappage(struct addrspace *space, uintptr_t virt, uintptr_t phys, uint64_t flags, bool user) {
                NLib::ScopeMCSSpinlock guard(&space->lock);
                return this->_mappage(space, virt, phys, flags, user);
            }

            bool remappage(struct addrspace *space, uintptr_t virt, uintptr_t newphys, uint64_t flags) {
                NLib::ScopeMCSSpinlock guard(&space->lock);
                return this->_remappage(space, virt, newphys, flags);
            }

            // Unmap a virtual address.
            void unmappage(struct addrspace *space, uintptr_t virt) {
                NLib::ScopeMCSSpinlock guard(&space->lock);
                this->_unmappage(space, virt);
            }

            bool maprange(struct addrspace *space, uintptr_t virt, uintptr_t phys, uint64_t flags, size_t size) {
                NLib::ScopeMCSSpinlock guard(&space->lock);
                return this->_maprange(space, virt, phys, flags, size);
            }

            bool remaprange(struct addrspace *space, uintptr_t virt, uintptr_t newphys, uint64_t flags, size_t size) {
                NLib::ScopeMCSSpinlock guard(&space->lock);
                return this->_remaprange(space, virt, newphys, flags, size);
            }

            void unmaprange(struct addrspace *space, uintptr_t virt, size_t size) {
                NLib::ScopeMCSSpinlock guard(&space->lock);
                this->_unmaprange(space, virt, size);
            }

            // Maps kernel regions according to start and end of individual sections.
            void mapkernel(void *start, void *end, uint64_t flags);
            void setup(void);
    };
}

#endif
