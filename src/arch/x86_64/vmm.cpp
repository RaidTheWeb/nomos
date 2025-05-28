#include <arch/limine/requests.hpp>
#include <arch/x86_64/vmm.hpp>
#include <lib/assert.hpp>
#include <lib/string.hpp>
#include <util/kprint.hpp>

extern void *_text_start;
extern void *_text_end;
extern void *_data_start;
extern void *_data_end;
extern void *_rodata_start;
extern void *_rodata_end;

namespace NArch {


    static inline void *hhdmoff(void *ptr) {
        return (void *)((uintptr_t)ptr + NLimine::hhdmreq.response->offset);
    }

    static inline void *hhdmsub(void *ptr) {
        return (void *)((uintptr_t)ptr - NLimine::hhdmreq.response->offset);
    }

    struct VMM::pagetable *VMM::walk(uint64_t entry) {
        // Walk down into the next entry.

        if (entry == 0) {
            return NULL; // Nothing to work with.
        }

        // Adds HHDM offset to allow access in a higher half kernel.
        return (struct pagetable *)(hhdmoff((void *)(entry & ADDRMASK)));
    }

    uint64_t *VMM::_resolvepte(struct addrspace *space, uintptr_t virt) {

        // Decode virtual address:
        uint64_t pml4idx = (virt & PML4MASK) >> 39;
        uint64_t pdpidx = (virt & PDPMASK) >> 30;
        uint64_t pdidx = (virt & PDMASK) >> 21;
        uint64_t ptidx = (virt & PTMASK) >> 12;

        // Resolve virtual address:

        // Get reference to PML4 table.
        uint64_t pml4e = space->pml4->entries[pml4idx];
        if (!(pml4e & PRESENT)) {
            return NULL;
        }

        // Get reference to PDP table.
        struct pagetable *pdp = this->walk(pml4e);
        if (!pdp) {
            return NULL;
        }
        uint64_t pdpe = pdp->entries[pdpidx];
        if (!(pdpe & PRESENT)) {
            return NULL;
        }

        if (pdpe & HUGE) {
            return &pdp->entries[pdpidx];
        }

        // Get reference to PD table.
        struct pagetable *pd = this->walk(pdpe);
        if (!pd) {
            return NULL;
        }
        uint64_t pde = pd->entries[pdidx];
        if (!(pde & PRESENT)) {
            return NULL;
        }

        if (pde & HUGE) {
            return &pd->entries[pdidx];
        }

        // Get reference to PT table.
        struct pagetable *pt = this->walk(pde);
        if (!pt) {
            return NULL;
        }
        uint64_t pte = pt->entries[ptidx];
        if (!(pte & PRESENT)) {
            return NULL;
        }

        return &pt->entries[ptidx];
    }

    uintptr_t VMM::_virt2phys(struct addrspace *space, uintptr_t virt) {
        uint64_t *pte = this->_resolvepte(space, virt);
        if (!pte) {
            return 0;
        }

        // Construct physical address from address mask with offset.
        return (*pte & ADDRMASK) | (virt & OFFMASK);
    }

    bool VMM::_mappage(struct addrspace *space, uintptr_t virt, uintptr_t phys, uint64_t flags, bool user) {

        // Align down to base of the page the address exists in.
        // phys = ((phys) + ~(PAGESIZE - 1));
        // virt = ((virt) + ~(PAGESIZE - 1));
        phys = pagealign(phys);
        virt = pagealign(virt);

        // Decode virtual address:
        uint64_t pml4idx = (virt & PML4MASK) >> 39;
        uint64_t pdpidx = (virt & PDPMASK) >> 30;
        uint64_t pdidx = (virt & PDMASK) >> 21;
        uint64_t ptidx = (virt & PTMASK) >> 12;

        // Step through the same process for decoding, but to create non-existent entries.
        struct pagetable *pdp = this->walk(space->pml4->entries[pml4idx]);
        if (!pdp) { // If this entry hasn't already been allocated.
            pdp = (struct pagetable *)pmm.alloc(PAGESIZE);
            if (!pdp) {
                return false; // Failed to allocate page.
            }

            // Set pml4 entry to point to new page, has to be a non-higher half address.
            space->pml4->entries[pml4idx] = (uint64_t)pdp | WRITEABLE | PRESENT | (user ? USER : 0);
            pdp = (struct pagetable *)hhdmoff(pdp);
            NLib::memset(pdp, 0, PAGESIZE);
        }

        struct pagetable *pd = this->walk(pdp->entries[pdpidx]);
        if (!pd) { // If this entry hasn't already been allocated.
            pd = (struct pagetable *)pmm.alloc(PAGESIZE);
            if (!pd) {
                return false; // Failed to allocate page.
            }

            pdp->entries[pdpidx] = (uint64_t)pd | WRITEABLE | PRESENT | (user ? USER : 0);
            pd = (struct pagetable *)hhdmoff(pd);
            NLib::memset(pd, 0, PAGESIZE);
        }

        struct pagetable *pt = this->walk(pd->entries[pdidx]);
        if (!pt) { // If this entry hasn't already been allocated.
            pt = (struct pagetable *)pmm.alloc(PAGESIZE);
            if (!pt) {
                return false; // Failed to allocate page.
            }

            pd->entries[pdidx] = (uint64_t)pt | WRITEABLE | PRESENT | (user ? USER : 0);
            pt = (struct pagetable *)hhdmoff(pt);
            NLib::memset(pt, 0, PAGESIZE);
        }

        // At the end of all the indirection:
        pt->entries[ptidx] = (phys & ADDRMASK) | flags;

        return true;
    }

    void VMM::_unmappage(struct addrspace *space, uintptr_t virt) {
        uint64_t *pte = this->_resolvepte(space, virt);
        if (pte) {
            *pte = 0; // Blank page table entry, so that it now points NOWHERE.
            invlpg(virt); // Invalidate, so that the CPU will know that it's lost this page.
        }
    }

    bool VMM::_maprange(struct addrspace *space, uintptr_t virt, uintptr_t phys, uint64_t flags, size_t size) {
        size_t len = pagealign((virt) + size); // Align length to page.
        // Align down to base.
        phys = pagealign(phys);
        virt = pagealign(virt);
        size = len - virt; // Overwrite size of range to represent page alignmentment.

        for (size_t i = 0; i < size; i += PAGESIZE) {
            assertarg(this->_mappage(space, virt + i, phys + i, flags, false), "Failed to map page in range 0x%016llx->0x%016llx.\n", virt, virt + size);

            // this->_unmaprange(space, virt, i); // Recovery to unmap current progress.
            // return false;
        }
        return true;
    }

    void VMM::_unmaprange(struct addrspace *space, uintptr_t virt, size_t size) {
        size_t len = pagealign(pagealign(virt) + size); // Align length to page.
        virt = pagealign(virt);
        len = len - virt;

        for (size_t i = 0; i < size; i += PAGESIZE) {
            this->_unmappage(space, virt + i);
        }
    }

    void VMM::mapkernel(void *start, void *end, uint64_t flags) {
        size_t len = (uintptr_t)end - (uintptr_t)start;
        uintptr_t base = (uintptr_t)start;
        uintptr_t phyaddr = (uintptr_t)start - NLimine::eareq.response->virtual_base + NLimine::eareq.response->physical_base;

        this->maprange(&this->kspace, base, phyaddr, flags, len);
    }

    void VMM::setup(void) {

        this->kspace.pml4 = (struct pagetable *)pmm.alloc(PAGESIZE);
        assert(this->kspace.pml4 != NULL, "Failed to allocate top level page for kernel address space.\n");

        this->kspace.pml4 = (struct pagetable *)hhdmoff(this->kspace.pml4);
        NLib::memset(this->kspace.pml4, 0, PAGESIZE); // Blank page.

        for (size_t i = 256; i < 512; i++) {
            uint64_t *entry = (uint64_t *)pmm.alloc(PAGESIZE);
            assert(entry != NULL, "Failed to allocate intermediate entries.\n");
            NLib::memset(hhdmoff(entry), 0, PAGESIZE);
            this->kspace.pml4->entries[i] = (uint64_t)entry | PRESENT | WRITEABLE | USER;
        }

        // Map entire memory range:
        for (size_t i = 0; i < NLimine::mmreq.response->entry_count; i++) {
            struct limine_memmap_entry *entry = NLimine::mmreq.response->entries[i];
            // For every actually useful bit of memory.
            if (entry->type == LIMINE_MEMMAP_USABLE ||
                entry->type == LIMINE_MEMMAP_FRAMEBUFFER ||
                entry->type == LIMINE_MEMMAP_BOOTLOADER_RECLAIMABLE ||
                entry->type == LIMINE_MEMMAP_EXECUTABLE_AND_MODULES) {

                // Map entire region.
                this->maprange(&this->kspace, (uintptr_t)hhdmoff((void *)(entry->base)), entry->base, NOEXEC | WRITEABLE | PRESENT, entry->length);
            }
        }

        // Map executable section of kernel:
        mapkernel(&_text_start, &_text_end, 0 | PRESENT); // Read-only + Executable.
        mapkernel(&_data_start, &_data_end, 0 | WRITEABLE | NOEXEC | PRESENT); // R/W + Not executable.
        mapkernel(&_rodata_start, &_rodata_end, 0 | NOEXEC | PRESENT); // Read-only + Not executable.

        uint64_t efer = 0;
        // Read EFER CPU register from 0xC0000080.
        asm volatile("rdmsr" : "=A"(efer) : "c"(0xC0000080));

        efer |= (1 << 11); // Flip the Execute Disable Bit Enable bit, to allow NOEXEC pages.

        // Write EFER CPU register into 0xC0000080.
        asm volatile("wrmsr" : : "A"(efer), "c"(0xC0000080));

        uint64_t cr3;
        asm volatile("mov %%cr3, %0" : "=r"(cr3));
        asm volatile("mov %0, %%cr3" : : "r"((uint64_t)hhdmsub(&this->kspace.pml4->entries[0])));
        asm volatile("mfence" : : : "memory");
        NUtil::printf("[vmm]: Successfully swapped to kernel page table.\n");

        NUtil::printf("[vmm]: VMM initialised.\n");
    }
}
