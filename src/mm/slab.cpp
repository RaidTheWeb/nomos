#ifdef __x86_64__
#include <arch/limine/requests.hpp>
#include <arch/x86_64/pmm.hpp>
#endif
#include <lib/assert.hpp>
#include <lib/string.hpp>
#include <mm/slab.hpp>

namespace NMem {
    // Debug.
    bool nonzeroalloc = false;
    bool sanitisefreed = false;

    // Get index of slab associated with allocation size.
    static size_t getslabidx(size_t size) {
        for (size_t i = 0; i < numslabs; i++) {
            if (size <= slabsizes[i]) {
                return i;
            }
        }
        return __SIZE_MAX__;
    }

    SlabAllocator allocator = SlabAllocator();

    void SlabAllocator::setup(void) {
        // Initialise slabs.
        // No preallocation, as the memory usage *grows* with the need for memory.
        // With objects that need to be dynamically allocated very quickly, we shouldn't be using this, as there'll be slow down on growth.
        for (size_t i = 0; i < numslabs; i++) {
            this->slabs[i].freelist = NULL;
            this->slabs[i].blksize = slabsizes[i];
            this->slabs[i].blkpp = NArch::PAGESIZE / slabsizes[i];
        }

        void *test = NMem::allocator.alloc(32);
        assert(test != NULL, "Failed to allocate bytes during slab allocator setup.\n");
        NMem::allocator.free(test);
    }

    void *SlabAllocator::alloc(size_t size) {
        assert(size, "Zero size allocation.\n");

        // Align the size to 16 bytes (smallest slab size, and also multiplies to make every other size).
        // Needs to include enough space for the metadata.
        size_t aligned = (((size + sizeof(struct SubAllocator::metadata)) + (16 - 1)) & ~(16 - 1));

        // Get slab index.
        size_t idx = getslabidx(aligned);

        if (idx != __SIZE_MAX__) {
            // We found an allocator, allocate with it:

            SubAllocator *sub = &this->slabs[idx];
            if (sub->freelist == NULL) { // No free blocks in this slab! Allocate some more.
                void *ptr = ((void *)((uintptr_t)NArch::PMM::alloc(NArch::PAGESIZE) + NLimine::hhdmreq.response->offset)); // Allocate a single page (this works because all slabs are smaller than a page).
                if (ptr == NULL) {
                    return NULL;
                }

                // Try to prepare as many slab blocks in this page as we can.
                uintptr_t current = (uintptr_t)ptr;
                for (size_t i = 0; i < sub->blkpp - 1; i++) { // blkpp - 1 means we can work with the last header ourselves.
                    // Fill a new linked list out of these new blocks.
                    struct SubAllocator::header *header = (struct SubAllocator::header *)current;
                    header->next = (struct SubAllocator::header *)(current + sub->blksize);
                    current += sub->blksize;
                }

                struct SubAllocator::header *last = (struct SubAllocator::header *)current;
                last->next = NULL;

                // Dump our new blocks onto the freelist.
                sub->freelist = (struct SubAllocator::header *)ptr;
            }

            // Get latest free block.
            struct SubAllocator::header *block = sub->freelist; // If we had previously allocated more blocks, this would grab the head of that.
            sub->freelist = block->next; // Push freelist forwards.

            // Reinterpret block as metadata.
            struct SubAllocator::metadata *meta = (struct SubAllocator::metadata *)block;
            meta->size = aligned; // Set metadata.

            // Memory corruption meta.
            meta->startcanary = CANARY;
            meta->magic = ALLOCMAGIC;
            meta->endcanary = CANARY;

            if (nonzeroalloc) {
                NLib::memset((void *)((uintptr_t)block + sizeof(struct SubAllocator::metadata)), 0xaa, size);
            }

            // Return pointer to the memory *after* the metadata.
            return (void *)((uintptr_t)block + sizeof(struct SubAllocator::metadata));
        } else {
            // Unable to find slab (too big). Try to allocate this as a page.

            size_t needed = (aligned + NArch::PAGESIZE - 1) / NArch::PAGESIZE;
            void *ptr = ((void *)((uintptr_t)NArch::PMM::alloc(needed) + NLimine::hhdmreq.response->offset));
            if (ptr == NULL) {
                return NULL;
            }

            // Store metadata header at the start of page allocation.
            struct SubAllocator::metadata *meta = (struct SubAllocator::metadata *)ptr;
            meta->size = aligned; // Set metadata.

            // Memory corruption meta.
            meta->startcanary = CANARY;
            meta->magic = ALLOCMAGIC;
            meta->endcanary = CANARY;

            if (nonzeroalloc) {
                NLib::memset((void *)((uintptr_t)ptr + sizeof(struct SubAllocator::metadata)), 0xaa, size);
            }

            // Return pointer to data *after* metadata.
            return (void *)((uintptr_t)ptr + sizeof(struct SubAllocator::metadata));
        }
    }

    extern bool sanitisefreed;

    void SlabAllocator::free(void *ptr) {
        assert(ptr != NULL, "Invalid pointer to free.\n");

        // Get the header from the allocation meta data.
        struct SubAllocator::metadata *meta = (struct SubAllocator::metadata *)((uintptr_t)ptr - sizeof(struct SubAllocator::metadata));
        assert(meta->magic == ALLOCMAGIC, "Invalid free on potentially non-allocated block.\n");
        assert(meta->startcanary == CANARY && meta->endcanary == CANARY, "Slab memory corruption detected.\n");

        size_t size = meta->size;

        size_t idx = getslabidx(size);

        if (idx != __SIZE_MAX__ && size <= this->slabs[idx].blksize) { // Fits within a slab.
            // Release slabbed
            SubAllocator *sub = &this->slabs[idx];

            if (sanitisefreed) {
                // Overwrite freed memory with nonsense (sanitisation).
                NLib::memset(meta, 0xaa, size);
            }

            struct SubAllocator::header *block = (struct SubAllocator::header *)meta; // Reinterpret pointer as free block.
            block->next = sub->freelist; // This metadata'd allocation (indicating that it's allocated) is now free, so we need to point it somewhere.

            sub->freelist = block; // Add to freelist.
        } else { // Outside of slab, this means that it was allocated from pages directly.

            if (sanitisefreed) {
                // Overwrite freed memory with nonsense (sanitisation).
                NLib::memset(meta, 0xaa, size);
            }

            // Metadata start is the start of the page, therefore, we can just shove the location of the metadata into the PMM to free it.
            NArch::PMM::free(meta);
        }
    }

    void *SlabAllocator::calloc(size_t num, size_t size) {
        size_t total = num * size;
        void *ptr = this->alloc(total); // Allocate enough for the entire section.
        if (ptr != NULL) {
            NLib::memset(ptr, 0, total); // Calloc demands whole region be zeroed.
        }
        return ptr;
    }

    void *SlabAllocator::realloc(void *ptr, size_t newsize) {
        if (ptr == NULL) {
            return this->alloc(newsize); // If the pointer we pass in is NULL, we must allocate a new pointer.
        }

        if (!newsize) {
            this->free(ptr); // Zero size means free.
            return NULL;
        }

        struct SubAllocator::metadata *meta = (struct SubAllocator::metadata *)((uintptr_t)ptr - sizeof(struct SubAllocator::metadata));
        size_t old = meta->size; // Find old size, so we can figure out how much to copy.

        if (getslabidx(newsize) == getslabidx(old)) {
            return ptr;
        }

        void *newptr = this->alloc(newsize);
        if (newptr == NULL) {
            return NULL;
        }

        // Pick if we should be copying all the data from the old one, or up until the new size.
        size_t copysize = old < newsize ? old : newsize;
        NLib::memcpy(newptr, ptr, copysize); // Copy across the old data.

        // Free old pointer.
        free(ptr);
        return newptr;
    }
}
