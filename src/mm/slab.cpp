#include <arch/x86_64/pmm.hpp>
#include <mm/slab.hpp>
#include <lib/assert.hpp>

namespace NMem {
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
            NUtil::printf("initialise slab allocator for size %lu with %lu blocks per page.\n", slabsizes[i], this->slabs[i].blkpp);
        }

    }

    void *SlabAllocator::alloc(size_t size) {
        assert(size, "Zero size allocation.\n");

        // Align the size to 16 bytes (smallest slab size, and also multiplies to make every other size).
        size_t aligned = (((size) + (16 - 1)) & ~(16 - 1));

        // Get slab index.
        size_t idx = getslabidx(aligned);

        if (idx != __SIZE_MAX__) {
            NUtil::printf("valid allocation on slab size %lu.\n", slabsizes[idx]);
            // We found an allocator, allocate with it:

            SubAllocator *sub = &this->slabs[idx];
            if (sub->freelist == NULL) { // No free blocks in this slab! Allocate some more.
                NUtil::printf("[slab]: Grow.\n");
                void *ptr = NArch::pmm.alloc(1); // Allocate a single page (this works because all slabs are smaller than a page).
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
                NUtil::printf("[slab]: Grew slab size of %lu by %lu.\n", sub->blksize, sub->blkpp);

                // Dump our new blocks onto the freelist.
                sub->freelist = (struct SubAllocator::header *)ptr;
            }

            // Get latest free block.
            struct SubAllocator::header *block = sub->freelist; // If we had previously allocated more blocks, this would grab the head of that.
            sub->freelist = block->next; // Push freelist forwards.

            // Reinterpret block as metadata.
            struct SubAllocator::metadata *meta = (struct SubAllocator::metadata *)block;
            meta->size = aligned; // Set metadata.

            NUtil::printf("[slab]: Returning allocation of 0x%016lx+0x0%016lx->0x%016lx.\n", meta, sizeof(struct SubAllocator::metadata), (uintptr_t)meta + sizeof(struct SubAllocator::metadata));

            // Return pointer to the memory *after* the metadata.
            return (void *)((uintptr_t)block + sizeof(struct SubAllocator::metadata));
        } else {
            NUtil::printf("[slab]: Too big, page allocate.\n");
            // Unable to find slab (too big). Try to allocate this as a page.

            size_t needed = (aligned + NArch::PAGESIZE - 1) / NArch::PAGESIZE;
            void *ptr = NArch::pmm.alloc(needed);
            if (ptr == NULL) {
                return NULL;
            }

            // Store metadata header at the start of page allocation.
            struct SubAllocator::metadata *meta = (struct SubAllocator::metadata *)ptr;
            meta->size = aligned; // Set metadata.

            // Return pointer to data *after* metadata.
            return (void *)((uintptr_t)ptr + sizeof(struct SubAllocator::metadata));
        }
    }

    void SlabAllocator::free(void *ptr) {
        assert(ptr != NULL, "Invalid pointer to free.\n");

        // Get the header from the allocation meta data.
        struct SubAllocator::metadata *meta = (struct SubAllocator::metadata *)((uintptr_t)ptr - sizeof(struct SubAllocator::metadata));

        size_t size = meta->size;

        size_t idx = getslabidx(size);

        if (idx != __SIZE_MAX__ && size <= this->slabs[idx].blksize) { // Fits within a slab.
            NUtil::printf("[slab]: Freeing on slab.\n");
            // Release slabbed
            SubAllocator *sub = &this->slabs[idx];
            struct SubAllocator::header *block = (struct SubAllocator::header *)meta; // Reinterpret pointer as free block.
            block->next = sub->freelist; // This metadata'd allocation (indicating that it's allocated) is now free, so we need to point it somewhere.

            sub->freelist = block; // Add to freelist.
        } else { // Outside of slab, this means that it was allocated from pages directly.
            NUtil::printf("[slab]: Outside of slab, page free.\n");
            // Metadata start is the start of the page, therefore, we can just shove the location of the metadata into the PMM to free it.
            NArch::pmm.free(meta);
        }
    }
}
