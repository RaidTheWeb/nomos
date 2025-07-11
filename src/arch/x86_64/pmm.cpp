#include <arch/limine/requests.hpp>
#include <arch/x86_64/pmm.hpp>
#include <arch/x86_64/vmm.hpp>
#include <lib/align.hpp>
#include <lib/assert.hpp>
#include <lib/sync.hpp>
#include <util/kprint.hpp>

namespace NArch {
    namespace PMM {

        struct zone zone;
        struct bzone bitmapzones[16]; // Allow for 16 disjointed zones at max. The bitmap allocator is given all the smaller regions, as they're usually also above the traditional block size of the buddy allocator.
        size_t numbitmapzones = 0;
        Spinlock alloclock;

        size_t alloci = 0;

        static const char *maptype[] = {
            "USABLE",
            "RESERVED",
            "RECLAIMABLE",
            "NVS",
            "BADMEM",
            "RECLAIMABLE",
            "MODULES",
            "FRAMEBUFFER"
        };

        void setup(void) {

            size_t usable = 0;

            for (size_t i = 0; i < NLimine::mmreq.response->entry_count; i++) {
                struct limine_memmap_entry *entry = NLimine::mmreq.response->entries[i];

                NUtil::printf("[arch/x86_64/pmm]: Memory map entry: %p->%p, length %lu, type %s.\n", entry->base, entry->base + entry->length, entry->length, maptype[entry->type]);

                if (entry->type == LIMINE_MEMMAP_USABLE) {
                    usable += entry->length;
                }
            }
            NUtil::printf("[arch/x86_64/pmm]: Total usable memory is %lu MiB.\n", usable / 1024 / 1024);

            size_t bitmaptarget = usable * 30 / 100; // Bitmap allocator is given a 30% split target of total memory.
            size_t buddytarget = usable * 70 / 100; // Buddy allocator gets all the rest.
            NUtil::printf("[arch/x86_64/pmm]: Buddy/Bitmap split %lu MiB / %lu MiB.\n", buddytarget / 1024 / 1024, bitmaptarget / 1024 / 1024);

            size_t bitmapalloc = 0;
            size_t buddyalloc = 0;

            for (size_t i = 0; i < NLimine::mmreq.response->entry_count; i++) {
                struct limine_memmap_entry *entry = NLimine::mmreq.response->entries[i];

                if (entry->type == LIMINE_MEMMAP_USABLE) {
                    uintptr_t regionbase = NLib::alignup(entry->base, PAGESIZE);
                    uintptr_t regionend = NLib::alignup(entry->base + entry->length, PAGESIZE);
                    if (regionend <= regionbase) {
                        continue;
                    }

                    size_t regionsize = regionend - regionbase;

                    if (buddyalloc < buddytarget) { // If we haven't reached our target
                        size_t allocate = regionsize;
                        if (buddyalloc + allocate > buddytarget) {
                            allocate = buddytarget - buddyalloc;
                        }

                        allocate = NLib::aligndown(allocate, (SMALLESTBLOCK << (ALLOCLEVEL - 1)));

                        if (allocate >= (SMALLESTBLOCK << (ALLOCLEVEL - 1))) {
                            if (!zone.size) {
                                zone.addr = (uintptr_t)hhdmoff((void *)regionbase);
                                zone.size = allocate;
                            } else {
                                if (allocate > zone.size) { // If this is a bigger region, use it instead.
                                    zone.addr = (uintptr_t)hhdmoff((void *)regionbase);
                                    zone.size = allocate;
                                }
                            }
                            buddyalloc += allocate;
                            regionbase += allocate;
                            regionsize -= allocate;
                        }
                    }


                    if (regionsize >= PAGESIZE && bitmapalloc < bitmaptarget) { // If we still have space, and we're under the target for bitmap allocation, commit the rest of this region to bitmaps.
                        size_t allocate = regionsize;
                        if (bitmapalloc + allocate > bitmaptarget) {
                            allocate = bitmaptarget - bitmapalloc;
                        }

                        allocate = NLib::aligndown(allocate, PAGESIZE);

                        size_t pages = allocate / PAGESIZE;
                        size_t bmapsize = (pages + 7) / 8;
                        size_t bmappages = NLib::alignup(bmapsize, PAGESIZE) / PAGESIZE;

                        if (bmappages * PAGESIZE + PAGESIZE > allocate) {
                            continue; // Not even enough space for the region.
                        }

                        bitmapzones[numbitmapzones].addr = (uintptr_t)hhdmoff((void *)regionbase) + bmappages * PAGESIZE;
                        bitmapzones[numbitmapzones].size = allocate - bmappages * PAGESIZE;
                        bitmapzones[numbitmapzones].bitmap = (uint8_t *)hhdmoff((void *)regionbase);
                        NLib::memset(bitmapzones[numbitmapzones].bitmap, 0, bmappages * PAGESIZE);

                        for (size_t j = 0; j < bmappages; j++) {
                            bitmapzones[numbitmapzones].bitmap[j / 8] |= (1 << (j % 8));
                        }

                        numbitmapzones++;
                        bitmapalloc += allocate;
                    }
                }
            }

            for (size_t i = 0; i < ALLOCLEVEL; i++) {
                zone.freelist[i] = NULL;
            }

            NUtil::printf("[arch/x86_64/pmm]: Initialising buddy allocator...\n");

            // Shove the *entire* region into the top level freelist.

            size_t size = zone.size;
            size_t biggestblock = (SMALLESTBLOCK << (ALLOCLEVEL - 1)); // Biggest block size.
            // For as long as we have a fully sized block at the maximum level.
            size_t i = 0;

            struct block *prev = NULL;
            while (size > biggestblock) {
                // The linked list entry sits within the block until the block is no longer free, in which case it'll be overwritten for use as memory region.
                struct block *block = (struct block *)(zone.addr + (i * biggestblock)); // Pick an area.
                block->canary = CANARY; // Fill with canary for UAF checks.
                block->next = NULL;

                if (prev != NULL) {
                    prev->next = block; // Point previous block towards this one.
                } else { // First entry.
                    zone.freelist[ALLOCLEVEL - 1] = block; // Point the head of the freelist to this current entry, this will consequently append all free entries.
                }

                prev = block; // Update this for the next block, so that it knows to add itself.

                i++; // Increment counter.
                size -= biggestblock; // Decrement available size by block size.
            }
            NUtil::printf("[arch/x86_64/pmm]: Buddy allocator initialised.\n");

            // Sanity check:
            // If we allocate, and then immediately free, the next allocation of the same size should be the same pointer (free list logic).
            void *test1 = alloc(4096);
            free(test1);
            void *test2 = alloc(4096);
            free(test2);
            assertarg(test1 == test2, "Buddy allocator does not return last freed (%p != %p).\n", test1, test2);

            NUtil::printf("[arch/x86_64/pmm]: Buddy allocator self-test passed.\n");

            void *test3 = alloc(2 * 1024 * 1000);
            free(test3);

            void *test4 = alloc(2 * 1024 * 1024);
            free(test4);
            assertarg(test3 == test4, "Bitmap allocator does not return last freed (%p != %p).\n", test3, test4);

            NUtil::printf("[arch/x86_64/pmm]: PMM initialised.\n");
        }

        void *buddyalloc(size_t size) {
            // NOTE: Due to the behaviour of a freelist (last block is first in free list), the PMM buddy allocator will grow upwards from the allocatable region base.

            // Round up to nearest block size that fits this allocation.
            size_t actual = SMALLESTBLOCK;

            size_t level = 0; // Start at smallest block size and work our way up.
            while (actual < size && level < ALLOCLEVEL - 1) {
                actual <<= 1; // Shift up to next level, trying to get a closest fit possible.
                level++; // Also increase a counter for referencing the freelist later.
            }

            size_t found = level;
            // While we haven't exceeded the maximum number of levels, and there are empty freelists (not yet split).
            while (found < ALLOCLEVEL && zone.freelist[found] == NULL) { // For as long as we're working with real levels that are empty.
                found++; // If the ideal size has no free blocks, we'll have to go upwards to a larger size.
            }

            if (found == ALLOCLEVEL) { // If we have actually reached the maximum allocation level, then we couldn't find anything.
                NUtil::printf("[arch/x86_64/pmm]: Buddy allocator OOM when trying to find for size %lu.\n", size);
                return NULL; // OOM.
            }

            while (found > level) { // While we haven't yet split down to the comfiest level.
                struct block *block = zone.freelist[found]; // Grab the head of the freelist.
                zone.freelist[found] = block->next; // We're planning to consume this block, so move the freelist onwards.

                // Split in half (this works because everything is a power of two) for two of the smaller levels.
                size_t half = (SMALLESTBLOCK << (found - 1)); // Get the size of the smaller level size.
                struct block *second = (struct block *)((uintptr_t)block + half); // Reference the start of the "second" block within this split.

                // Setup canaries.
                block->canary = CANARY;
                second->canary = CANARY;

                // Add both to the lower level.

                block->next = zone.freelist[found - 1]; // This block will be just before the latest on the free list.
                second->next = block; // This block will be just behind the other block.
                zone.freelist[found - 1] = second; // Shove this on the head of the free list.

                found--;
            }

            // We have now reached the point when we can actually pull something off the free list here.
            struct block *alloc = zone.freelist[level];
            zone.freelist[level] = alloc->next; // We're consuming this block now.
            alloc->canary = 0; // Remove canary.
            return (void *)((uintptr_t)alloc - NLimine::hhdmreq.response->offset); // Return block allocation.
        }

        void *bmapalloc(size_t size) {

            size_t needed = NLib::alignup(size + sizeof(struct bheader), PAGESIZE) / PAGESIZE;
            void *res = NULL;

            for (size_t i = 0; i < numbitmapzones; i++) {
                size_t inregion = bitmapzones[i].size / PAGESIZE; // How many pages are in here? Check how many pages can we work with.
                uint8_t *bmap = bitmapzones[i].bitmap;

                for (size_t page = 0; page < inregion;) {
                    if (!(page % 8) && (inregion - page >= 8)) { // Alignment means we can check in terms of full-size words.
                        uint64_t word = *((uint64_t *)((uintptr_t)bmap + page / 8));
                        if (word == 0xffffffffffffffff) { // All full.
                            page += 64; // We can just skip a whole set of 64 pages.
                            continue;
                        }
                    }

                    if (!(bmap[page / 8] & (1 << (page % 8)))) {
                        bool found = true;
                        for (size_t j = 1; j < needed; j++) { // Check for contiguous pages.
                            if ((page + j) >= inregion || (bmap[(page + j) / 8] & (1 << ((page + j) % 8)))) {
                                found = false;
                                break;
                            }
                        }

                        if (found) { // If we found a good region, mark as allocated and return.
                            for (size_t j = 0; j < needed; j++) {
                                bmap[(page + j) / 8] |= (1 << ((page + j) % 8)); // Mark.
                            }
                            struct bheader *header = (struct bheader *)(bitmapzones[i].addr + page * PAGESIZE);
                            header->magic = CANARY;
                            header->size = size;

                            res = (void *)((uintptr_t)hhdmsub(header) + sizeof(struct bheader));

                            if (needed > 1 && ((uintptr_t)res % PAGESIZE)) { // Violations of page alignment will need to be corrected.
                                uintptr_t aligned = NLib::alignup((uintptr_t)res, PAGESIZE);
                                if (aligned < (uintptr_t)header + needed * PAGESIZE) {
                                    res = (void *)aligned;
                                }
                            }
                            goto done;
                        }
                    }
                    page++;
                }
            }
done:
            return res;
        }

        void *alloc(size_t size) {
            NLib::ScopeSpinlock guard(&alloclock);

            alloci++;
            if (size <= (SMALLESTBLOCK << (ALLOCLEVEL - 1))) { // Allocation could theoretically be made with the buddy allocator.
                return buddyalloc(size);
            }
            return bmapalloc(size);
        }

        void buddyfree(void *ptr) {
            uintptr_t addr = (uintptr_t)ptr + NLimine::hhdmreq.response->offset;
            assertarg(((struct block *)addr)->canary != CANARY, "Double free occurred on address %p.\n", ptr);

            // Check if the pointer actually exists in the allocator zone, if it's not, it's an invalid pointer.
            assert(addr >= zone.addr && addr < zone.addr + zone.size, "Free on invalid pointer.\n");

            size_t level = 0;
            size_t size = SMALLESTBLOCK;

            // Iterate over levels to find a "buddy" to merge with.
            // This buddy can be a higher level, or not, but the idea is to keep it contiguous.
            // Greedily merge all the contiguous pages together (helps get rid of fragmentation).
            while (level < ALLOCLEVEL - 1) {
                uintptr_t buddyaddr = addr ^ size; // Attempt to get a paired block.
                struct block *buddy = (struct block *)buddyaddr;

                if (buddy->canary != CANARY) {
                    break; // The buddy is not free, we can't merge.
                }

                struct block **prev = &zone.freelist[level];
                while (*prev != NULL && *prev != buddy) { // Attempt to either reach the end of the freelist, or locate the buddy.
                    prev = &(*prev)->next;
                }

                if (*prev == buddy) {
                    *prev = buddy->next; // Remove buddy from freelist (we're merging with it upwards).
                }

                addr &= ~size; // Raise address to next biggest block size alignment (this will include the buddy).
                size <<= 1; // Move to higher level.

                level++;
            }


            struct block *block = (struct block *)addr;
            block->canary = CANARY;

            // Direct freelist head to the newly merged block.
            block->next = zone.freelist[level];
            zone.freelist[level] = block;
        }

        void bitmapfree(void *ptr) {
            uintptr_t hoff = (uintptr_t)hhdmoff(ptr);

            struct bheader *header = (struct bheader *)(hoff - sizeof(struct bheader));

            if (hoff - sizeof(struct bheader) % PAGESIZE) { // Because of the alignment, the header should be within the start of the previous page.
                header = (struct bheader *)(hoff - PAGESIZE);
            } // Otherwise, it's right before the current page.

            assert(header->magic == CANARY, "Attempting double-free or invalid pointer.\n");
            header->magic = 0;

            size_t size = header->size + sizeof(struct bheader);
            size_t pages = NLib::alignup(size, PAGESIZE) / PAGESIZE;
            uintptr_t addr = (uintptr_t)header;

            for (size_t i = 0; i < numbitmapzones; i++) {
                if (addr >= bitmapzones[i].addr && addr < bitmapzones[i].addr + bitmapzones[i].size) {
                    size_t page = (addr - bitmapzones[i].addr) / PAGESIZE;
                    for (size_t j = 0; j < pages; j++) {
                        if (page + j >= bitmapzones[i].size / PAGESIZE) {
                            break;
                        }
                        bitmapzones[i].bitmap[(page + j) / 8] &= ~(1 << ((page + j) % 8));
                    }
                    break;
                }
            }

        }

        void free(void *ptr) {
            if (!ptr) {
                return;
            }

            // TODO: Defer the merging!
            NLib::ScopeSpinlock guard(&alloclock);

            alloci--;

            if ((uintptr_t)ptr >= (uintptr_t)hhdmsub((void *)zone.addr) && (uintptr_t)ptr < (uintptr_t)hhdmsub((void *)zone.addr) + zone.size) { // If our pointer exists within the buddy allocator region, we can assume it'll be freed by it.
                buddyfree(ptr);
            } else {
                bitmapfree(ptr);
            }
        }
    }
}
