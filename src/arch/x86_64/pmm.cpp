#include <arch/limine/requests.hpp>
#include <arch/x86_64/pmm.hpp>
#include <lib/assert.hpp>
#include <lib/sync.hpp>
#include <util/kprint.hpp>

namespace NArch {
    namespace PMM {

        struct zone zone;
        Spinlock buddylock;

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
            // Buddy Allocator.


            size_t usablepages = 0;
            size_t rsvdpages = 0;

            // The initial goal is to locate the largest contiguous block of free memory for usage as an allocation zone.
            // Biggest zone will last the longest. Why don't we try smaller zones? They're typically just gaps between bigger regions split up by reserved regions, not worth trying.

            // Address of the largest area of free memory.
            uintptr_t largestaddr = 0;
            // Size of the largest area of free memory.
            size_t largestsize = 0;

            NUtil::printf("[arch/x86_64/pmm]: Initialising using 4KiB pages.\n");
            for (size_t i = 0; i < NLimine::mmreq.response->entry_count; i++) {
                struct limine_memmap_entry *entry = NLimine::mmreq.response->entries[i];
                if (entry->length == 0) {
                    continue; // Skip empty entries.
                }

                NUtil::printf("[arch/x86_64/pmm]: Memory map entry: 0x%016lx->0x%016lx, length %lu, type %s.\n", entry->base, entry->base + entry->length, entry->length, maptype[entry->type]);

                switch (entry->type) {
                    case LIMINE_MEMMAP_USABLE: // Free! We can use this!
                        usablepages += (entry->length + (PAGESIZE - 1)) / PAGESIZE;

                        if (entry->length > largestsize) { // Is this bigger than our currently stored largest entry?
                            // If so: update it.
                            largestsize = entry->length;
                            largestaddr = entry->base + NLimine::hhdmreq.response->offset; // We need an HHDM offset because Nomos runs within the higher half.
                        }
                        break;
                    default: // Everything else is "reserved".
                        rsvdpages += (entry->length + (PAGESIZE - 1)) / PAGESIZE;
                        break;
                }
            }

            NUtil::printf("[arch/x86_64/pmm]: Usable Pages: %lu (%luMiB).\n", usablepages, (usablepages * PAGESIZE) / 1024 / 1024);
            NUtil::printf("[arch/x86_64/pmm]: Using largest region of usable memory: size %luMiB, at 0x%016lx.\n", (largestsize) / 1024 / 1024, largestaddr);

            // Align to block size.
            largestaddr = (largestaddr + (SMALLESTBLOCK - 1)) & ~(SMALLESTBLOCK - 1);
            largestsize = largestsize & ~(SMALLESTBLOCK - 1);


            // Initialise buddy allocator zone.
            zone.addr = largestaddr;
            zone.size = largestsize;

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
            assertarg(test1 == test2, "Buddy allocator does not return last freed (0x%016x != 0x%016x).\n", test1, test2);

            NUtil::printf("[arch/x86_64/pmm]: Buddy allocator self-test passed.\n");

            NUtil::printf("[arch/x86_64/pmm]: PMM initialised.\n");
        }

        void *alloc(size_t size) {
            NLib::ScopeSpinlock guard(&buddylock);

            alloci++;

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

        void free(void *ptr) {
            // TODO: Defer the merging!
            NLib::ScopeSpinlock guard(&buddylock);

            alloci--;

            uintptr_t addr = (uintptr_t)ptr + NLimine::hhdmreq.response->offset;

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
    }
}
