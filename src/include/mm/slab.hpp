#ifndef _MM__SLAB_HPP
#define _MM__SLAB_HPP

#include <stddef.h>
#include <stdint.h>

namespace NMem {
    // Fill allocations with 0xAA, like free santitisation.
    extern bool nonzeroalloc;
    // Fill freed allocations with 0xAA, to hide what they originally contained on next alloc.
    extern bool sanitisefreed;

    __attribute__((used))
    static const size_t numslabs = 17;

    __attribute__((used))
    static const size_t slabsizes[numslabs] = {
        // Allocate slabs up to the exact size of a traditional "page".
        16, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512, 768, 1024, 1536,
        2048, 3072, 4096
    };

    __attribute__((used))
    static const uint32_t ALLOCMAGIC = 0xab2113f4; // Indicates allocated.

    __attribute__((used))
    static const uint32_t CANARY = 0x3fce23a2; // Memory corruption canary.

    class SlabAllocator {
        private:

            class SubAllocator {
                public:
                    // Free block header.
                    struct header {
                        struct header *next;
                    };

                    // Metadata header.
                    struct metadata {
                        uint32_t startcanary;
                        uint32_t size; // This means we can only have a maximum size of a 4G allocation.
                        uint32_t magic;
                        uint32_t endcanary;
                    };

                    struct header *freelist;
                    size_t blksize; // Size of this suballocator's block.
                    size_t blkpp; // Number of blocks fit within a page.
            };

            SubAllocator slabs[numslabs];
        public:
            SlabAllocator(void) { };
            void setup(void);

            void *alloc(size_t size);
            void *calloc(size_t num, size_t size);
            void *realloc(void *ptr, size_t newsize);
            void free(void *ptr);
    };

    extern SlabAllocator allocator;
}

#endif
