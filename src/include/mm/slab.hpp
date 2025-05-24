#ifndef _MM__SLAB_HPP
#define _MM__SLAB_HPP

#include <stddef.h>
#include <stdint.h>

namespace NMem {
    __attribute__((unused))
    static const size_t numslabs = 9;

    __attribute__((unused))
    static const size_t slabsizes[numslabs] = {
        // Allocate slabs up to the exact size of a traditional "page".
        16, 32, 64, 128, 256, 512, 1024, 2048, 4096
    };

    __attribute__((unused))
    static const uint32_t ALLOCMAGIC = 0xab2113f4; // Indicates allocated.

    __attribute__((unused))
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
                        size_t size;
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
            void free(void *ptr);
    };

    extern SlabAllocator allocator;
}

#endif
