#ifndef _ARCH__X86_64__PMM_HPP
#define _ARCH__X86_64__PMM_HPP

#include <lib/sync.hpp>
#include <stddef.h>
#include <stdint.h>

namespace NArch {
    __attribute__((used))
    static const size_t PAGESIZE = 4096; // Page size.

    __attribute__((used))
    static const size_t SMALLESTBLOCK = PAGESIZE; // Smallest size of a buddy allocated block.

    __attribute__((used))
    static const size_t ALLOCLEVEL = 8; // SMALLESTBLOCK * (2 ^ 7) pages.

    __attribute__((used))
    static const uint64_t CANARY = 0x4fc0ffee2dead9f5; // Magic "canary" to be stored at the start of free entries, to check for UAF errors.

    namespace PMM {
        // Phyical page metadata.
        class PageMeta {
            public:
                size_t refcount = 0;
                uint64_t flags = 0;

                void ref(void);
                void unref(void);
                void free(void);
        };

        struct block {
            uint64_t canary; // Canary for UAF checks.
            struct block *next; // Reference next block in linked list.
        };

        struct zone {
            uintptr_t addr; // Base address for allocation region.
            size_t size; // Size of allocation region.
            struct block *freelist[ALLOCLEVEL]; // References to linked list that reference blocks, for each buddy allocation level.

            PageMeta *meta; // Associated page meta array.
        };

        struct bzone {
            uintptr_t addr; // Base address for allocation region.

            size_t size; // Size of allocation region.
            uint8_t *bitmap; // Associated bitmap for this region.

            PageMeta *meta; // Associated page metadata array.
        };

        PageMeta *phystometa(uintptr_t phys);

        extern size_t alloci;
        void setup(void);

        void *alloc(size_t size);
        void free(void *ptr, size_t size = 0);
    }
}

#endif
