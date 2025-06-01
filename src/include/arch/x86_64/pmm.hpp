#ifndef _ARCH__X86_64__PMM_HPP
#define _ARCH__X86_64__PMM_HPP

#include <lib/sync.hpp>
#include <stddef.h>
#include <stdint.h>

namespace NArch {
    __attribute__((unused))
    static const size_t PAGESIZE = 4096; // Page size.

    __attribute__((unused))
    static const size_t SMALLESTBLOCK = PAGESIZE; // Smallest size of a buddy allocated block.

    __attribute__((unused))
    static const size_t ALLOCLEVEL = 8; // SMALLESTBLOCK * (2 ^ 7) pages.

    __attribute__((unused))
    static const uint64_t CANARY = 0x4fc0ffee2dead9f5; // Magic "canary" to be stored at the start of free entries, to check for UAF errors.

    namespace PMM {
        struct block {
            uint64_t canary; // Canary for UAF checks.
            struct block *next; // Reference next block in linked list.
        };

        struct zone {
            uintptr_t addr; // Base address for allocation region.
            size_t size; // Size of allocation region.
            struct block *freelist[ALLOCLEVEL]; // References to linked list that reference blocks, for each buddy allocation level.
        };

        extern struct zone zone;
        extern Spinlock buddylock;

        extern size_t alloci;
        void setup(void);

        // NOTE: Returns with HHDM offset! For stuff that does NOT support higher halves, we need to subtract the HHDM offset.
        void *alloc(size_t size);
        void free(void *ptr);
    }
}

#endif
