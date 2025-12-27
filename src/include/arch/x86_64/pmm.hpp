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
        // Physical page metadata.
        class PageMeta {
            public:
                enum flags {
                    PAGEMETA_DEVICEMAP  = (1 << 0),      // Page is used for memory-mapped device (no free, allocating context is expected to clean this up).
                    PAGEMETA_PAGECACHE  = (1 << 1),      // Page is managed by the page cache.
                    PAGEMETA_ANONYMOUS  = (1 << 2),      // Anonymous page (not backed by file, for future swap support).
                    PAGEMETA_SLAB       = (1 << 3)       // Page is part of slab allocator.
                };

                NArch::IRQSpinlock pagelock; // Lock for this page's metadata.
                uint32_t refcount = 0;
                uint8_t flags = 0;
                uintptr_t addr = 0; // Physical address of this page.

                // Page cache linkage (valid when PAGEMETA_PAGECACHE is set).
                void *cacheentry = NULL;

                void ref(void);
                void unref(void);
                void zeroref(void) {
                    NLib::ScopeIRQSpinlock guard(&this->pagelock);
                    this->flags = 0;
                    this->refcount = 0;
                    this->cacheentry = NULL;
                }
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

        enum flags {
            FLAGS_NOTRACK   = (1 << 0), // Allocation that is not tracked (for early allocations).
            FLAGS_NOWAIT    = (1 << 1), // Allocation must not block (returns NULL if no memory available, for use in interrupt context).
            FLAGS_DEVICE    = (1 << 2)  // Device-mapped allocation (not automatically freed).
        };

        // TODO: Memory reclamation, so FLAGS_NOWAIT has a use.
        void *alloc(size_t size, uint8_t flags = 0);
        void free(void *ptr, size_t size = 0, bool track = true);
    }
}

#endif
