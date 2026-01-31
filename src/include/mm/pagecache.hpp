#ifndef _MM__PAGECACHE_HPP
#define _MM__PAGECACHE_HPP

#include <lib/list.hpp>
#include <lib/sync.hpp>
#include <sched/event.hpp>
#include <stddef.h>
#include <stdint.h>
#include <sys/timer.hpp>

#ifdef __x86_64__
#include <arch/x86_64/pmm.hpp>
#endif

namespace NFS {
    namespace VFS {
        class INode;
    }
}

namespace NDev {
    class BlockDevice;
}

namespace NArch {
    namespace VMM {
        struct addrspace;
    }
}

namespace NMem {

    // Represents a single VMA mapping to a cached page.
    struct vmamapping {
        NArch::VMM::addrspace *space;   // Address space containing mapping.
        uintptr_t virtaddr;             // Virtual address in that space.
        vmamapping *next;               // Next mapping in list.
        vmamapping *prev;               // Previous mapping in list.

        vmamapping(NArch::VMM::addrspace *s, uintptr_t v) : space(s), virtaddr(v), next(NULL), prev(NULL) {}
    };

    // Forward declarations.
    class PageCache;

    // Page cache entry flags.
    enum pageflag {
        PAGE_DIRTY      = (1 << 0),     // Page has been modified.
        PAGE_UPTODATE   = (1 << 1),     // Page contains valid data.
        PAGE_LOCKED     = (1 << 2),     // Page is locked for I/O.
        PAGE_WRITEBACK  = (1 << 3),     // Page is being written back.
        PAGE_REFERENCED = (1 << 4),     // Page has been accessed recently (for LRU).
        PAGE_ERROR      = (1 << 5),     // I/O error occurred.
        PAGE_IOINFLIGHT = (1 << 6),     // Read I/O in progress (lock released during I/O).
        PAGE_PRIVATE    = (1 << 7),     // Page has private data (filesystem-specific).
        PAGE_SWAPCACHE  = (1 << 8)      // Page is in swap cache (reserved for future).
    };

    // LRU list membership tracking (pretty easy way to quickly determine which list a page belongs to).
    enum lrulist {
        LRU_NONE = 0,
        LRU_ACTIVE = 1,
        LRU_INACTIVE = 2
    };

    // Page cache entry representing a single cached page.
    class CachePage {
        public:
            NArch::IRQSpinlock lock; // Per-page lock.

            // Reference count for CachePage lifetime management.
            // Initial ref of 1 is taken when page is added to cache.
            // Additional refs are taken when:
            // - Page is looked up and returned to caller (lookupandlock)
            // - Page is collected into a batch for processing
            // Final unref triggers deletion.
            volatile int32_t refcount = 0;

            // Generation counter for ABA protection in lookupandlock().
            // Incremented each time page is removed from a radix tree.
            // Allows detection of page reuse after eviction.
            volatile uint32_t generation = 0;

            NFS::VFS::INode *inode = NULL; // Owning inode (for filesystem pages).
            NDev::BlockDevice *blockdev = NULL; // Owning block device (for device pages).
            off_t offset = 0; // Byte offset within file/device (page-aligned).

            uintptr_t physaddr = 0; // Physical address of the page.
            NArch::PMM::PageMeta *pagemeta = NULL; // PMM page metadata.

            uint16_t flags = 0; // Page flags (see pageflag enum).
            uint16_t mapcount = 0; // Number of mappings (for shared pages).
            uint8_t errorcount = 0; // Consecutive I/O errors.
            uint8_t lrulist = LRU_NONE; // Which LRU list this page belongs to.

            CachePage *lrunext = NULL;
            CachePage *lruprev = NULL;


            // List of VMA mappings to this page.
            struct vmamapping *mappingshead = NULL;

            // Wait queue for I/O completion.
            NSched::WaitQueue waitq;

            CachePage(void) = default;
            ~CachePage(void) = default;

            // Reference counting.
            void ref(void);
            void unref(void);  // May delete page when refcount hits 0.
            int32_t getref(void) const;

            // Lock the page for exclusive access.
            void pagelock(void);
            // Unlock the page after I/O.
            void pageunlock(void);
            // Try to lock, returns true if successful.
            bool trypagelock(void);
            // Wait for page to become unlocked.
            void waitunlocked(void);

            // Wait for any in-flight I/O to complete. Caller must NOT hold the page lock.
            void waitio(void);
            // Signal that I/O has completed. Clears IOINFLIGHT and wakes waiters.
            void signalio(void);

            // Flag manipulation.
            void setflag(uint16_t flag);
            void clearflag(uint16_t flag);
            bool testflag(uint16_t flag) const;
            bool testandsetflag(uint16_t flag);
            bool testandclearflag(uint16_t flag);

            // Mark page dirty (needs writeback).
            void markdirty(void);
            // Mark page clean (data written to backing store).
            void markclean(void);

            // Get virtual address of page data via HHDM.
            void *data(void);

            // Add a mapping from an address space to this cached page.
            void addmapping(NArch::VMM::addrspace *space, uintptr_t virtaddr);
            // Remove a specific mapping from this page.
            void removemapping(NArch::VMM::addrspace *space, uintptr_t virtaddr);
            // Remove all mappings (used during page eviction). Returns number removed.
            size_t unmapall(void);
            // Check if this page has any mappings.
            bool hasmappings(void) const {
                return mappingshead != NULL;
            }
    };

    // Radix tree node for page lookup.
    static constexpr size_t RADIXTREESLOTS = 64;
    static constexpr size_t RADIXTREESHIFT = 6;
    static constexpr size_t RADIXTREEMASK = RADIXTREESLOTS - 1;

    class RadixTreeNode {
        public:
            NArch::Spinlock lock;
            uint8_t height = 0; // Height of this node in tree.
            uint8_t count = 0; // Number of non-null slots.
            void *slots[RADIXTREESLOTS] = { NULL }; // Child nodes or CachePage pointers.

            RadixTreeNode(void) = default;
            ~RadixTreeNode(void);
    };

    // Radix tree for page lookup by file offset.
    class RadixTree {
        private:
            NArch::IRQSpinlock treelock;
            RadixTreeNode *root = NULL;
            uint8_t height = 0; // Current tree height.

            RadixTreeNode *extendtree(off_t index);
            static size_t maxindex(uint8_t height);
            CachePage *lookupinternal(off_t index); // Internal lookup without lock.
        public:
            RadixTree(void) = default;
            ~RadixTree(void);

            // Insert a page at the given page index.
            int insert(off_t index, CachePage *page);

            // Lookup a page by index.
            CachePage *lookup(off_t index);

            // Lookup a page and lock it atomically. Prevents race with eviction. Returns page with ref held, or NULL if not found.
            CachePage *lookupandlock(off_t index);

            // Remove a page by index.
            CachePage *remove(off_t index);

            // Iterate over all pages in the tree calling the callback.
            void foreach(bool (*callback)(CachePage *, void *), void *ctx);

            // Collect pages matching a filter into an output array. Takes a ref on each collected page before releasing the lock.
            size_t foreachcollect(CachePage **out, size_t maxcount, bool (*filter)(CachePage *, void *), void *ctx, off_t *resumeindex);
    };

    // Global page cache manager.
    class PageCache {
        private:
            NArch::IRQSpinlock cachelock; // Global cache lock.

            CachePage *activehead = NULL; // Active (recently used) pages (LRU_ACTIVE).
            CachePage *activetail = NULL;
            size_t activecount = 0;

            CachePage *inactivehead = NULL; // Inactive (candidates for eviction) (LRU_INACTIVE).
            CachePage *inactivetail = NULL;
            size_t inactivecount = 0;

            size_t totalpages = 0; // Total pages in cache.
            size_t dirtypages = 0; // Pages needing writeback.
            uint64_t cachehits = 0; // Cache hit count.
            uint64_t cachemisses = 0; // Cache miss count.

            size_t maxpages = 0; // Maximum pages to cache (0 = unlimited).
            size_t targetfreepages = 0; // Target free pages to maintain.

            // Writeback thread management stuff.
            volatile bool running = true;
            volatile bool exited = false;
            volatile bool wakeupneeded = false; // Flag to wake writeback thread early.
            volatile uint64_t throttlegeneration = 0; // Incremented when writeback makes progress.
            NSched::WaitQueue exitwq;    // For shutdown synchronisation.
            NSched::WaitQueue wakeupwq;  // For immediate writeback wakeup.
            NSched::WaitQueue throttlewq; // For blocking throttled writers.
            NSched::Thread *wbthread = NULL;

            // Writeback configuration.
            static constexpr uint64_t WRITEBACKINTERVALMS = 500; // 500ms default (reduced from 1s).
            static constexpr size_t MAXWRITEBACKPERCYCLE = 128; // Max pages per writeback cycle (increased from 64).
            
            // Two-tier dirty thresholds for soft/hard throttling.
            static constexpr size_t DIRTYSOFTTHRESHOLDPERCENT = 25; // Wake writeback at 25% dirty.
            static constexpr size_t DIRTYHARDTHRESHOLDPERCENT = 50; // Block writers at 50% dirty.
            static constexpr size_t DIRTYTHRESHOLDPERCENT = 40; // Legacy threshold (kept for compatibility).
            static constexpr size_t DIRTYTARGETPERCENT = 15; // Target dirty ratio after cleanup.
            
            // Batch sizes for writeback.
            static constexpr size_t BATCHSIZENORMAL = 32; // Normal batch size.
            static constexpr size_t BATCHSIZEPRESSURE = 128; // Batch size under pressure.

            void addtoactive(CachePage *page);
            void addtoinactive(CachePage *page);
            void removefromlru(CachePage *page);
            void promotepage(CachePage *page); // Move from inactive to active.
            void demotepage(CachePage *page); // Move from active to inactive.

            CachePage *selectvictim(void); // Select page for eviction (any page).

            // Statistics from selectvictim operations for diagnostics.
            struct selvictimstats {
                size_t skippedlocked = 0;
                size_t skippeddirty = 0;
                size_t skippedwriteback = 0;
                size_t skippedreferenced = 0;
                size_t skippedioinflight = 0;
            };

            CachePage *selectvictimclean(struct selvictimstats *stats = NULL); // Select clean page for eviction (avoids writeback during shrink).
            int evictpage(CachePage *page); // Evict a single page.
            void evictpagefromwriteback(CachePage *page); // Evict page from writeback context (page already locked+clean).

            int writebackpage(CachePage *page); // Write single page to backing store.
        public:
            PageCache(void);
            ~PageCache(void);

            // Initialise with memory limits.
            void init(size_t maxpages, size_t targetfree);

            CachePage *findpage(NFS::VFS::INode *inode, off_t offset);
            CachePage *findorcreate(NFS::VFS::INode *inode, off_t offset);

            // Add a page to the cache. Page must be locked.
            int addpage(CachePage *page);

            // Remove a page from the cache. Page must be locked.
            void removepage(CachePage *page);

            // Write back all dirty pages for an inode.
            int syncnode(NFS::VFS::INode *inode);
            // Write back all dirty pages globally.
            int syncall(void);

            // Background writeback thread entry point.
            void writebackthread(void);

            // Start the writeback thread. Called after scheduler is initialised.
            void startwritebackthread(void);

            // Immediately wake the writeback thread.
            void wakewriteback(void);

            // Try to free 'count' clean pages. Returns number actually freed.
            size_t shrink(size_t count);

            // Try to free 'count' clean/dirty pages, with synchronous writeback fallback. Can tolerate blocking I/O.
            size_t shrinkwithwriteback(size_t count);

            // Invalidate a single page.
            int invalidatepage(NFS::VFS::INode *inode, off_t offset);

            // Invalidate all pages for an inode.
            int invalidateinode(NFS::VFS::INode *inode);

            // Check if dirty page throttling should occur (hard threshold).
            bool shouldthrottle(void) const;
            
            // Check if we should wake writeback proactively (soft threshold).
            bool shouldwakewriteback(void) const;

            // Block the caller until cache pressure is relieved.
            void throttle(void);
            
            // Perform direct reclaim from calling thread. Returns pages written/freed.
            size_t directreclaim(size_t target);

            size_t gettotalpages(void) const {
                return this->totalpages;
            }
            size_t getdirtypages(void) const {
                return this->dirtypages;
            }
            uint64_t gethits(void) const {
                return __atomic_load_n(&this->cachehits, memory_order_relaxed);
            }
            uint64_t getmisses(void) const {
                return __atomic_load_n(&this->cachemisses, memory_order_relaxed);
            }

            void inchits(void) {
                __atomic_add_fetch(&this->cachehits, 1, memory_order_relaxed);
            }
            void incmisses(void) {
                __atomic_add_fetch(&this->cachemisses, 1, memory_order_relaxed);
            }

            void incdirtypages(void) {
                __atomic_add_fetch(&this->dirtypages, 1, memory_order_relaxed);
            }
            void decdirtypages(void) {
                __atomic_sub_fetch(&this->dirtypages, 1, memory_order_relaxed);
            }

            bool isrunning(void) const {
                return __atomic_load_n(&this->running, memory_order_acquire);
            }

            void signalexit(void) {
                __atomic_store_n(&this->exited, true, memory_order_release);
                this->exitwq.wake();
            }

            void shutdown(void);
    };

    // Global page cache instance.
    extern PageCache *pagecache;

    // Initialise the global page cache subsystem.
    void initpagecache(void);

    // Start the page cache writeback thread (call after scheduler init).
    void startpagecachethread(void);

    // Called by PMM under memory pressure to reclaim pages.
    size_t reclaimcachepages(size_t count);

    // Convert byte offset to page index.
    static inline off_t offsettopageindex(off_t offset) {
        return offset / NArch::PAGESIZE;
    }

    // Convert page index to byte offset.
    static inline off_t pageindextooffset(off_t index) {
        return index * NArch::PAGESIZE;
    }

    // Get offset within page.
    static inline size_t offsetinpage(off_t offset) {
        return offset % NArch::PAGESIZE;
    }

}

#endif
