#ifndef _MM__PAGECACHE_HPP
#define _MM__PAGECACHE_HPP

#include <lib/list.hpp>
#include <lib/sync.hpp>
#include <sched/event.hpp>
#include <stddef.h>
#include <stdint.h>

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

namespace NMem {

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
        PAGE_PRIVATE    = (1 << 6),     // Page has private data (filesystem-specific).
        PAGE_SWAPCACHE  = (1 << 7)      // Page is in swap cache (reserved for future).
    };

    // LRU list membership tracking.
    enum lrulist {
        LRU_NONE = 0,
        LRU_ACTIVE = 1,
        LRU_INACTIVE = 2
    };

    // Page cache entry representing a single cached page.
    class CachePage {
        public:
            NArch::IRQSpinlock lock; // Per-page lock.

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

            // Wait queue for I/O completion.
            NSched::WaitQueue waitq;

            CachePage(void) = default;
            ~CachePage(void) = default;

            // Lock the page for exclusive access.
            void pagelock(void);
            // Unlock the page after I/O.
            void pageunlock(void);
            // Try to lock, returns true if successful.
            bool trypagelock(void);
            // Wait for page to become unlocked.
            void waitunlocked(void);

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

            void ref(void);
            void unref(void);
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
        public:
            RadixTree(void) = default;
            ~RadixTree(void);

            // Insert a page at the given page index.
            int insert(off_t index, CachePage *page);

            // Lookup a page by index.
            CachePage *lookup(off_t index);

            // Remove a page by index.
            CachePage *remove(off_t index);

            // Iterate over all pages in the tree calling the callback.
            void foreach(bool (*callback)(CachePage *, void *), void *ctx);
    };

    // Global page cache manager.
    class PageCache {
        private:
            NArch::IRQSpinlock cachelock; // Global cache lock.

            CachePage *activehead = NULL; // Active (recently used) pages.
            CachePage *activetail = NULL;
            size_t activecount = 0;

            CachePage *inactivehead = NULL; // Inactive (candidates for eviction).
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
            NSched::WaitQueue exitwq;
            NSched::Thread *wbthread = NULL;

            void addtoactive(CachePage *page);
            void addtoinactive(CachePage *page);
            void removefromlru(CachePage *page);
            void promotepage(CachePage *page); // Move from inactive to active.
            void demotepage(CachePage *page); // Move from active to inactive.

            CachePage *selectvictim(void); // Select page for eviction.
            int evictpage(CachePage *page); // Evict a single page.

            int writebackpage(CachePage *page); // Write single page to backing store.
        public:
            PageCache(void);
            ~PageCache(void);

            // Initialize with memory limits.
            void init(size_t maxpages, size_t targetfree);

            CachePage *findpage(NFS::VFS::INode *inode, off_t offset);
            CachePage *findorcreate(NFS::VFS::INode *inode, off_t offset);

            // Add a page to the cache. Page must be locked.
            int addpage(CachePage *page);

            // Remove a page from the cache. Page must be locked.
            void removepage(CachePage *page);

            // Read data from cache, populating from backing store if needed.
            ssize_t read(NFS::VFS::INode *inode, void *buf, size_t count, off_t offset);

            // Write data to cache, marking pages dirty.
            ssize_t write(NFS::VFS::INode *inode, const void *buf, size_t count, off_t offset);

            // Write back all dirty pages for an inode.
            int syncnode(NFS::VFS::INode *inode);
            // Write back all dirty pages globally.
            int syncall(void);

            // Background writeback thread entry point.
            void writebackthread(void);

            // Try to free 'count' pages. Returns number actually freed.
            size_t shrink(size_t count);

            // Reclaim pages under memory pressure.
            void reclaim(void);

            size_t gettotalpages(void) const {
                return this->totalpages;
            }
            size_t getdirtypages(void) const {
                return this->dirtypages;
            }
            uint64_t gethits(void) const {
                return this->cachehits;
            }
            uint64_t getmisses(void) const {
                return this->cachemisses;
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

    // Initialize the global page cache subsystem.
    void initpagecache(void);

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
