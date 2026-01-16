#include <lib/assert.hpp>
#include <lib/errno.hpp>
#include <lib/string.hpp>
#include <mm/pagecache.hpp>
#include <mm/slab.hpp>
#include <sched/event.hpp>
#include <sched/sched.hpp>
#include <std/stdatomic.h>
#include <std/stddef.h>
#include <sys/timer.hpp>
#include <util/kprint.hpp>

#ifdef __x86_64__
#include <arch/x86_64/cpu.hpp>
#include <arch/x86_64/vmm.hpp>
#endif

#include <dev/block.hpp>
#include <fs/vfs.hpp>

namespace NMem {

    // Global page cache instance.
    PageCache *pagecache = NULL;

    void CachePage::pagelock(void) {
        while (true) {
            uint16_t expected = __atomic_load_n(&this->flags, memory_order_acquire);
            if (expected & PAGE_LOCKED) {
                // Page is already locked, wait using waitevent to avoid lost wakeups.
                waitevent(&this->waitq, !(__atomic_load_n(&this->flags, memory_order_acquire) & PAGE_LOCKED));
                continue;
            }

            // Try to set LOCKED flag.
            uint16_t desired = expected | PAGE_LOCKED;
            if (__atomic_compare_exchange_n(&this->flags, &expected, desired, false, memory_order_acq_rel, memory_order_acquire)) {
                return;
            }
        }
    }

    void CachePage::pageunlock(void) {
        // Clear LOCKED flag and wake waiters (if we were locked).
        uint16_t old = __atomic_fetch_and(&this->flags, ~PAGE_LOCKED, memory_order_release);
        if (old & PAGE_LOCKED) {
            this->waitq.wake();
        }
    }

    bool CachePage::trypagelock(void) {
        uint16_t expected = __atomic_load_n(&this->flags, memory_order_acquire);
        if (expected & PAGE_LOCKED) {
            return false;
        }
        uint16_t desired = expected | PAGE_LOCKED;
        return __atomic_compare_exchange_n(&this->flags, &expected, desired, false, memory_order_acq_rel, memory_order_acquire);
    }

    void CachePage::waitunlocked(void) {
        // Wait until page is unlocked using waitevent to avoid lost wakeups.
        waitevent(&this->waitq, !(__atomic_load_n(&this->flags, memory_order_acquire) & PAGE_LOCKED));
    }

    void CachePage::setflag(uint16_t flag) {
        __atomic_or_fetch(&this->flags, flag, memory_order_release);
    }

    void CachePage::clearflag(uint16_t flag) {
        __atomic_and_fetch(&this->flags, ~flag, memory_order_release);
    }

    bool CachePage::testflag(uint16_t flag) const {
        return __atomic_load_n(&this->flags, memory_order_acquire) & flag;
    }

    bool CachePage::testandsetflag(uint16_t flag) {
        uint16_t old = __atomic_fetch_or(&this->flags, flag, memory_order_acq_rel);
        return old & flag;
    }

    bool CachePage::testandclearflag(uint16_t flag) {
        uint16_t old = __atomic_fetch_and(&this->flags, ~flag, memory_order_acq_rel);
        return old & flag;
    }

    void CachePage::markdirty(void) {
        if (!testandsetflag(PAGE_DIRTY)) {
            // Transitioned from clean to dirty.
            if (pagecache) {
                pagecache->incdirtypages();
            }
        }
        // Also mark as referenced.
        setflag(PAGE_REFERENCED);
    }

    void CachePage::markclean(void) {
        if (testandclearflag(PAGE_DIRTY)) {
            // Transitioned from dirty to clean.
            if (pagecache) {
                pagecache->decdirtypages();
            }
        }
    }

    void *CachePage::data(void) {
        // Get us an HHDM offset of the physical page.
        return NArch::hhdmoff((void *)this->physaddr);
    }

    void CachePage::ref(void) {
        if (this->pagemeta) {
            this->pagemeta->ref();
        }
    }

    void CachePage::unref(void) {
        if (this->pagemeta) {
            this->pagemeta->unref();
        }
    }

    RadixTreeNode::~RadixTreeNode(void) {
        if (this->height > 0) {
            for (size_t i = 0; i < RADIXTREESLOTS; i++) {
                if (this->slots[i]) {
                    delete (RadixTreeNode *)this->slots[i];
                }
            }
        }
    }

    size_t RadixTree::maxindex(uint8_t height) {
        // Maximum index representable at a given height.

        if (height == 0) {
            return RADIXTREESLOTS - 1;
        }
        size_t result = 1;
        for (uint8_t i = 0; i <= height; i++) {
            result *= RADIXTREESLOTS;
        }
        return result - 1;
    }

    RadixTree::~RadixTree(void) {
        if (this->root) {
            delete this->root;
        }
    }

    RadixTreeNode *RadixTree::extendtree(off_t index) {
        // Extend tree height to accommodate the given index.
        while (this->root && (size_t)index > maxindex(this->height)) {
            RadixTreeNode *newroot = new RadixTreeNode();
            if (!newroot) {
                return NULL;
            }
            newroot->height = this->height + 1;
            newroot->slots[0] = this->root;
            newroot->count = 1;
            this->root = newroot;
            this->height = newroot->height;
        }

        if (!this->root) {
            // Calculate required height.
            uint8_t reqheight = 0;
            while ((size_t)index > maxindex(reqheight)) {
                reqheight++;
            }

            this->root = new RadixTreeNode();
            if (!this->root) {
                return NULL;
            }
            this->root->height = reqheight;
            this->height = reqheight;
        }

        return this->root;
    }

    int RadixTree::insert(off_t index, CachePage *page) {
        NLib::ScopeIRQSpinlock guard(&this->treelock);

        RadixTreeNode *node = extendtree(index);
        if (!node) {
            return -ENOMEM;
        }

        // Walk down the tree, creating nodes as needed.
        uint8_t h = this->height;
        while (h > 0) {
            size_t shift = h * RADIXTREESHIFT;
            size_t slot = (index >> shift) & RADIXTREEMASK;

            if (!node->slots[slot]) {
                RadixTreeNode *child = new RadixTreeNode();
                if (!child) {
                    return -ENOMEM;
                }
                child->height = h - 1;
                node->slots[slot] = child;
                node->count++;
            }
            node = (RadixTreeNode *)node->slots[slot];
            h--;
        }

        // At leaf level.
        size_t slot = index & RADIXTREEMASK;
        if (node->slots[slot]) {
            return -EEXIST;
        }
        node->slots[slot] = page;
        node->count++;
        return 0;
    }

    CachePage *RadixTree::lookup(off_t index) {
        NLib::ScopeIRQSpinlock guard(&this->treelock);

        if (!this->root) {
            return NULL;
        }

        if ((size_t)index > maxindex(this->height)) {
            return NULL;
        }

        RadixTreeNode *node = this->root;
        uint8_t h = this->height;

        while (h > 0) {
            size_t shift = h * RADIXTREESHIFT;
            size_t slot = (index >> shift) & RADIXTREEMASK;

            if (!node->slots[slot]) {
                return NULL;
            }
            node = (RadixTreeNode *)node->slots[slot];
            h--;
        }

        size_t slot = index & RADIXTREEMASK;
        return (CachePage *)node->slots[slot];
    }

    CachePage *RadixTree::remove(off_t index) {
        NLib::ScopeIRQSpinlock guard(&this->treelock);

        if (!this->root) {
            return NULL;
        }

        if ((size_t)index > maxindex(this->height)) {
            return NULL;
        }

        // Track path for cleanup.
        RadixTreeNode *path[16];
        size_t slots[16];
        int depth = 0;

        RadixTreeNode *node = this->root;
        uint8_t h = this->height;

        while (h > 0) {
            size_t shift = h * RADIXTREESHIFT;
            size_t slot = (index >> shift) & RADIXTREEMASK;

            if (!node->slots[slot]) {
                return NULL;
            }
            path[depth] = node;
            slots[depth] = slot;
            depth++;

            node = (RadixTreeNode *)node->slots[slot];
            h--;
        }

        size_t slot = index & RADIXTREEMASK;
        CachePage *page = (CachePage *)node->slots[slot];
        if (!page) {
            return NULL;
        }

        node->slots[slot] = NULL;
        node->count--;

        // Clean up empty nodes.
        while (depth > 0 && node->count == 0) {
            delete node;
            depth--;
            path[depth]->slots[slots[depth]] = NULL;
            path[depth]->count--;
            node = path[depth];
        }

        if (this->root->count == 0) {
            delete this->root;
            this->root = NULL;
            this->height = 0;
        }

        return page;
    }

    void RadixTree::foreach(bool (*callback)(CachePage *, void *), void *ctx) {
        NLib::ScopeIRQSpinlock guard(&this->treelock);

        if (!this->root) {
            return;
        }

        // Simple recursive traversal using stack.
        struct stackentry {
            RadixTreeNode *node;
            size_t slot;
        };
        stackentry stack[16];
        int sp = 0;

        stack[sp].node = this->root;
        stack[sp].slot = 0;

        while (sp >= 0) {
            RadixTreeNode *node = stack[sp].node;
            size_t slot = stack[sp].slot;

            // Find next non-null slot.
            while (slot < RADIXTREESLOTS && !node->slots[slot]) {
                slot++;
            }

            if (slot >= RADIXTREESLOTS) {
                // Done with this node.
                sp--;
                if (sp >= 0) {
                    stack[sp].slot++;
                }
                continue;
            }

            stack[sp].slot = slot;

            if (node->height > 0) {
                // Descend.
                sp++;
                stack[sp].node = (RadixTreeNode *)node->slots[slot];
                stack[sp].slot = 0;
            } else {
                // Leaf, call callback.
                CachePage *page = (CachePage *)node->slots[slot];
                if (!callback(page, ctx)) {
                    return;
                }
                stack[sp].slot++;
            }
        }
    }

    size_t RadixTree::foreachcollect(CachePage **out, size_t maxcount, bool (*filter)(CachePage *, void *), void *ctx, off_t *resumeindex) {
        NLib::ScopeIRQSpinlock guard(&this->treelock);

        if (!this->root || maxcount == 0) {
            if (resumeindex) {
                *resumeindex = -1;
            }
            return 0;
        }

        size_t collected = 0;
        off_t startindex = resumeindex ? *resumeindex : 0;
        if (startindex < 0) {
            startindex = 0;
        }

        // Simple recursive traversal using stack.
        struct stackentry {
            RadixTreeNode *node;
            size_t slot;
            off_t baseindex; // Base index for this node level.
        };
        stackentry stack[16];
        int sp = 0;

        stack[sp].node = this->root;
        stack[sp].slot = 0;
        stack[sp].baseindex = 0;

        while (sp >= 0) {
            RadixTreeNode *node = stack[sp].node;
            size_t slot = stack[sp].slot;
            off_t baseindex = stack[sp].baseindex;

            // Find next non-null slot.
            while (slot < RADIXTREESLOTS && !node->slots[slot]) {
                slot++;
            }

            if (slot >= RADIXTREESLOTS) {
                // Done with this node.
                sp--;
                if (sp >= 0) {
                    stack[sp].slot++;
                }
                continue;
            }

            stack[sp].slot = slot;

            // Calculate index contribution from this slot.
            size_t shift = node->height * RADIXTREESHIFT;
            off_t slotindex = baseindex + ((off_t)slot << shift);

            if (node->height > 0) {
                // Check if we can skip this entire subtree (all indices < startindex).
                off_t subtreemax = slotindex + ((off_t)1 << shift) - 1;
                if (subtreemax < startindex) {
                    stack[sp].slot++;
                    continue;
                }

                // Descend.
                sp++;
                stack[sp].node = (RadixTreeNode *)node->slots[slot];
                stack[sp].slot = 0;
                stack[sp].baseindex = slotindex;
            } else {
                // Leaf level.
                off_t pageindex = slotindex;

                // Skip if before resume point.
                if (pageindex < startindex) {
                    stack[sp].slot++;
                    continue;
                }

                CachePage *page = (CachePage *)node->slots[slot];

                // Apply filter if provided.
                if (!filter || filter(page, ctx)) {
                    // Take a reference before returning.
                    page->ref();
                    out[collected++] = page;

                    if (collected >= maxcount) {
                        // Set resume index to next page.
                        if (resumeindex) {
                            *resumeindex = pageindex + 1;
                        }
                        return collected;
                    }
                }

                stack[sp].slot++;
            }
        }

        // Finished iterating, no more pages.
        if (resumeindex) {
            *resumeindex = -1;
        }
        return collected;
    }

    PageCache::PageCache(void) { }

    PageCache::~PageCache(void) {
        this->shutdown();
    }

    void PageCache::init(size_t maxpages, size_t targetfree) {
        this->maxpages = maxpages;
        this->targetfreepages = targetfree;


        NUtil::printf("[mm/pagecache]: Page cache initialized with max %lu pages.\n", maxpages);
    }

    void PageCache::shutdown(void) {
        // Signal writeback thread to stop.
        __atomic_store_n(&this->running, false, memory_order_release);

        // Wait for writeback thread to exit (if running).
        if (this->wbthread) {
            waitevent(&this->exitwq, __atomic_load_n(&this->exited, memory_order_acquire));
        }

        // Sync all dirty pages before shutdown.
        this->syncall();

        NUtil::printf("[mm/pagecache]: Page cache shut down.\n");
    }

    void PageCache::addtoactive(CachePage *page) {
        page->lruprev = NULL;
        page->lrunext = this->activehead;
        if (this->activehead) {
            this->activehead->lruprev = page;
        }
        this->activehead = page;
        if (!this->activetail) {
            this->activetail = page;
        }
        page->lrulist = LRU_ACTIVE;
        this->activecount++;
    }

    void PageCache::addtoinactive(CachePage *page) {
        page->lruprev = NULL;
        page->lrunext = this->inactivehead;
        if (this->inactivehead) {
            this->inactivehead->lruprev = page;
        }
        this->inactivehead = page;
        if (!this->inactivetail) {
            this->inactivetail = page;
        }
        page->lrulist = LRU_INACTIVE;
        this->inactivecount++;
    }

    void PageCache::removefromlru(CachePage *page) {
        // Use tracked list membership for efficient removal.
        if (page->lrulist == LRU_NONE) {
            return; // Not in any list.
        }

        // Update prev/next pointers.
        if (page->lruprev) {
            page->lruprev->lrunext = page->lrunext;
        }
        if (page->lrunext) {
            page->lrunext->lruprev = page->lruprev;
        }

        // Update head/tail and count based on tracked list membership.
        if (page->lrulist == LRU_ACTIVE) {
            if (this->activehead == page) {
                this->activehead = page->lrunext;
            }
            if (this->activetail == page) {
                this->activetail = page->lruprev;
            }
            if (this->activecount > 0) {
                this->activecount--;
            }
        } else if (page->lrulist == LRU_INACTIVE) {
            if (this->inactivehead == page) {
                this->inactivehead = page->lrunext;
            }
            if (this->inactivetail == page) {
                this->inactivetail = page->lruprev;
            }
            if (this->inactivecount > 0) {
                this->inactivecount--;
            }
        }

        page->lruprev = NULL;
        page->lrunext = NULL;
        page->lrulist = LRU_NONE;
    }

    void PageCache::promotepage(CachePage *page) {
        // Move from inactive to active (MRU position).
        removefromlru(page);
        addtoactive(page);
    }

    void PageCache::demotepage(CachePage *page) {
        // Move from active to inactive.
        removefromlru(page);
        addtoinactive(page);
    }

    CachePage *PageCache::selectvictim(void) {
        // Shrimple second-chance LRU clock algorithm.

        CachePage *candidate = this->inactivetail;
        while (candidate) {
            if (candidate->testflag(PAGE_LOCKED | PAGE_WRITEBACK)) {
                // Skip locked or writeback pages.
                candidate = candidate->lruprev;
                continue;
            }

            if (candidate->testflag(PAGE_REFERENCED)) {
                // Give second chance.
                candidate->clearflag(PAGE_REFERENCED);
                promotepage(candidate);
                candidate = this->inactivetail;
                continue;
            }

            return candidate;
        }

        // Try active list if inactive is empty.
        candidate = this->activetail;
        while (candidate) {
            if (candidate->testflag(PAGE_LOCKED | PAGE_WRITEBACK)) {
                candidate = candidate->lruprev;
                continue;
            }

            if (candidate->testflag(PAGE_REFERENCED)) {
                candidate->clearflag(PAGE_REFERENCED);
                // Move to head (MRU).
                removefromlru(candidate);
                addtoactive(candidate);
                candidate = this->activetail;
                continue;
            }

            // Demote to inactive for future eviction.
            demotepage(candidate);
            return candidate;
        }

        return NULL;
    }

    int PageCache::evictpage(CachePage *page) {
        if (page->testflag(PAGE_DIRTY)) { // Dirty pages should be written back before evicting (so we don't end up losing data).
            int err = writebackpage(page);
            if (err < 0) {
                return err;
            }
        }

        // Remove from owning radix tree to prevent dangling pointers.
        off_t index = page->offset / NArch::PAGESIZE;
        if (page->inode) {
            RadixTree *cache = page->inode->getpagecache();
            if (cache) {
                cache->remove(index);
            }
        } else if (page->blockdev) {
            RadixTree *cache = page->blockdev->getpagecache();
            if (cache) {
                cache->remove(index);
            }
        }

        // Remove from LRU (requires cachelock).
        {
            NLib::ScopeIRQSpinlock guard(&this->cachelock);
            removefromlru(page);
            this->totalpages--;
        }

        // Free the physical page.
        if (page->pagemeta) {
            page->pagemeta->flags &= ~NArch::PMM::PageMeta::PAGEMETA_PAGECACHE;
            page->pagemeta->cacheentry = NULL;
        }
        if (page->physaddr) {
            NArch::PMM::free((void *)page->physaddr, NArch::PAGESIZE);
        }

        // Release reference to inode or blockdev to allow them to be freed.
        if (page->inode) {
            page->inode->unref();
        }

        delete page;
        return 0;
    }

    int PageCache::writebackpage(CachePage *page) {
        if (!page->testflag(PAGE_DIRTY)) {
            return 0;
        }

        // Set writeback flag.
        page->setflag(PAGE_WRITEBACK);

        ssize_t result = -EINVAL;

        if (page->inode) {
            // Inode-backed page: write via inode.
            NFS::VFS::INode *inode = page->inode;
            result = inode->writepage(page);
            if (result == 0) {
                result = NArch::PAGESIZE; // writepage returns 0 on success
            }
        } else if (page->blockdev) {
            // Block device page: write via block device.
            NDev::BlockDevice *dev = page->blockdev;
            int err = dev->writepagedata(page->data(), page->offset);
            result = (err < 0) ? err : NArch::PAGESIZE;
        } else {
            // Anonymous pages don't have backing store.
            page->clearflag(PAGE_WRITEBACK);
            return -EINVAL;
        }

        page->clearflag(PAGE_WRITEBACK);

        if (result < 0) {
            page->errorcount++;
            if (page->errorcount >= 10) {
                page->setflag(PAGE_ERROR);
            }
            return (int)result;
        }

        page->markclean();
        page->errorcount = 0;
        return 0;
    }

    CachePage *PageCache::findpage(NFS::VFS::INode *inode, off_t offset) {
        if (!inode) {
            return NULL;
        }

        // Page-align the offset.
        off_t pageoffset = (offset / NArch::PAGESIZE) * NArch::PAGESIZE;
        off_t index = pageoffset / NArch::PAGESIZE;

        // Look up in inode's page cache.
        RadixTree *cache = inode->getpagecache();
        if (!cache) {
            this->cachemisses++;
            return NULL;
        }

        CachePage *page = cache->lookup(index);
        if (page) {
            this->cachehits++;
            page->pagelock();
            return page;
        }

        this->cachemisses++;
        return NULL;
    }

    CachePage *PageCache::findorcreate(NFS::VFS::INode *inode, off_t offset) {
        if (!inode) {
            return NULL;
        }

        // Delegate to inode's getorcacheepage which properly handles the per-inode radix tree.
        CachePage *page = inode->getorcacheepage(offset);
        if (page) {
            // Page is returned locked by getorcacheepage.
            return page;
        }

        this->cachemisses++;
        return NULL;
    }

    int PageCache::addpage(CachePage *page) {
        if (!page) {
            return -EINVAL;
        }

        NLib::ScopeIRQSpinlock guard(&this->cachelock);

        addtoactive(page);
        this->totalpages++;

        // Check if we need to evict.
        if (this->maxpages > 0 && this->totalpages > this->maxpages) {
            // Trigger async reclaim rather than blocking.
            // For now, just warn.
            // TODO: Wake up reclaim thread.
        }

        return 0;
    }

    void PageCache::removepage(CachePage *page) {
        if (!page) {
            return;
        }

        NLib::ScopeIRQSpinlock guard(&this->cachelock);

        removefromlru(page);
        this->totalpages--;

        if (page->testflag(PAGE_DIRTY)) {
            this->dirtypages--;
        }
    }

    ssize_t PageCache::read(NFS::VFS::INode *inode, void *buf, size_t count, off_t offset) {
        if (!inode || !buf || count == 0) {
            return -EINVAL;
        }

        ssize_t totalread = 0;
        uint8_t *dest = (uint8_t *)buf;

        while (count > 0) {
            off_t pageoffset = (offset / NArch::PAGESIZE) * NArch::PAGESIZE;
            size_t offwithinpage = offset % NArch::PAGESIZE;
            size_t toread = NArch::PAGESIZE - offwithinpage;
            if (toread > count) {
                toread = count;
            }

            // Find or create the page.
            CachePage *page = findorcreate(inode, offset);
            if (!page) {
                if (totalread > 0) {
                    return totalread;
                }
                return -ENOMEM;
            }

            // If page is not up to date, read from backing store.
            if (!page->testflag(PAGE_UPTODATE)) {
                // Read from inode.
                ssize_t readresult = inode->read(page->data(), NArch::PAGESIZE, pageoffset, 0);
                if (readresult < 0) {
                    page->pageunlock();
                    if (totalread > 0) {
                        return totalread;
                    }
                    return readresult;
                }
                // Zero rest of page if partial read.
                if ((size_t)readresult < NArch::PAGESIZE) {
                    NLib::memset((uint8_t *)page->data() + readresult, 0, NArch::PAGESIZE - readresult);
                }
                page->setflag(PAGE_UPTODATE);
            }

            // Copy data to user buffer.
            NLib::memcpy(dest, (uint8_t *)page->data() + offwithinpage, toread);

            page->setflag(PAGE_REFERENCED);
            page->pageunlock();

            dest += toread;
            offset += toread;
            count -= toread;
            totalread += toread;
        }

        return totalread;
    }

    ssize_t PageCache::write(NFS::VFS::INode *inode, const void *buf, size_t count, off_t offset) {
        if (!inode || !buf || count == 0) {
            return -EINVAL;
        }

        ssize_t totalwritten = 0;
        const uint8_t *src = (const uint8_t *)buf;

        while (count > 0) {
            off_t pageoffset = (offset / NArch::PAGESIZE) * NArch::PAGESIZE;
            size_t offwithinpage = offset % NArch::PAGESIZE;
            size_t towrite = NArch::PAGESIZE - offwithinpage;
            if (towrite > count) {
                towrite = count;
            }

            // Find or create the page.
            CachePage *page = findorcreate(inode, offset);
            if (!page) {
                if (totalwritten > 0) {
                    return totalwritten;
                }
                return -ENOMEM;
            }

            // If partial page write and page not uptodate, need to read first.
            if (!page->testflag(PAGE_UPTODATE) && (offwithinpage != 0 || towrite < NArch::PAGESIZE)) {
                ssize_t readresult = inode->read(page->data(), NArch::PAGESIZE, pageoffset, 0);
                if (readresult < 0 && readresult != -ENOENT) {
                    page->pageunlock();
                    if (totalwritten > 0) {
                        return totalwritten;
                    }
                    return readresult;
                }
                if (readresult >= 0) {
                    if ((size_t)readresult < NArch::PAGESIZE) {
                        NLib::memset((uint8_t *)page->data() + readresult, 0, NArch::PAGESIZE - readresult);
                    }
                } else {
                    // New page, zero it.
                    NLib::memset(page->data(), 0, NArch::PAGESIZE);
                }
            }

            // Copy data from user buffer.
            NLib::memcpy((uint8_t *)page->data() + offwithinpage, (void *)src, towrite);

            page->setflag(PAGE_UPTODATE);
            page->markdirty();
            page->pageunlock();

            src += towrite;
            offset += towrite;
            count -= towrite;
            totalwritten += towrite;
        }

        return totalwritten;
    }

    int PageCache::syncnode(NFS::VFS::INode *inode) {
        if (!inode) {
            return -EINVAL;
        }

        // Use the inode's synccache method which iterates through its radix tree.
        return inode->synccache();
    }

    int PageCache::syncall(void) {
        // Write back all dirty pages using collect-then-process pattern.
        int errors = 0;

        static constexpr size_t MAXBATCH = 64;
        CachePage *batch[MAXBATCH];
        size_t count;

        // Collect dirty pages from active list.
        do {
            count = 0;
            {
                NLib::ScopeIRQSpinlock guard(&this->cachelock);

                CachePage *page = this->activehead;
                while (page && count < MAXBATCH) {
                    CachePage *next = page->lrunext;
                    if (page->testflag(PAGE_DIRTY) && !page->testflag(PAGE_WRITEBACK)) {
                        page->ref();
                        batch[count++] = page;
                    }
                    page = next;
                }
            }

            // Process batch outside of lock.
            for (size_t i = 0; i < count; i++) {
                CachePage *page = batch[i];
                if (page->trypagelock()) {
                    if (page->testflag(PAGE_DIRTY)) {
                        int err = writebackpage(page);
                        if (err < 0) {
                            errors++;
                        }
                    }
                    page->pageunlock();
                }
                page->unref();
            }
        } while (count >= MAXBATCH);

        // Collect dirty pages from inactive list.
        do {
            count = 0;
            {
                NLib::ScopeIRQSpinlock guard(&this->cachelock);

                CachePage *page = this->inactivehead;
                while (page && count < MAXBATCH) {
                    CachePage *next = page->lrunext;
                    if (page->testflag(PAGE_DIRTY) && !page->testflag(PAGE_WRITEBACK)) {
                        page->ref();
                        batch[count++] = page;
                    }
                    page = next;
                }
            }

            // Process batch outside of lock.
            for (size_t i = 0; i < count; i++) {
                CachePage *page = batch[i];
                if (page->trypagelock()) {
                    if (page->testflag(PAGE_DIRTY)) {
                        int err = writebackpage(page);
                        if (err < 0) {
                            errors++;
                        }
                    }
                    page->pageunlock();
                }
                page->unref();
            }
        } while (count >= MAXBATCH);

        return errors;
    }

    void PageCache::writebackthread(void) {
        NUtil::printf("[mm/pagecache]: Writeback thread started.\n");

        while (this->isrunning()) {
            // Wait for either timeout or explicit wakeup.
            NSched::sleep(WRITEBACKINTERVALMS);

            if (!this->isrunning()) {
                break;
            }

            // Write back dirty pages using collect-then-process pattern.
            size_t written = 0;

            static constexpr size_t BATCHSIZE = 32;
            CachePage *batch[BATCHSIZE];
            size_t count;

            // Collect from active list.
            {
                NLib::ScopeIRQSpinlock guard(&this->cachelock);

                count = 0;
                CachePage *page = this->activehead;
                while (page && count < BATCHSIZE && written + count < MAXWRITEBACKPERCYCLE) {
                    CachePage *next = page->lrunext;
                    if (page->testflag(PAGE_DIRTY) && !page->testflag(PAGE_WRITEBACK)) {
                        page->ref();
                        batch[count++] = page;
                    }
                    page = next;
                }
            }

            // Process active batch outside of lock.
            for (size_t i = 0; i < count; i++) {
                CachePage *page = batch[i];
                if (page->trypagelock()) {
                    if (page->testflag(PAGE_DIRTY)) {
                        writebackpage(page);
                        written++;
                    }
                    page->pageunlock();
                }
                page->unref();
            }

            // Collect from inactive list if we haven't hit the limit.
            if (written < MAXWRITEBACKPERCYCLE) {
                {
                    NLib::ScopeIRQSpinlock guard(&this->cachelock);

                    count = 0;
                    CachePage *page = this->inactivehead;
                    while (page && count < BATCHSIZE && written + count < MAXWRITEBACKPERCYCLE) {
                        CachePage *next = page->lrunext;
                        if (page->testflag(PAGE_DIRTY) && !page->testflag(PAGE_WRITEBACK)) {
                            page->ref();
                            batch[count++] = page;
                        }
                        page = next;
                    }
                }

                // Process inactive batch outside of lock.
                for (size_t i = 0; i < count; i++) {
                    CachePage *page = batch[i];
                    if (page->trypagelock()) {
                        if (page->testflag(PAGE_DIRTY)) {
                            writebackpage(page);
                            written++;
                        }
                        page->pageunlock();
                    }
                    page->unref();
                }
            }

            if (written > 0) {
                NUtil::printf("[mm/pagecache]: Wrote back %lu dirty pages.\n", written);
            }
        }

        NUtil::printf("[mm/pagecache]: Writeback thread exiting.\n");
        this->signalexit();
    }

    // Static wrapper for thread entry point.
    static void writebackthreadentry(void *arg) {
        PageCache *cache = (PageCache *)arg;
        cache->writebackthread();
        NSched::exit(0);
    }

    void PageCache::startwritebackthread(void) {
        if (this->wbthread) {
            return; // Already started.
        }

        // Create kernel thread for writeback.
        this->wbthread = new NSched::Thread(NSched::kprocess, NSched::DEFAULTSTACKSIZE, (void *)writebackthreadentry, (void *)this);
        if (!this->wbthread) {
            NUtil::printf("[mm/pagecache]: Failed to create writeback thread!\n");
            return;
        }

        // Schedule the thread.
        NSched::schedulethread(this->wbthread);
        NUtil::printf("[mm/pagecache]: Writeback thread scheduled.\n");
    }

    void PageCache::wakewriteback(void) {
        // Wake writeback thread if it's sleeping.
        this->wakeupwq.wake();
    }

    size_t PageCache::shrink(size_t count) {
        // Use collect-then-process pattern to avoid holding cachelock during I/O.
        static constexpr size_t BATCHSIZE = 16;
        CachePage *batch[BATCHSIZE];
        size_t freed = 0;

        while (freed < count) {
            size_t collected = 0;

            // Collect victim pages.
            {
                NLib::ScopeIRQSpinlock guard(&this->cachelock);
                while (collected < BATCHSIZE && freed + collected < count) {
                    CachePage *victim = selectvictim();
                    if (!victim) {
                        break;
                    }
                    victim->ref();
                    batch[collected++] = victim;
                }
            }

            if (collected == 0) {
                break; // We can't free any more pages.
            }

            // Evict collected pages outside of lock.
            for (size_t i = 0; i < collected; i++) {
                CachePage *page = batch[i];
                if (page->trypagelock()) {
                    int err = evictpage(page);
                    if (err == 0) {
                        freed++;
                        // Page is now deleted.
                    } else {
                        // Eviction failed, page still valid.
                        page->pageunlock();
                        page->unref();
                    }
                } else {
                    // Couldn't lock page, skip it.
                    page->unref();
                }
            }
        }

        return freed;
    }

    void PageCache::reclaim(void) {
        // Called under memory pressure.
        size_t targetfree = this->targetfreepages;
        if (targetfree == 0) {
            targetfree = 16; // Default.
        }

        size_t current = this->totalpages;
        if (this->maxpages > 0 && current > this->maxpages - targetfree) { // We NEED to evict to keep our limits.
            size_t toevict = current - (this->maxpages - targetfree);
            shrink(toevict);
        }
    }

    int PageCache::invalidatepage(NFS::VFS::INode *inode, off_t offset) {
        if (!inode) {
            return -EINVAL;
        }

        off_t pageoffset = (offset / NArch::PAGESIZE) * NArch::PAGESIZE;
        off_t index = pageoffset / NArch::PAGESIZE;

        RadixTree *cache = inode->getpagecache();
        if (!cache) {
            return 0; // No cache, nothing to invalidate.
        }

        CachePage *page = cache->lookup(index);
        if (!page) {
            return 0; // Page not cached.
        }

        // Lock the page.
        page->pagelock();

        // If dirty, write it back first (we don't want to lose data).
        if (page->testflag(PAGE_DIRTY)) {
            writebackpage(page);
        }

        // Remove from cache and LRU.
        cache->remove(index);
        {
            NLib::ScopeIRQSpinlock guard(&this->cachelock);
            removefromlru(page);
            this->totalpages--;
        }

        // Free physical page.
        if (page->pagemeta) {
            page->pagemeta->flags &= ~NArch::PMM::PageMeta::PAGEMETA_PAGECACHE;
            page->pagemeta->cacheentry = NULL;
        }
        if (page->physaddr) {
            NArch::PMM::free((void *)page->physaddr, NArch::PAGESIZE);
        }

        // Release reference to inode.
        if (page->inode) {
            page->inode->unref();
        }

        delete page;
        return 0;
    }

    int PageCache::invalidateinode(NFS::VFS::INode *inode) {
        if (!inode) {
            return -EINVAL;
        }

        RadixTree *cache = inode->getpagecache();
        if (!cache) {
            return 0; // No cache.
        }

        int errors = 0;

        // Callback to invalidate each page.
        struct invalidatectx {
            PageCache *pc;
            int errors;
        };

        struct invalidatectx ctx = { this, 0 };

        // We need to collect pages first since we can't modify tree during iteration.
        while (true) {
            CachePage *page = cache->lookup(0);
            // Walk tree to find any page.
            bool found = false;

            cache->foreach([](CachePage *page, void *arg) -> bool {
                CachePage **foundpage = (CachePage **)arg;
                *foundpage = page;
                return false; // Stop at first page.
            }, &page);

            if (!page) {
                break; // No more pages.
            }
            found = true;

            page->pagelock();

            // Write back if dirty.
            if (page->testflag(PAGE_DIRTY)) {
                int err = writebackpage(page);
                if (err < 0) {
                    errors++;
                }
            }

            off_t index = page->offset / NArch::PAGESIZE;
            cache->remove(index);

            {
                NLib::ScopeIRQSpinlock guard(&this->cachelock);
                removefromlru(page);
                this->totalpages--;
            }

            if (page->pagemeta) {
                page->pagemeta->flags &= ~NArch::PMM::PageMeta::PAGEMETA_PAGECACHE;
                page->pagemeta->cacheentry = NULL;
            }
            if (page->physaddr) {
                NArch::PMM::free((void *)page->physaddr, NArch::PAGESIZE);
            }

            // Release reference to inode.
            if (page->inode) {
                page->inode->unref();
            }

            delete page;

            if (!found) {
                break;
            }
        }

        return errors;
    }

    bool PageCache::shouldthrottle(void) const {
        if (this->maxpages == 0) {
            return false; // No limit.
        }

        size_t dirty = __atomic_load_n(&this->dirtypages, memory_order_acquire);
        size_t threshold = (this->maxpages * DIRTYTHRESHOLDPERCENT) / 100;

        return dirty > threshold;
    }

    void initpagecache(void) {
        pagecache = new PageCache();
        if (pagecache) {
            //pagecache->init(16384, 256); // 16k pages, but TRY to keep at least 256 free.
            pagecache->init(__SIZE_MAX__, 0); // Unlimited pages. XXX: Figure out how to actually manage this. Right now, it'll just keep claiming until OOM (and that's the only time we'll ever reclaim).
        }
    }

    void startpagecachethread(void) {
        if (pagecache) {
            pagecache->startwritebackthread();
        }
    }

    size_t reclaimcachepages(size_t count) {
        if (!pagecache) {
            return 0;
        }
        return pagecache->shrink(count);
    }

}
