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
#include <arch/x86_64/pmm.hpp>
#include <arch/x86_64/vmm.hpp>
#endif

#include <dev/block.hpp>
#include <fs/vfs.hpp>

namespace NMem {

    // Global page cache instance.
    PageCache *pagecache = NULL;

    // CachePage reference counting implementation.
    void CachePage::ref(void) {
        __atomic_add_fetch(&this->refcount, 1, memory_order_acq_rel);
    }

    void CachePage::unref(void) {
        int32_t newref = __atomic_sub_fetch(&this->refcount, 1, memory_order_acq_rel);
        assertarg(newref >= 0, "CachePage::unref: refcount went negative (%d)\n", newref);
        if (newref == 0) {
            // This was the last reference, delete the page.
            delete this;
        }
    }

    int32_t CachePage::getref(void) const {
        return __atomic_load_n(&this->refcount, memory_order_acquire);
    }

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

    void CachePage::waitio(void) {
        // Wait until IOINFLIGHT is clear. Caller must NOT hold the page lock.
        waitevent(&this->waitq, !(__atomic_load_n(&this->flags, memory_order_acquire) & PAGE_IOINFLIGHT));
    }

    void CachePage::signalio(void) {
        // Clear IOINFLIGHT and wake any waiters.
        uint16_t oldflags = __atomic_fetch_and(&this->flags, ~PAGE_IOINFLIGHT, memory_order_release);
        if (oldflags & PAGE_IOINFLIGHT) {
            this->waitq.wake();
        }
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

    void CachePage::addmapping(NArch::VMM::addrspace *space, uintptr_t virtaddr) {
        // Allocate a new mapping entry.
        vmamapping *mapping = new vmamapping(space, virtaddr);
        if (!mapping) {
            return; // OOM, mapping won't be tracked.
        }

        // Insert at head of mappings list.
        this->lock.acquire();
        mapping->next = this->mappingshead;
        mapping->prev = NULL;
        if (this->mappingshead) {
            this->mappingshead->prev = mapping;
        }
        this->mappingshead = mapping;
        this->mapcount++;
        this->lock.release();
    }

    void CachePage::removemapping(NArch::VMM::addrspace *space, uintptr_t virtaddr) {
        this->lock.acquire();
        vmamapping *m = this->mappingshead;
        while (m) {
            if (m->space == space && m->virtaddr == virtaddr) {
                // Found the mapping, remove it from the list.
                if (m->prev) {
                    m->prev->next = m->next;
                } else {
                    this->mappingshead = m->next;
                }
                if (m->next) {
                    m->next->prev = m->prev;
                }
                this->mapcount--;
                this->lock.release();
                delete m;
                return;
            }
            m = m->next;
        }
        this->lock.release();
    }

    size_t CachePage::unmapall(void) {
        // Unmap this page from all address spaces that have it mapped.
        // We collect mappings while holding page lock, then process without it to avoid lock order violation (page lock vs address space lock).
        static constexpr size_t BATCHSIZE = 32;
        vmamapping *batch[BATCHSIZE];
        size_t totalcount = 0;

        while (true) {
            size_t collected = 0;

            // Collect mappings under page lock.
            this->lock.acquire();
            vmamapping *m = this->mappingshead;
            while (m && collected < BATCHSIZE) {
                batch[collected++] = m;
                vmamapping *next = m->next;
                m = next;
            }

            // Remove collected mappings from list.
            if (collected > 0) {
                // Update head to point past collected items.
                vmamapping *last = batch[collected - 1];
                this->mappingshead = last->next;
                if (this->mapcount >= collected) {
                    this->mapcount -= collected;
                } else {
                    this->mapcount = 0;
                }
            }
            this->lock.release();

            if (collected == 0) {
                break; // No more mappings.
            }

            // Process collected mappings outside page lock.
            for (size_t i = 0; i < collected; i++) {
                vmamapping *mapping = batch[i];

                // Unmap from the address space.
                mapping->space->lock.acquire();
                NArch::VMM::_unmappage(mapping->space, mapping->virtaddr, false);
                mapping->space->lock.release();

                // Decrement the page's reference count (process no longer has it mapped).
                if (this->pagemeta) {
                    this->pagemeta->unref();
                }

                delete mapping;
                totalcount++;
            }
        }

#ifdef __x86_64__
        // Issue a full TLB shootdown since we may have unmapped from multiple address spaces.
        if (totalcount > 0) {
            NArch::VMM::doshootdown(NArch::VMM::SHOOTDOWN_FULL, 0, 0);
        }
#endif

        return totalcount;
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

    CachePage *RadixTree::lookupinternal(off_t index) {
        // Internal lookup without lock, caller must hold treelock.
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

    CachePage *RadixTree::lookup(off_t index) {
        NLib::ScopeIRQSpinlock guard(&this->treelock);
        return lookupinternal(index);
    }

    CachePage *RadixTree::lookupandlock(off_t index) {
        this->treelock.acquire();

        CachePage *page = lookupinternal(index);
        if (!page) {
            this->treelock.release();
            return NULL;
        }

        // Take a reference on the CachePage to prevent it from being deleted while we release the tree lock and try to acquire the page lock.
        page->ref();

        // Capture the generation counter to detect ABA (page evicted + memory reused).
        uint32_t gen = __atomic_load_n(&page->generation, memory_order_acquire);
        // Also ref the pagemeta to prevent physical page reclaim.
        if (page->pagemeta) {
            page->pagemeta->ref();
        }

        this->treelock.release();

        // Now lock the page. We hold refs so neither will be freed.
        page->pagelock();

        // Release the pagemeta ref (page lock now protects the physical page).
        if (page->pagemeta) {
            page->pagemeta->unref();
        }

        // Verify the page is still in this cache (not evicted while we were locking).
        // Check both that it's still at this index AND that generation hasn't changed
        // (to detect ABA problem where memory is reused for a different page).
        this->treelock.acquire();
        CachePage *verify = lookupinternal(index);
        uint32_t newgen = (verify == page) ? __atomic_load_n(&page->generation, memory_order_acquire) : 0;
        this->treelock.release();

        if (verify != page || newgen != gen) {
            // Page was evicted and possibly replaced, or memory was reused. Release and return NULL.
            page->pageunlock();
            page->unref();
            return NULL;
        }

        // Page is still valid. We keep the ref for the caller.
        // Caller MUST call page->unref() after page->pageunlock().
        return page;
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

        // Increment generation counter for ABA protection.
        __atomic_add_fetch(&page->generation, 1, memory_order_acq_rel);

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
                    // Take references before returning.
                    page->ref();  // CachePage ref for caller.
                    if (page->pagemeta) {
                        page->pagemeta->ref();  // Pagemeta ref for physical page protection.
                    }
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


        NUtil::printf("[mm/pagecache]: Page cache initialised with max %lu pages.\n", maxpages);
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
        // Dynamic iteration limit based on actual page count.
        size_t maxiters = (this->activecount + this->inactivecount) * 2;
        if (maxiters < 1024) {
            maxiters = 1024;
        }
        if (maxiters > 65536) {
            maxiters = 65536;
        }
        size_t iters = 0;
        bool restarted = false;

        CachePage *candidate = this->inactivetail;
        while (iters < maxiters) {
            // If we've reached the head, restart from tail for second pass.
            if (!candidate) {
                if (restarted) {
                    break;  // Already did second pass.
                }
                candidate = this->inactivetail;
                restarted = true;
                if (!candidate) {
                    break;  // List is empty.
                }
            }
            iters++;
            if (candidate->testflag(PAGE_LOCKED | PAGE_WRITEBACK)) {
                // Skip locked or writeback pages.
                candidate = candidate->lruprev;
                continue;
            }

            if (candidate->testflag(PAGE_REFERENCED)) {
                // Give second chance: clear flag but don't move.
                // Page stays in place, will be evictable on next scan.
                candidate->clearflag(PAGE_REFERENCED);
                candidate = candidate->lruprev;
                continue;
            }

            return candidate;
        }

        // Try active list if inactive is empty or exhausted.
        iters = 0;
        restarted = false;
        candidate = this->activetail;
        while (iters < maxiters) {
            if (!candidate) {
                if (restarted) {
                    break;
                }
                candidate = this->activetail;
                restarted = true;
                if (!candidate) {
                    break;
                }
            }
            iters++;
            if (candidate->testflag(PAGE_LOCKED | PAGE_WRITEBACK)) {
                candidate = candidate->lruprev;
                continue;
            }

            if (candidate->testflag(PAGE_REFERENCED)) {
                candidate->clearflag(PAGE_REFERENCED);
                CachePage *prev = candidate->lruprev;
                demotepage(candidate);
                candidate = prev ? prev : this->activetail;
                continue;
            }

            // Demote to inactive for future eviction.
            demotepage(candidate);
            return candidate;
        }

        return NULL;
    }

    CachePage *PageCache::selectvictimclean(selvictimstats *stats) {
        // Select a CLEAN victim page for eviction. Used by shrink() to avoid writeback stalls.
        // Dynamic iteration limit based on actual page count.
        size_t maxiters = (this->activecount + this->inactivecount) * 2;
        if (maxiters < 1024) {
            maxiters = 1024;
        }
        if (maxiters > 65536) {
            maxiters = 65536;
        }
        size_t iters = 0;
        bool restarted = false;

        CachePage *candidate = this->inactivetail;
        while (iters < maxiters) {
            // If we've reached the head, restart from tail for second pass.
            if (!candidate) {
                if (restarted) {
                    break;  // Already did second pass.
                }
                candidate = this->inactivetail;
                restarted = true;
                if (!candidate) {
                    break;  // List is empty.
                }
            }
            iters++;

            // Track skip reasons for diagnostics.
            if (candidate->testflag(PAGE_LOCKED)) {
                if (stats) {
                    stats->skippedlocked++;
                }
                candidate = candidate->lruprev;
                continue;
            }
            if (candidate->testflag(PAGE_IOINFLIGHT)) {
                if (stats) {
                    stats->skippedioinflight++;
                }
                candidate = candidate->lruprev;
                continue;
            }
            if (candidate->testflag(PAGE_WRITEBACK)) {
                if (stats) {
                    stats->skippedwriteback++;
                }
                candidate = candidate->lruprev;
                continue;
            }
            if (candidate->testflag(PAGE_DIRTY)) {
                if (stats) {
                    stats->skippeddirty++;
                }
                candidate = candidate->lruprev;
                continue;
            }

            if (candidate->testflag(PAGE_REFERENCED)) {
                // Give second chance: clear flag but don't move.
                if (stats) {
                    stats->skippedreferenced++;
                }
                candidate->clearflag(PAGE_REFERENCED);
                candidate = candidate->lruprev;
                continue;
            }

            return candidate;
        }

        // Try active list if inactive is empty or exhausted.
        iters = 0;
        restarted = false;
        candidate = this->activetail;
        while (iters < maxiters) {
            if (!candidate) {
                if (restarted) {
                    break;
                }
                candidate = this->activetail;
                restarted = true;
                if (!candidate) {
                    break;
                }
            }
            iters++;

            // Track skip reasons for diagnostics.
            if (candidate->testflag(PAGE_LOCKED)) {
                if (stats) {
                    stats->skippedlocked++;
                }
                candidate = candidate->lruprev;
                continue;
            }
            if (candidate->testflag(PAGE_IOINFLIGHT)) {
                if (stats) {
                    stats->skippedioinflight++;
                }
                candidate = candidate->lruprev;
                continue;
            }
            if (candidate->testflag(PAGE_WRITEBACK)) {
                if (stats) {
                    stats->skippedwriteback++;
                }
                candidate = candidate->lruprev;
                continue;
            }
            if (candidate->testflag(PAGE_DIRTY)) {
                if (stats) {
                    stats->skippeddirty++;
                }
                candidate = candidate->lruprev;
                continue;
            }

            if (candidate->testflag(PAGE_REFERENCED)) {
                // Demote to inactive tail instead of promoting to head.
                if (stats) {
                    stats->skippedreferenced++;
                }
                candidate->clearflag(PAGE_REFERENCED);
                CachePage *prev = candidate->lruprev;
                demotepage(candidate);
                candidate = prev ? prev : this->activetail;
                continue;
            }

            // Demote to inactive for future eviction.
            demotepage(candidate);
            return candidate;
        }

        return NULL;
    }

    int PageCache::evictpage(CachePage *page) {
        // Verify refcount contract in debug builds.
        assertarg(page->getref() >= 2, "evictpage: page refcount too low (%d), expected >= 2\n", page->getref());

        if (page->testflag(PAGE_DIRTY)) { // Dirty pages should be written back before evicting (so we don't end up losing data).
            int err = writebackpage(page);
            if (err < 0) {
                return err;
            }
        }

        if (page->hasmappings()) {
            page->unmapall(); // Unmap all mappings during eviction (programs still trying to use the previous mapping will end up triggering demand page to load the page back in).
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
            page->pagemeta->unref();  // Release initial cache ref (taken in addpage).
            page->pagemeta->unref();  // Release caller's collection ref.
        }

        // Release reference to inode (BlockDevice pages don't hold refs).
        if (page->inode) {
            page->inode->unref();
        }

        // Unlock page before final unref (unref may delete if refcount reaches 0).
        page->pageunlock();

        // Release caller's collection ref (taken in shrink collection phase).
        page->unref();

        // Release initial cache ref (taken in addpage). This may delete the page.
        page->unref();

        return 0;
    }

    void PageCache::evictpagefromwriteback(CachePage *page) {
        // Verify refcount contract in debug builds.
        assertarg(page->getref() >= 2, "evictpagefromwriteback: page refcount too low (%d), expected >= 2\n", page->getref());

        // Eviction logic that can perform blocking I/O (used by writeback thread).

        if (page->hasmappings()) {
            page->unmapall();
        }

        // Remove from owning radix tree.
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

        // Remove from LRU.
        {
            NLib::ScopeIRQSpinlock guard(&this->cachelock);
            removefromlru(page);
            this->totalpages--;
        }

        // Free the physical page.
        if (page->pagemeta) {
            page->pagemeta->flags &= ~NArch::PMM::PageMeta::PAGEMETA_PAGECACHE;
            page->pagemeta->cacheentry = NULL;
            page->pagemeta->unref();  // Release initial cache ref.
            page->pagemeta->unref();  // Release ref taken by writeback batch collection.
        }

        // Release reference to inode (BlockDevice pages don't hold refs).
        if (page->inode) {
            page->inode->unref();
        }

        // Unlock page before final unref.
        page->pageunlock();

        // Release caller's collection ref.
        page->unref();

        // Release initial cache ref. This may delete the page.
        page->unref();
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
            this->incmisses();
            return NULL;
        }

        CachePage *page = cache->lookupandlock(index);
        if (page) {
            // Mark page as recently accessed for LRU.
            page->setflag(PAGE_REFERENCED);

            // Promote from inactive to active on cache hit (second access).
            {
                NLib::ScopeIRQSpinlock guard(&this->cachelock);
                if (page->lrulist == LRU_INACTIVE) {
                    promotepage(page);
                }
            }

            this->inchits();
            return page;
        }

        this->incmisses();
        return NULL;
    }

    CachePage *PageCache::findorcreate(NFS::VFS::INode *inode, off_t offset) {
        if (!inode) {
            return NULL;
        }

        // Delegate to inode's getorcachepage which properly handles the per-inode radix tree.
        CachePage *page = inode->getorcachepage(offset);
        if (page) {
            // Page is returned locked by getorcachepage.
            return page;
        }

        this->incmisses();
        return NULL;
    }

    int PageCache::addpage(CachePage *page) {
        if (!page) {
            return -EINVAL;
        }

        // Take initial reference for being in the cache.
        page->ref();

        {
            NLib::ScopeIRQSpinlock guard(&this->cachelock);

            // New pages start in inactive list. They get promoted to active on second access (cache hit).
            addtoinactive(page);
            this->totalpages++;
        }


        // We RELY on the writeback thread to write back dirty pages periodically, as we can't synchronously write them back here (would cause deadlocks).
        // If we're over the limit, just wake the writeback thread.
        if (this->maxpages > 0 && this->totalpages > this->maxpages) {
            wakewriteback();
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
                        // Take refs on both CachePage and pagemeta to prevent deletion/reclaim.
                        page->ref();
                        if (page->pagemeta) {
                            page->pagemeta->ref();
                        }
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
                if (page->pagemeta) {
                    page->pagemeta->unref();
                }
                page->unref();  // Release collection ref.
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
                        // Take refs on both CachePage and pagemeta to prevent deletion/reclaim.
                        page->ref();
                        if (page->pagemeta) {
                            page->pagemeta->ref();
                        }
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
                if (page->pagemeta) {
                    page->pagemeta->unref();
                }
                page->unref();  // Release collection ref.
            }
        } while (count >= MAXBATCH);

        return errors;
    }

    void PageCache::writebackthread(void) {
        while (this->isrunning()) {
            // Clear the wakeup flag BEFORE waiting to avoid losing wakes.
            __atomic_store_n(&this->wakeupneeded, false, memory_order_release);

            // Wait until either:
            // 1. wakeupneeded flag is set (immediate wake from wakewriteback())
            // 2. Timeout expires (periodic writeback interval)
            // 3. Shutdown requested (!isrunning())
            int waitresult;
            waiteventtimeout(&this->wakeupwq,
                __atomic_load_n(&this->wakeupneeded, memory_order_acquire) || !this->isrunning(),
                WRITEBACKINTERVALMS,
                waitresult);
            // waitresult is 0 (woken by condition) or -ETIMEDOUT (periodic interval)
            (void)waitresult;  // We don't care which triggered the wake.

            bool wokeforthrottle = this->shouldthrottle();
            bool wakeforsoftthreshold = this->shouldwakewriteback();
            // Capture whether we're over the page limit at the START of the cycle.
            // This is used later to decide if we need to shrink for headroom.
            bool wasovertotallimit = (this->maxpages > 0 && this->totalpages > this->maxpages);

            if (!this->isrunning()) {
                break;
            }

            // Check if we're under memory pressure (over limit OR hard dirty threshold exceeded).
            bool underpressure = wasovertotallimit || wokeforthrottle;

            // Write back dirty pages using collect-then-process pattern.
            // Under pressure, remove the per-cycle limit to flush more aggressively.
            size_t maxpercycle = underpressure ? __SIZE_MAX__ : MAXWRITEBACKPERCYCLE;
            size_t written = 0;

            // Use larger batch size under pressure.
            size_t batchsize = underpressure ? BATCHSIZEPRESSURE : BATCHSIZENORMAL;
            CachePage *batch[BATCHSIZEPRESSURE]; // Allocate for max size.
            size_t count;

            // Collect from active list.
            {
                NLib::ScopeIRQSpinlock guard(&this->cachelock);

                count = 0;
                CachePage *page = this->activehead;
                while (page && count < batchsize && written + count < maxpercycle) {
                    CachePage *next = page->lrunext;
                    if (page->testflag(PAGE_DIRTY) && !page->testflag(PAGE_WRITEBACK) && !page->testflag(PAGE_LOCKED)) {
                        // Only take refs, NOT locks. We'll lock one at a time during processing.
                        page->ref();
                        if (page->pagemeta) {
                            page->pagemeta->ref();
                        }
                        batch[count++] = page;
                    }
                    page = next;
                }
            }

            // Process active batch outside of lock.
            // Lock one page at a time, write it, then unlock before moving to next.
            for (size_t i = 0; i < count; i++) {
                CachePage *page = batch[i];

                // Try to lock the page. If we can't, skip it.
                if (!page->trypagelock()) {
                    // Page is locked by someone else, skip.
                    page->unref();
                    if (page->pagemeta) {
                        page->pagemeta->unref();
                    }
                    continue;
                }

                // Re-check dirty flag after acquiring lock (page may have been cleaned).
                if (page->testflag(PAGE_DIRTY)) {
                    writebackpage(page);
                    written++;
                }

                // If under pressure and page is now clean, evict immediately.
                if (underpressure && !page->testflag(PAGE_DIRTY) && this->totalpages > this->maxpages) {
                    // Evict the page. evictpagefromwriteback handles unlock and unref.
                    evictpagefromwriteback(page);
                } else {
                    page->pageunlock();
                    page->unref();
                    if (page->pagemeta) {
                        page->pagemeta->unref();
                    }
                }
            }

            // Collect from inactive list if we haven't hit the limit.
            if (written < maxpercycle) {
                {
                    NLib::ScopeIRQSpinlock guard(&this->cachelock);

                    count = 0;
                    CachePage *page = this->inactivehead;
                    while (page && count < batchsize && written + count < maxpercycle) {
                        CachePage *next = page->lrunext;
                        if (page->testflag(PAGE_DIRTY) && !page->testflag(PAGE_WRITEBACK) && !page->testflag(PAGE_LOCKED)) {
                            // Only take refs, NOT locks. We'll lock one at a time during processing.
                            page->ref();
                            if (page->pagemeta) {
                                page->pagemeta->ref();
                            }
                            batch[count++] = page;
                        }
                        page = next;
                    }
                }

                // Process inactive batch outside of lock.
                // Lock one page at a time, write it, then unlock before moving to next.
                for (size_t i = 0; i < count; i++) {
                    CachePage *page = batch[i];

                    // Try to lock the page. If we can't, skip it.
                    if (!page->trypagelock()) {
                        // Page is locked by someone else, skip.
                        page->unref();
                        if (page->pagemeta) {
                            page->pagemeta->unref();
                        }
                        continue;
                    }

                    // Re-check dirty flag after acquiring lock (page may have been cleaned).
                    if (page->testflag(PAGE_DIRTY)) {
                        writebackpage(page);
                        written++;
                    }

                    // If under pressure and page is now clean, evict immediately.
                    if (underpressure && !page->testflag(PAGE_DIRTY) && this->totalpages > this->maxpages) {
                        // evictpagefromwriteback handles unlock and unref.
                        evictpagefromwriteback(page);
                    } else {
                        page->pageunlock();
                        page->unref();
                        if (page->pagemeta) {
                            page->pagemeta->unref();
                        }
                    }
                }
            }

            // After writeback, check if we need to shrink.
            // The writeback thread is a safe context for shrinking because:
            // 1. It's not in any I/O call chain
            // 2. shrink() only evicts clean pages, so no recursive I/O
            // 3. Even if shrink triggers some I/O, we're not holding any page locks

            // Also shrink if dirty ratio is high and we're near page limit (make room for new dirty pages).
            size_t dirtytarget = (this->maxpages * DIRTYTARGETPERCENT) / 100;
            bool overdirtytarget = this->dirtypages > dirtytarget;
            bool needshrink = wasovertotallimit ||
                              (this->maxpages > 0 && this->totalpages > this->maxpages) ||
                              (overdirtytarget && this->totalpages > (this->maxpages * 90) / 100);
            if (needshrink) {
                size_t target = this->targetfreepages > 0 ? this->targetfreepages : 16;
                size_t current = this->totalpages;
                size_t limit = this->maxpages;

                // Calculate how many to evict to get below the limit plus headroom.
                size_t toevict = current - limit + target;

                size_t freed = shrink(toevict);

                // If shrink didn't free enough, use aggressive writeback+shrink.
                // This writes back dirty pages and evicts them immediately.
                if (freed < toevict && this->totalpages > this->maxpages) {
                    size_t remaining = toevict - freed;
                    size_t morefreed = shrinkwithwriteback(remaining);
                    freed += morefreed;
                }

                // Wake any throttled writers now that we've freed pages.
                // Increment generation BEFORE wake so waiters see the change.
                if (freed > 0) {
                    __atomic_fetch_add(&this->throttlegeneration, 1, memory_order_release);
                    this->throttlewq.wake();
                }
            }

            // Also wake throttled writers if we wrote back dirty pages
            // (reduces dirty page count below threshold even without shrink).
            // Increment generation BEFORE wake so waiters see the change.
            if (written > 0) {
                __atomic_fetch_add(&this->throttlegeneration, 1, memory_order_release);
                this->throttlewq.wake();
            }

            // CRITICAL: Always increment generation and wake at end of each cycle.
            // This ensures waiters don't get stuck if writeback couldn't make progress
            // (e.g., all pages are locked, or no clean pages to evict).
            // The timeout in throttle() will retry, but we need to signal that we ran.
            // Only do this if we didn't already wake above.
            if (written == 0) {
                __atomic_fetch_add(&this->throttlegeneration, 1, memory_order_release);
                this->throttlewq.wake();
            }

        }

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
    }

    void PageCache::wakewriteback(void) {
        // Set flag and immediately wake the writeback thread.
        // The thread uses waiteventtimeout so it will wake immediately.
        __atomic_store_n(&this->wakeupneeded, true, memory_order_release);
        this->wakeupwq.wake();
    }

    size_t PageCache::shrink(size_t count) {
        // CRITICAL: Prevent recursive shrink calls.
        NSched::Thread *shrinkthread = NArch::CPU::get() ? NArch::CPU::get()->currthread : NULL;
        if (shrinkthread && shrinkthread->inshrink) {
            // Already in shrink in this thread, bail out to prevent recursion.
            return 0;
        }

        // Set recursion guard.
        if (shrinkthread) {
            shrinkthread->inshrink = true;
        }

        // Use collect-then-process pattern to avoid holding cachelock during I/O.
        // We lock each page during collection to prevent double-collection and
        // to ensure pages remain valid until we process them.
        static constexpr size_t BATCHSIZE = 16;
        static constexpr size_t MAX_LOCKED_RETRIES = 3;
        CachePage *batch[BATCHSIZE];
        size_t freed = 0;
        size_t lockedretries = 0;
        size_t loopiter = 0;

        while (freed < count) {
            loopiter++;
            if (loopiter > 1000) {
                break;
            }

            size_t collected = 0;
            struct selvictimstats stats = {};

            // Collect victim pages. Only collect CLEAN pages to avoid writeback during shrink.
            // Dirty pages will be handled by the writeback thread.
            // We lock each page during collection to prevent the same page being
            // collected twice and to ensure it remains valid.
            {
                NLib::ScopeIRQSpinlock guard(&this->cachelock);
                while (collected < BATCHSIZE && freed + collected < count) {
                    CachePage *victim = selectvictimclean(&stats);
                    if (!victim) {
                        break;
                    }
                    // Try to lock the page while holding cachelock.
                    // This prevents double-collection: locked pages are skipped by selectvictimclean.
                    if (!victim->trypagelock()) {
                        // Page is already locked, skip it.
                        continue;
                    }
                    // Take refs to keep page and pagemeta alive.
                    victim->ref();
                    if (victim->pagemeta) {
                        victim->pagemeta->ref();
                    }
                    batch[collected++] = victim;
                }
            }

            if (collected == 0) {
                // Check if we failed because pages exist but are locked.
                if ((stats.skippedlocked > 0 || stats.skippedioinflight > 0) && lockedretries < MAX_LOCKED_RETRIES) {
                    lockedretries++;
                    // Yield to let I/O threads complete.
                    NSched::yield();
                    continue;
                }
                break; // No more clean pages to free.
            }

            lockedretries = 0; // Reset on successful collection.

            // Evict collected pages outside of lock.
            // Pages are already locked from collection phase.
            for (size_t i = 0; i < collected; i++) {
                CachePage *page = batch[i];
                // Double-check page is still clean (may have been dirtied since collection).
                if (page->testflag(PAGE_DIRTY)) {
                    // Page became dirty, skip it.
                    page->pageunlock();
                    page->unref();
                    if (page->pagemeta) {
                        page->pagemeta->unref();
                    }
                    continue;
                }
                int err = evictpage(page);
                if (err == 0) {
                    freed++;
                    // Evict page handles unlock and unref.
                } else {
                    // Eviction failed, page still valid.
                    page->pageunlock();
                    page->unref();
                    if (page->pagemeta) {
                        page->pagemeta->unref();
                    }
                }
            }
        }

        // Clear recursion guard.
        if (shrinkthread) {
            shrinkthread->inshrink = false;
        }

        return freed;
    }

    size_t PageCache::shrinkwithwriteback(size_t count) {
        // First try clean-only shrink (fast, no I/O).
        size_t freed = shrink(count);
        if (freed >= count) {
            return freed;
        }

        // Clean-only shrink insufficient. Write back dirty pages and retry.
        // This is more aggressive and may block on I/O.
        static constexpr size_t MAXRETRIES = 3;
        static constexpr size_t BATCHSIZE = 32;
        CachePage *batch[BATCHSIZE];

        for (size_t retry = 0; retry < MAXRETRIES && freed < count; retry++) {
            size_t batchcount = 0;

            // Collect dirty pages from inactive list first (prefer cold pages).
            // Then scan active list if we didn't fill the batch.
            // Lock pages during collection and take refs.
            {
                NLib::ScopeIRQSpinlock guard(&this->cachelock);

                // First scan inactive list (cold pages preferred).
                CachePage *page = this->inactivetail;
                while (page && batchcount < BATCHSIZE) {
                    CachePage *prev = page->lruprev;
                    if (page->testflag(PAGE_DIRTY) && !page->testflag(PAGE_WRITEBACK)) {
                        // Lock page during collection to prevent double-collection.
                        if (!page->trypagelock()) {
                            page = prev;
                            continue;
                        }
                        page->ref();
                        if (page->pagemeta) {
                            page->pagemeta->ref();
                        }
                        batch[batchcount++] = page;
                    }
                    page = prev;
                }

                // If inactive list didn't fill the batch, also scan active list.
                // This handles the case where dirty pages have been promoted.
                if (batchcount < BATCHSIZE) {
                    page = this->activetail;
                    while (page && batchcount < BATCHSIZE) {
                        CachePage *prev = page->lruprev;
                        if (page->testflag(PAGE_DIRTY) && !page->testflag(PAGE_WRITEBACK)) {
                            if (!page->trypagelock()) {
                                page = prev;
                                continue;
                            }
                            page->ref();
                            if (page->pagemeta) {
                                page->pagemeta->ref();
                            }
                            batch[batchcount++] = page;
                        }
                        page = prev;
                    }
                }
            }

            if (batchcount == 0) {
                // No dirty pages to write.
                break;
            }

            // Write back the batch synchronously.
            // Pages are already locked from collection phase.
            for (size_t i = 0; i < batchcount; i++) {
                CachePage *page = batch[i];
                // Page is already locked from collection.
                if (page->testflag(PAGE_DIRTY)) {
                    writebackpage(page);
                }
                page->pageunlock();
                page->unref();
                if (page->pagemeta) {
                    page->pagemeta->unref();
                }
            }

            // Retry clean-only shrink.
            size_t morefreed = shrink(count - freed);
            freed += morefreed;
        }

        return freed;
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

        // Use lookupandlock to atomically look up and lock, preventing race with eviction.
        // lookupandlock takes a ref on the page for us.
        CachePage *page = cache->lookupandlock(index);
        if (!page) {
            return 0; // Page not cached.
        }

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

        // Free physical page via pagemeta unref.
        if (page->pagemeta) {
            page->pagemeta->flags &= ~NArch::PMM::PageMeta::PAGEMETA_PAGECACHE;
            page->pagemeta->cacheentry = NULL;
            page->pagemeta->unref();  // Release initial cache ref.
            page->pagemeta->unref();  // Release ref from lookupandlock.
        }

        // Release reference to inode (BlockDevice pages don't hold refs).
        if (page->inode) {
            page->inode->unref();
        }

        // Unlock page before final unref.
        page->pageunlock();

        // Release ref from lookupandlock.
        page->unref();

        // Release initial cache ref (from addpage). This may delete the page.
        page->unref();

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

        // We can't modify tree during iteration, so use foreach to find one page at a time and remove it. Repeat until no pages remain.
        while (true) {
            CachePage *foundpage = NULL;

            // Find first page in the cache.
            cache->foreach([](CachePage *page, void *arg) -> bool {
                CachePage **result = (CachePage **)arg;
                // Take a ref to keep the page alive.
                page->ref();
                *result = page;
                return false; // Stop at first page.
            }, &foundpage);

            if (!foundpage) {
                break; // No more pages.
            }

            // Lock the page. We hold a ref so page won't be freed.
            foundpage->pagelock();

            // Verify page is still in cache (may have been evicted while we waited for lock).
            off_t index = foundpage->offset / NArch::PAGESIZE;
            CachePage *check = cache->lookup(index);
            if (check != foundpage) {
                // Page was evicted, release our ref and continue.
                foundpage->pageunlock();
                foundpage->unref();
                continue;
            }

            // Write back if dirty.
            if (foundpage->testflag(PAGE_DIRTY)) {
                int err = writebackpage(foundpage);
                if (err < 0) {
                    errors++;
                }
            }

            cache->remove(index);

            {
                NLib::ScopeIRQSpinlock guard(&this->cachelock);
                removefromlru(foundpage);
                this->totalpages--;
            }

            // Free physical page via pagemeta unref.
            if (foundpage->pagemeta) {
                foundpage->pagemeta->flags &= ~NArch::PMM::PageMeta::PAGEMETA_PAGECACHE;
                foundpage->pagemeta->cacheentry = NULL;
                foundpage->pagemeta->unref();  // Release initial cache ref.
            }

            // Release reference to inode (BlockDevice pages don't hold refs).
            if (foundpage->inode) {
                foundpage->inode->unref();
            }

            // Unlock and release refs.
            foundpage->pageunlock();
            foundpage->unref();  // Release our lookup ref.
            foundpage->unref();  // Release initial cache ref. May delete page.
        }

        return errors;
    }

    bool PageCache::shouldthrottle(void) const {
        if (this->maxpages == 0) {
            return false; // No limit.
        }

        // Throttle if we're over the total page limit.
        size_t total = __atomic_load_n(&this->totalpages, memory_order_acquire);
        if (total > this->maxpages) {
            return true;
        }

        // Use hard threshold (50%) for blocking writers.
        size_t dirty = __atomic_load_n(&this->dirtypages, memory_order_acquire);
        size_t hardthreshold = (this->maxpages * DIRTYHARDTHRESHOLDPERCENT) / 100;

        return dirty > hardthreshold;
    }

    bool PageCache::shouldwakewriteback(void) const {
        if (this->maxpages == 0) {
            return false; // No limit.
        }

        // Wake writeback at soft threshold (25%), proactive writeback.
        size_t dirty = __atomic_load_n(&this->dirtypages, memory_order_acquire);
        size_t softthreshold = (this->maxpages * DIRTYSOFTTHRESHOLDPERCENT) / 100;

        return dirty > softthreshold;
    }

    void PageCache::throttle(void) {
        static constexpr uint64_t THROTTLETIMEOUTMS = 25;
        static constexpr size_t MAXNOPROGRESSCYCLES = 20;
        static constexpr size_t DIRECTRECLAIMBATCH = 16; // Pages to write back directly per cycle.

        size_t noprogresscycles = 0;

        // Keep waiting until we're no longer throttled or shutdown requested.
        // We don't have a retry limit - we MUST wait until pages are freed.
        while (this->shouldthrottle() && this->isrunning()) {
            // Capture state BEFORE signalling writeback thread.
            size_t startdirty = this->dirtypages;
            size_t startpages = this->totalpages;
            uint64_t startgen = __atomic_load_n(&this->throttlegeneration, memory_order_acquire);

            // First, try direct reclaim ourselves to avoid blocking on writeback thread.
            size_t reclaimed = this->directreclaim(DIRECTRECLAIMBATCH);
            if (reclaimed > 0) {
                // We made progress, check condition again immediately.
                noprogresscycles = 0;
                continue;
            }

            // Direct reclaim didn't help, wake the writeback thread.
            this->wakewriteback();

            // Wait until:
            // 1. No longer throttled (condition satisfied), OR
            // 2. Generation changed (writeback made progress, possibly before we entered wait), OR
            // 3. Shutdown requested, OR
            // 4. Timeout expires (fallback)
            int result;
            waiteventtimeout(&this->throttlewq,
                !this->shouldthrottle() ||
                !this->isrunning() ||
                __atomic_load_n(&this->throttlegeneration, memory_order_acquire) != startgen,
                THROTTLETIMEOUTMS,
                result);

            // Check for progress.
            if (this->shouldthrottle() && this->totalpages >= startpages && this->dirtypages >= startdirty) {
                noprogresscycles++;

                if (noprogresscycles >= MAXNOPROGRESSCYCLES) {
                    // Reset counter to avoid wasted comparisons, but keep trying.
                    noprogresscycles = 0;
                }
            } else {
                noprogresscycles = 0;
            }

            // If timeout expired and still throttled, just wake writeback again.
            if (result == -ETIMEDOUT && this->shouldthrottle()) {
                // Wake writeback more aggressively, it will handle shrinking.
                this->wakewriteback();
            }
        }
    }

    // Direct reclaim: write back dirty pages from the calling thread.
    size_t PageCache::directreclaim(size_t target) {
        static constexpr size_t BATCHSIZE = 16;
        CachePage *batch[BATCHSIZE];
        size_t written = 0;
        size_t toprocess = target < BATCHSIZE ? target : BATCHSIZE;

        // Collect dirty pages from inactive list (prefer cold pages).
        size_t collected = 0;
        {
            NLib::ScopeIRQSpinlock guard(&this->cachelock);

            CachePage *page = this->inactivetail;
            while (page && collected < toprocess) {
                CachePage *prev = page->lruprev;
                if (page->testflag(PAGE_DIRTY) && !page->testflag(PAGE_WRITEBACK) && !page->testflag(PAGE_LOCKED)) {
                    if (page->trypagelock()) {
                        page->ref();
                        if (page->pagemeta) {
                            page->pagemeta->ref();
                        }
                        batch[collected++] = page;
                    }
                }
                page = prev;
            }

            // If inactive didn't fill batch, try active list.
            if (collected < toprocess) {
                page = this->activetail;
                while (page && collected < toprocess) {
                    CachePage *prev = page->lruprev;
                    if (page->testflag(PAGE_DIRTY) && !page->testflag(PAGE_WRITEBACK) && !page->testflag(PAGE_LOCKED)) {
                        if (page->trypagelock()) {
                            page->ref();
                            if (page->pagemeta) {
                                page->pagemeta->ref();
                            }
                            batch[collected++] = page;
                        }
                    }
                    page = prev;
                }
            }
        }

        if (collected == 0) {
            return 0;
        }

        // Write back collected pages (already locked).
        for (size_t i = 0; i < collected; i++) {
            CachePage *page = batch[i];
            if (page->testflag(PAGE_DIRTY)) {
                int err = writebackpage(page);
                if (err == 0) {
                    written++;
                }
            }
            page->pageunlock();
            page->unref();
            if (page->pagemeta) {
                page->pagemeta->unref();
            }
        }

        // Signal progress to other throttled waiters.
        if (written > 0) {
            __atomic_fetch_add(&this->throttlegeneration, 1, memory_order_release);
            this->throttlewq.wake();
        }

        return written;
    }

    void initpagecache(void) {
        pagecache = new PageCache();
        if (pagecache) {
            // Scale page cache size based on total system memory.
            // Use ~33% of total RAM for page cache, with 64 MiB minimum.
            NArch::PMM::stats memstats;
            NArch::PMM::getstats(&memstats);

            size_t totalpages = memstats.buddytotal / NArch::PAGESIZE;
            size_t maxpages = totalpages / 3; // 33% of buddy split RAM.
            if (maxpages < 16384) {
                maxpages = 16384; // Minimum 64 MiB.
            }

            // Target keeping ~1.5% of maxpages free for headroom.
            size_t targetfree = maxpages / 64;
            if (targetfree < 64) {
                targetfree = 64;
            }

            pagecache->init(maxpages, targetfree);
            NUtil::printf("[mm/pagecache]: Page cache sized to %lu pages (%lu MiB), target free %lu.\n",
                         maxpages, (maxpages * NArch::PAGESIZE) / (1024 * 1024), targetfree);
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
        // First try clean-only shrink (fast, no I/O).
        size_t freed = pagecache->shrink(count);
        if (freed >= count) {
            return freed;
        }
        // Fall back to writeback-enabled shrink for remaining pages.
        // This is called from PMM under memory pressure, so blocking is acceptable.
        // XXX: Could possibly deadlock if called with interrupts disabled?
        return freed + pagecache->shrinkwithwriteback(count - freed);
    }

}
