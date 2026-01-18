#ifdef __x86_64__
#include <arch/x86_64/cpu.hpp>
#endif
#include <dev/block.hpp>
#include <fs/pipefs.hpp>
#include <fs/vfs.hpp>
#include <lib/align.hpp>
#include <lib/errno.hpp>
#include <mm/pagecache.hpp>
#include <mm/ucopy.hpp>
#include <sched/workqueue.hpp>
#include <sys/clock.hpp>
#include <sys/syscall.hpp>
#include <util/kprint.hpp>

namespace NFS {
    namespace VFS {
        VFS *vfs = NULL;

        NMem::RadixTree *INode::getpagecache(void) {
            NLib::ScopeIRQSpinlock guard(&this->metalock);
            if (!this->pagecache) {
                this->pagecache = new NMem::RadixTree();
            }
            return this->pagecache;
        }

        NMem::CachePage *INode::findcachedpage(off_t offset) {
            NMem::RadixTree *cache = this->getpagecache();
            if (!cache) {
                return NULL;
            }

            off_t index = offset / NArch::PAGESIZE;
            NMem::CachePage *page = cache->lookup(index);
            if (page) {
                page->pagelock();
            }
            return page;
        }

        NMem::CachePage *INode::getorcacheepage(off_t offset) {
            NMem::RadixTree *cache = this->getpagecache();
            if (!cache) {
                return NULL;
            }

            off_t pageoffset = (offset / NArch::PAGESIZE) * NArch::PAGESIZE;
            off_t index = pageoffset / NArch::PAGESIZE;

            // Check if page already exists.
            NMem::CachePage *page = cache->lookup(index);
            if (page) {
                page->pagelock();
                return page;
            }

            // Allocate new page.
            page = new NMem::CachePage();
            if (!page) {
                return NULL;
            }

            // Allocate physical page.
            void *phys = NArch::PMM::alloc(NArch::PAGESIZE);
            if (!phys) {
                delete page;
                return NULL;
            }

            page->physaddr = (uintptr_t)phys;
            page->pagemeta = NArch::PMM::phystometa((uintptr_t)phys);
            if (page->pagemeta) {
                page->pagemeta->flags |= NArch::PMM::PageMeta::PAGEMETA_PAGECACHE;
                page->pagemeta->cacheentry = page;
                page->pagemeta->ref();
            }

            page->inode = this;
            page->offset = pageoffset;
            page->flags = 0;

            // Hold a reference to the inode to prevent it from being freed while the page exists.
            this->ref();

            // Try to insert into radix tree.
            int err = cache->insert(index, page);
            if (err == -EEXIST) {
                if (page->pagemeta) {
                    page->pagemeta->flags &= ~NArch::PMM::PageMeta::PAGEMETA_PAGECACHE;
                    page->pagemeta->cacheentry = NULL;
                    page->pagemeta->unref();
                }
                // Release inode reference since we're discarding this page.
                this->unref();
                NArch::PMM::free(phys, NArch::PAGESIZE);
                delete page;

                page = cache->lookup(index);
                if (page) {
                    page->pagelock();
                }
                return page;
            } else if (err < 0) {
                // Allocation failure in radix tree.
                if (page->pagemeta) {
                    page->pagemeta->flags &= ~NArch::PMM::PageMeta::PAGEMETA_PAGECACHE;
                    page->pagemeta->cacheentry = NULL;
                    page->pagemeta->unref();
                }
                // Release inode reference since we're discarding this page.
                this->unref();
                NArch::PMM::free(phys, NArch::PAGESIZE);
                delete page;
                return NULL;
            }

            // Add to global page cache LRU.
            if (NMem::pagecache) {
                NMem::pagecache->addpage(page);
            }

            page->pagelock();
            return page;
        }

        void INode::invalidatecache(void) {
            NMem::RadixTree *cache = this->pagecache;
            if (!cache) {
                return;
            }

            // Use collect-then-process pattern to avoid blocking on pagelock
            // while holding treelock.
            static constexpr size_t BATCHSIZE = 32;
            NMem::CachePage *batch[BATCHSIZE];
            off_t resumeindex = 0;
            size_t count;

            // Collect all pages (no filter needed).
            while ((count = cache->foreachcollect(batch, BATCHSIZE, nullptr, nullptr, &resumeindex)) > 0) {
                // Process pages outside of treelock.
                for (size_t i = 0; i < count; i++) {
                    NMem::CachePage *page = batch[i];
                    page->pagelock();

                    // Remove from radix tree.
                    off_t index = page->offset / NArch::PAGESIZE;
                    cache->remove(index);

                    // Remove from global cache.
                    if (NMem::pagecache) {
                        NMem::pagecache->removepage(page);
                    }

                    // Free physical page.
                    if (page->pagemeta) {
                        page->pagemeta->flags &= ~NArch::PMM::PageMeta::PAGEMETA_PAGECACHE;
                        page->pagemeta->cacheentry = NULL;
                        page->pagemeta->unref();
                    }
                    if (page->physaddr) {
                        NArch::PMM::free((void *)page->physaddr, NArch::PAGESIZE);
                    }

                    // Release reference to inode.
                    if (page->inode) {
                        page->inode->unref();
                    }

                    page->pageunlock();
                    page->unref();  // Release ref from foreachcollect.
                    delete page;
                }

                if (resumeindex < 0) {
                    break;
                }
            }

            delete cache;
            this->pagecache = NULL;
        }

        int INode::synccache(void) {
            NMem::RadixTree *cache = this->pagecache;
            if (!cache) {
                return 0;
            }

            // Use collect-then-process pattern to avoid holding treelock during I/O.
            static constexpr size_t MAX_BATCH = 32;
            NMem::CachePage *collected[MAX_BATCH];
            NMem::CachePage *batch[MAX_BATCH];
            size_t batchcount = 0;
            off_t batchstart = -1;
            int errors = 0;

            // Filter for dirty pages that are not already being written back.
            auto dirtyfilter = [](NMem::CachePage *page, void *) -> bool {
                return page->testflag(NMem::PAGE_DIRTY) &&
                       !page->testflag(NMem::PAGE_WRITEBACK);
            };

            off_t resumeindex = 0;
            size_t count;

            // Iterate in batches, releasing treelock between batches.
            while ((count = cache->foreachcollect(collected, MAX_BATCH, dirtyfilter, nullptr, &resumeindex)) > 0) {
                for (size_t i = 0; i < count; i++) {
                    NMem::CachePage *page = collected[i];

                    // Try to lock the page. If we can't, skip it.
                    if (!page->trypagelock()) {
                        page->unref();
                        continue;
                    }

                    // Re-check dirty flag after acquiring page lock.
                    if (!page->testflag(NMem::PAGE_DIRTY)) {
                        page->pageunlock();
                        page->unref();
                        continue;
                    }

                    off_t pageoff = page->offset;

                    // Check if page is contiguous with current batch.
                    bool contiguous = (batchcount > 0) && (pageoff == batchstart + (off_t)(batchcount * NArch::PAGESIZE));

                    if (!contiguous && batchcount > 0) {
                        // Flush current batch.
                        ssize_t res = this->writepages(batch, batchcount);
                        if (res < 0) {
                            errors++;
                        }
                        // Unlock and unref flushed pages.
                        for (size_t j = 0; j < batchcount; j++) {
                            batch[j]->pageunlock();
                            batch[j]->unref();
                        }
                        batchcount = 0;
                    }

                    // Start new batch if empty.
                    if (batchcount == 0) {
                        batchstart = pageoff;
                    }

                    batch[batchcount] = page;
                    batchcount++;

                    // Flush if batch is full.
                    if (batchcount >= MAX_BATCH) {
                        ssize_t res = this->writepages(batch, batchcount);
                        if (res < 0) {
                            errors++;
                        }
                        for (size_t j = 0; j < batchcount; j++) {
                            batch[j]->pageunlock();
                            batch[j]->unref();
                        }
                        batchcount = 0;
                    }
                }

                // If resumeindex is -1, we've finished iterating.
                if (resumeindex < 0) {
                    break;
                }
            }

            // Flush remaining pages.
            if (batchcount > 0) {
                ssize_t res = this->writepages(batch, batchcount);
                if (res < 0) {
                    errors++;
                }
                for (size_t i = 0; i < batchcount; i++) {
                    batch[i]->pageunlock();
                    batch[i]->unref();
                }
            }

            return errors;
        }

        // Read ahead context.
        struct readaheadwork {
            struct NSched::work work;
            INode *inode;              // Inode to readahead (refcounted).
            off_t rastart;             // Starting offset for readahead.
            size_t npages;             // Number of pages to readahead.

            NMem::CachePage *pages[32]; // Pages being read ahead (max 32).
        };

        // Callback for async readahead I/O completion.
        static void readaheadbiocomplete(struct NDev::bioreq *req) {
            NMem::CachePage *page = (NMem::CachePage *)req->udata;

            if (req->status == 0) {
                page->setflag(NMem::PAGE_UPTODATE);
                page->clearflag(NMem::PAGE_ERROR);
            } else {
                page->setflag(NMem::PAGE_ERROR);
                page->errorcount++;
            }

            // Release page lock (was held since getorcacheepage).
            page->pageunlock();

            // Free the bioreq.
            delete req;
        }

        // Worker function that performs the actual readahead I/O.
        static void readaheadworker(struct NSched::work *w) {
            struct readaheadwork *ctx = (struct readaheadwork *)w;
            INode *inode = ctx->inode;
            off_t rastart = ctx->rastart;
            size_t npages = ctx->npages;

            // Get backing block device.
            NDev::BlockDevice *blkdev = inode->getblockdevice();
            if (!blkdev) {
                inode->unref();
                delete ctx;
                return;
            }

            size_t blksize = blkdev->blksize;
            size_t blocksperpage = NArch::PAGESIZE / blksize;

            // Check if block device supports native async I/O.
            bool asyncio = blkdev->hasasyncio();

            // If using sync fallback, limit pages to avoid blocking worker too long.
            if (!asyncio && npages > 4) {
                npages = 4;
            }

            for (size_t i = 0; i < npages; i++) {
                off_t pageoff = rastart + i * NArch::PAGESIZE;

                // Check if already cached (skip if present or in-flight).
                NMem::RadixTree *cache = inode->getpagecache();
                if (cache) {
                    NMem::CachePage *existing = cache->lookup(pageoff / NArch::PAGESIZE);
                    if (existing) {
                        continue; // Already present or being fetched.
                    }
                }

                // Allocate and insert new page.
                NMem::CachePage *page = inode->getorcacheepage(pageoff);
                if (!page) {
                    continue; // Allocation failed.
                }

                // If already up-to-date (race), skip.
                if (page->testflag(NMem::PAGE_UPTODATE)) {
                    page->pageunlock();
                    continue;
                }

                // Try to get LBA from extent cache only (non-blocking). If not cached, skip this page to avoid blocking on extent tree I/O.
                bool needsio = false;
                uint64_t lba = inode->getpagelbacached(pageoff, &needsio);
                if (needsio) {
                    page->pageunlock();
                    continue;
                }

                if (lba == 0) {
                    // Hole in file.
                    NLib::memset(page->data(), 0, NArch::PAGESIZE);
                    page->setflag(NMem::PAGE_UPTODATE);
                    page->pageunlock();
                    continue;
                }

                struct NDev::bioreq *req = new NDev::bioreq();
                req->init(blkdev, NDev::bioreq::BIO_READ, lba, blocksperpage, page->data(), NArch::PAGESIZE);
                req->callback = readaheadbiocomplete;
                req->udata = page; // Store page for completion callback.

                int res = blkdev->submitbio(req);
                if (res < 0) {
                    page->setflag(NMem::PAGE_ERROR);
                    page->pageunlock();
                    delete req;
                }
            }

            // Release inode reference and free work context.
            inode->unref();
            delete ctx;
        }

        void INode::readahead(off_t offset) {
            // Only readahead for regular files.
            if (!S_ISREG(this->attr.st_mode)) {
                return;
            }

            // Get backing block device (quick check, no I/O).
            NDev::BlockDevice *blkdev = this->getblockdevice();
            if (!blkdev) {
                return; // No block device (e.g., ramfs).
            }

            off_t lastoff = __atomic_load_n(&this->ralastoffset, memory_order_acquire);
            size_t cursize = __atomic_load_n(&this->rasize, memory_order_acquire);

            // Check if access is sequential: within expected window of last offset.
            bool sequential = (lastoff >= 0 &&
                               offset >= lastoff &&
                               offset <= lastoff + (off_t)((cursize + 1) * NArch::PAGESIZE));

            // Update last offset.
            __atomic_store_n(&this->ralastoffset, offset, memory_order_release);

            if (!sequential) {
                __atomic_store_n(&this->rasize, 0, memory_order_release);
                return;
            }

            // Grow readahead window (double each time, up to max).
            size_t newsize = (cursize == 0) ? RA_INITPAGES : cursize * 2;
            if (newsize > RA_MAXPAGES) {
                newsize = RA_MAXPAGES;
            }
            __atomic_store_n(&this->rasize, newsize, memory_order_release);

            // Calculate readahead range (start from next page after current).
            off_t rastart = (offset + NArch::PAGESIZE) & ~((off_t)NArch::PAGESIZE - 1);
            off_t filesize = __atomic_load_n(&this->attr.st_size, memory_order_acquire);
            if (rastart >= filesize) {
                return;
            }

            // Cap pages to not exceed EOF.
            size_t maxpages = (filesize - rastart + NArch::PAGESIZE - 1) / NArch::PAGESIZE;
            size_t npages = newsize;
            if (npages > maxpages) {
                npages = maxpages;
            }
            if (npages == 0) {
                return;
            }

            // Allocate work context.
            struct readaheadwork *ctx = new struct readaheadwork;
            if (!ctx) {
                return;
            }

            // Take inode reference for async work.
            this->ref();

            NSched::initwork(&ctx->work, readaheadworker);

            ctx->inode = this;
            ctx->rastart = rastart;
            ctx->npages = npages;

            // The actual I/O will happen in a worker thread.
            if (!vfs->readaheadwq->queue(&ctx->work)) {
                // Failed to queue, clean up.
                this->unref();
                delete ctx;
            }
        }

        ssize_t INode::readcached(void *buf, size_t count, off_t offset) {
            if (!buf || count == 0) {
                return -EINVAL;
            }

            // Check file size and adjust count to not read past EOF.
            uint64_t filesize;
            {
                NLib::ScopeIRQSpinlock guard(&this->metalock);
                filesize = this->attr.st_size;
            }

            if ((uint64_t)offset >= filesize) {
                return 0; // EOF, nothing to read.
            }

            if ((uint64_t)(offset + count) > filesize) {
                count = filesize - offset; // Clamp to remaining bytes.
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

                // Trigger readahead if applicable.
                this->readahead(offset);

                // Get or create page.
                NMem::CachePage *page = this->getorcacheepage(offset);
                if (!page) {
                    if (totalread > 0) {
                        return totalread;
                    }
                    return -ENOMEM;
                }

                // If page not up to date, we may need to wait for readahead or do sync read.
                if (!page->testflag(NMem::PAGE_UPTODATE)) {
                    // Check if page has an error from a previous readahead attempt.
                    if (page->testflag(NMem::PAGE_ERROR)) {
                        // Clear error and retry with sync read.
                        page->clearflag(NMem::PAGE_ERROR);
                    }


                    // Do synchronous read to fill the page.
                    int err = this->readpage(page);
                    if (err < 0) {
                        page->pageunlock();
                        if (totalread > 0) {
                            return totalread;
                        }
                        return err;
                    }
                }

                // Copy data to user buffer.
                NLib::memcpy(dest, (uint8_t *)page->data() + offwithinpage, toread);

                page->setflag(NMem::PAGE_REFERENCED);
                page->pageunlock();

                dest += toread;
                offset += toread;
                count -= toread;
                totalread += toread;
            }

            return totalread;
        }

        ssize_t INode::writecached(const void *buf, size_t count, off_t offset) {
            if (!buf || count == 0) {
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

                // Get or create page.
                NMem::CachePage *page = this->getorcacheepage(offset);
                if (!page) {
                    if (totalwritten > 0) {
                        return totalwritten;
                    }
                    return -ENOMEM;
                }

                // If partial page write and page not up to date, fill it first.
                if (!page->testflag(NMem::PAGE_UPTODATE) && (offwithinpage != 0 || towrite < NArch::PAGESIZE)) {
                    int err = this->readpage(page);
                    if (err < 0 && err != -ENOENT) {
                        page->pageunlock();
                        if (totalwritten > 0) {
                            return totalwritten;
                        }
                        return err;
                    }
                    if (err == -ENOENT) { // Zero the page if it doesn't exist.
                        NLib::memset(page->data(), 0, NArch::PAGESIZE);
                    }
                }

                // Copy data from user buffer.
                NLib::memcpy((uint8_t *)page->data() + offwithinpage, (void *)src, towrite);

                page->setflag(NMem::PAGE_UPTODATE);
                page->markdirty();
                page->pageunlock();

                src += towrite;
                offset += towrite;
                count -= towrite;
                totalwritten += towrite;
            }

            return totalwritten;
        }

        int INode::readpage(NMem::CachePage *page) {
            (void)page;
            return -ENOSYS;
        }

        // Default implementation: call readpage() for each page sequentially.
        // Filesystems can override for better performance.
        int INode::readpages(NMem::CachePage **pages, size_t count) {
            int firsterr = 0;
            for (size_t i = 0; i < count; i++) {
                int err = this->readpage(pages[i]);
                if (err < 0 && firsterr == 0) {
                    firsterr = err; // Record first error but continue.
                }
            }
            return firsterr;
        }

        int INode::writepage(NMem::CachePage *page) {
            (void)page;
            return -ENOSYS;
        }

        // Default implementation is to just call writepage repeatedly.
        int INode::writepages(NMem::CachePage **pages, size_t count) {
            ssize_t written = 0;
            for (size_t i = 0; i < count; i++) {
                int err = this->writepage(pages[i]);
                if (err < 0) {
                    if (written > 0) {
                        return written;
                    }
                    return err;
                }
                written++;
            }
            return written;
        }

        int VFS::mount(const char *src, const char *path, const char *fs, uint64_t flags, const void *data) {

            if (!NLib::strcmp(fs, "auto")) {
                return this->identifyfs(src);
            }

            fsfactory_t *factory = NULL;
            {
                NLib::ScopeSpinlock guard(&this->mountlock);
                fsfactory_t **fsp = this->filesystems.find(fs);
                if (!fsp) {
                    return -ENODEV; // Filesystem not found.
                }
                factory = *fsp;
            }

            IFileSystem *filesystem = factory(this); // Create new filesystem instance.

            return this->mount(src, path, filesystem, flags, data);
        }

        int VFS::mount(const char *src, const char *_path, IFileSystem *fs, uint64_t flags, const void *data) {
            INode *mntnode = NULL;
            Path mntpath = Path(_path);

            // Mount paths must be absolute.
            if (!mntpath.isabsolute()) {
                return -EINVAL;
            }

            const char *path = mntpath.construct();

            // Resolve the mountpoint node (except for root mount).
            if (mntpath.depth() > 0) {
                ssize_t ret = this->resolve(path, &mntnode, NULL, true, NULL);
                if (ret < 0) {
                    delete[] path;
                    return ret; // Mountpoint doesn't exist.
                }

                // Ensure mountpoint is a directory.
                if (!S_ISDIR(mntnode->getattr().st_mode)) {
                    delete[] path;
                    mntnode->unref();
                    return -ENOTDIR;
                }
            }

            {
                NLib::ScopeSpinlock guard(&this->mountlock);
                // Check if there is a mountpoint on this specific path already. Findmount cannot be used here, as it finds the best match, not exact match.
                NLib::DoubleList<struct mntpoint>::Iterator it = this->mounts.begin();
                // Shadow path with mount path.
                for (; it.valid(); it.next()) {
                    if (!NLib::strcmp(it.get()->path, path)) {
                        if (mntnode) {
                            mntnode->unref();
                        }
                        delete[] path;
                        return -EBUSY; // Mountpoint already in use.
                    }
                }

            }
            if (mntpath.depth() > 0) {
                // Ensure we have permission to mount here.
                NSched::Process *proc = NArch::CPU::get()->currthread->process;
                proc->lock.acquire();
                bool access = this->checkaccess(mntnode, O_RDONLY | O_EXEC, proc->euid, proc->egid);
                proc->lock.release();
                if (!access) {
                    delete[] path;
                    mntnode->unref();
                    return -EACCES;
                }
            }

            {
                NLib::ScopeSpinlock guard(&this->mountlock);

                this->mounts.push((struct VFS::mntpoint) { NLib::strdup(path), fs, mntnode });

                if (!mntpath.depth() && !this->root) { // Attempt to assign root if we haven't already.
                    this->root = fs->getroot();
                }
            }

            if (fs->mount(src, path, mntnode, flags, data) != 0) {
                this->umount(path, 0); // Rollback mount on failure.
                if (mntnode) {
                    mntnode->unref();
                }
                delete[] path;
                return -EINVAL;
            }
            delete[] path;
            return 0;
        }

        int VFS::umount(const char *_path, int flags) {
            // Normalize and validate path.
            Path upath = Path(_path);

            // Umount paths must be absolute.
            if (!upath.isabsolute()) {
                return -EINVAL;
            }

            const char *path = upath.construct();

            // Prevent unmounting root filesystem.
            if (!NLib::strcmp(path, "/")) {
                delete[] path;
                return -EBUSY;
            }

            struct umount_ud {
                const char *match;
                const char *mntpath;
                IFileSystem *fs;
                INode *mntnode;
                size_t depth;
                bool found;
            } ud = { path, NULL, NULL, NULL, 0, false };

            {
                NLib::ScopeSpinlock guard(&this->mountlock);

                bool worked = this->mounts.remove([](struct mntpoint mnt, void *udata) {
                    struct umount_ud *u = (struct umount_ud *)udata;
                    if (!NLib::strcmp(mnt.path, u->match)) {
                        u->fs = mnt.fs;
                        u->mntpath = mnt.path; // Save path pointer for later deletion.
                        Path mntpath = Path(mnt.path);
                        u->mntnode = mnt.mntnode;
                        u->depth = mntpath.depth();
                        u->found = true;
                        return true;
                    }
                    return false;
                }, (void *)&ud);

                if (!ud.found) {
                    delete[] path;
                    return -EINVAL;
                }

                // Check if there are any child mounts under this path.
                // If so, the filesystem is busy and cannot be unmounted.
                Path umountpath = Path(ud.mntpath);
                size_t umountdepth = umountpath.depth();

                NLib::DoubleList<struct mntpoint>::Iterator it = this->mounts.begin();
                for (; it.valid(); it.next()) {
                    Path childpath = Path(it.get()->path);

                    // Check if this mount is a child of the mount being unmounted.
                    if (childpath.depth() > umountdepth) {
                        bool ischild = true;
                        NLib::DoubleList<const char *>::Iterator cit = childpath.iterator();
                        NLib::DoubleList<const char *>::Iterator uit = umountpath.iterator();

                        for (size_t i = 0; i < umountdepth; i++, cit.next(), uit.next()) {
                            if (NLib::strcmp(*cit.get(), *uit.get())) {
                                ischild = false;
                                break;
                            }
                        }

                        if (ischild) {
                            // Found a child mount, filesystem is busy.
                            // Reinsert the mount point.
                            this->mounts.push((struct VFS::mntpoint) { ud.mntpath, ud.fs, ud.mntnode });
                            delete[] path;
                            return -EBUSY;
                        }
                    }
                }

                // Check if the filesystem has any active usage.
                if (ud.fs && ud.fs->getfsrefcount() > 0) {
                    // Filesystem is busy, reinsert mount point.
                    this->mounts.push((struct VFS::mntpoint) { ud.mntpath, ud.fs, ud.mntnode });
                    delete[] path;
                    return -EBUSY;
                }

                // Check if the mount node itself has active references.
                if (ud.mntnode && ud.mntnode->getrefcount() > 1) {
                    // Mount point is busy, reinsert it.
                    this->mounts.push((struct VFS::mntpoint) { ud.mntpath, ud.fs, ud.mntnode });
                    delete[] path;
                    return -EBUSY;
                }

                if (!ud.depth && this->root) { // If this was the root mount, clear root reference.
                    this->root = NULL;
                }
            }

            // Call filesystem-specific umount (syncs, cleans up).
            if (ud.fs) {
                int ret = ud.fs->umount(flags);
                if (ret < 0) {
                    // Failed to unmount, reinsert mount point.
                    NLib::ScopeSpinlock guard(&this->mountlock);
                    this->mounts.push((struct VFS::mntpoint) { ud.mntpath, ud.fs, ud.mntnode });
                    if (!ud.depth && !this->root) {
                        this->root = ud.mntnode;
                    }
                    delete[] path;
                    return ret;
                }
                // Filesystem umount succeeded, now delete the filesystem object.
                delete ud.fs;
            }

            // Free the mount path string.
            if (ud.mntpath) {
                delete[] ud.mntpath;
            }

            // Unref the mount node.
            if (ud.mntnode) {
                ud.mntnode->unref();
            }

            delete[] path;
            return 0;
        }

        struct VFS::mntpoint *VFS::_findmount(Path *path) {
            // Find the best matching mount point for the given path.
            // The best matching mount point is the one with the longest matching prefix.
            // However, we must consider mounting points shadowed by others.

            struct mntpoint *best = NULL;
            size_t depth = 0;

            NLib::DoubleList<struct mntpoint>::Iterator it = this->mounts.begin();

            for (; it.valid(); it.next()) {
                Path mntpath = Path(it.get()->path);
                bool matches = true;
                NLib::DoubleList<const char *>::Iterator mpit = mntpath.iterator();
                NLib::DoubleList<const char *>::Iterator pit = path->iterator();

                size_t i = 0;
                for (; i < mntpath.depth(); pit.next(), mpit.next(), i++) {
                    if (i >= path->depth() || NLib::strcmp(*mpit.get(), *pit.get())) {
                        matches = false;
                        break;
                    }
                }

                if (!mntpath.depth() && mntpath.isabsolute() && path->isabsolute()) {
                    matches = true;
                }

                if (matches && mntpath.depth() >= depth) {
                    best = it.get();
                    depth = mntpath.depth();
                }
            }

            return best;
        }

        struct VFS::mntpoint *VFS::_findmountbynode(INode *node) {
            // Used during path traversal to detect mount point crossings.
            NLib::DoubleList<struct mntpoint>::Iterator it = this->mounts.begin();
            for (; it.valid(); it.next()) {
                if (it.get()->mntnode == node) {
                    return it.get();
                }
            }
            return NULL;
        }

        struct VFS::mntpoint *VFS::findmount(Path *path) {
            NLib::ScopeSpinlock guard(&this->mountlock);
            return this->_findmount(path);
        }

        struct VFS::mntpoint *VFS::findmountbynode(INode *node) {
            NLib::ScopeSpinlock guard(&this->mountlock);
            return this->_findmountbynode(node);
        }

        ssize_t VFS::resolve(const char *path, INode **nodeout, INode *relativeto, bool symlink, INode *procroot) {
            constexpr size_t MAX_SYMLINK_DEPTH = 40;

            Path rp = Path(path);

            // Determine the effective root for this resolution.
            INode *effroot = procroot ? procroot : this->root;

            if (!rp.depth()) { // Empty path or root path.
                if (rp.isabsolute()) { // Absolute path refers to root.
                    if (!effroot) {
                        return -ENOENT;
                    }
                    effroot->ref();
                    *nodeout = effroot;
                    return 0;
                } else { // Empty relative path refers to current directory.
                    INode *result = relativeto ? relativeto : effroot;
                    if (result) {
                        result->ref(); // Caller expects a referenced node.
                    } else {
                        return -ENOENT;
                    }

                    *nodeout = result;
                    return 0;
                }
                return 0;
            }

            if (!rp.isabsolute()) {
                INode *base = relativeto ? relativeto : effroot;

                // Prepend elements to construct an absolute path.
                while (base && base != effroot) {
                    INode *parent = base->getparent();

                    if (!parent) {
                        // We've hit a filesystem root. Find where this filesystem is mounted.
                        struct mntpoint *mnt = NULL;
                        NLib::DoubleList<struct mntpoint>::Iterator mit = this->mounts.begin();
                        for (; mit.valid(); mit.next()) {
                            if (mit.get()->fs->getroot() == base) {
                                mnt = mit.get();
                                break;
                            }
                        }

                        if (mnt && mnt->mntnode) {
                            // Found the mount point. Continue from the mount directory.
                            Path mntpath = Path(mnt->path);
                            // Prepend mount path components in reverse order.
                            NLib::DoubleList<const char *>::Iterator pit = mntpath.iterator();
                            // Collect components first, then prepend in reverse.
                            const char *comps[64]; // Reasonable max depth.
                            size_t ncomps = 0;
                            for (; pit.valid() && ncomps < 64; pit.next()) {
                                comps[ncomps++] = *pit.get();
                            }
                            // Prepend in reverse order (deepest first was collected first).
                            for (size_t i = ncomps; i > 0; i--) {
                                rp.pushcomponent(comps[i-1], false);
                            }
                            break;
                        } else {
                            // No mount found or at VFS root, stop.
                            break;
                        }
                    } else {
                        const char *name = base->getname();
                        if (name && *name) {
                            rp.pushcomponent(name, false);
                        }
                        base = parent;
                    }
                }

                rp.setabsolute();
            }

            const char *rpstr = rp.construct();
            Path pobj = Path(rpstr); // Forcibly collapse resultant path.
            delete[] rpstr;

            INode *current = NULL;
            size_t skip = 0;

            if (procroot) {
                // For any path in a chroot, start from procroot.
                current = procroot;
                current->ref();
                skip = 0; // Don't skip any components, traverse from procroot.
            } else {
                struct mntpoint *mount = this->findmount(&pobj);
                if (!mount) {
                    return -ENOENT; // Path is invalid. No mountpoint handles this path.
                }

                Path mntpath = Path(mount->path);
                skip = mntpath.depth(); // How many components of the main path should we skip to just get the path relative to the mount path?

                current = mount->fs->getroot();
            }

            NLib::DoubleList<const char *>::Iterator it = pobj.iterator();
            for (size_t i = 0; i < skip && it.valid(); i++) {
                it.next(); // Skip over components relevant to the mount path.
            }

            size_t symlink_depth = 0; // Track symlink resolution depth to prevent infinite loops.

            while (it.valid()) {

                if (!NLib::strcmp(*it.get(), "..")) {
                    INode *parent = current->getparent();

                    // Stop at the per-process root boundary to enforce chroot confinement.
                    if (!parent || current == effroot) {
                        // Stay at current if we're at the effective root.
                        it.next();
                        continue;
                    }

                    parent->ref(); // Increment refcount for parent.
                    current->unref(); // Unreference old current.
                    current = parent;
                    it.next();
                    continue;
                }

                // Check that we have search permission on the current node.
                if (!this->checkaccess(current, O_RDONLY | O_EXEC, 0, 0)) {
                    current->unref();
                    return -EACCES;
                }

                INode *next = current->lookup(*it.get());
                current->unref(); // Unreference old

                if (!next) {
                    return -ENOENT;
                }

                // Chroot precaution, ensure we cross mount points correctly.
                struct mntpoint *crossedmount = this->findmountbynode(next);
                if (crossedmount) {
                    // Switch from the underlying directory to the mounted filesystem's root.
                    next->unref();
                    next = crossedmount->fs->getroot();
                }

                it.next();
                current = next;
                if (symlink && S_ISLNK(current->getattr().st_mode)) { // If this node is a symbolic link.
                    if (symlink_depth >= MAX_SYMLINK_DEPTH) {
                        current->unref();
                        return -ELOOP; // Too many levels of symbolic links.
                    }
                    INode *resolved = current->resolvesymlink();
                    if (!resolved) {
                        current->unref();
                        return -ENOENT; // Invalid symbolic link.
                    }
                    current->unref(); // Unreference the symlink node.
                    current = resolved; // Resolved already has refcount from resolvesymlink.
                    symlink_depth++;

                    while (!it.valid() && S_ISLNK(current->getattr().st_mode)) {
                        if (symlink_depth >= MAX_SYMLINK_DEPTH) {
                            current->unref();
                            return -ELOOP; // Too many levels of symbolic links.
                        }
                        INode *nextresolved = current->resolvesymlink();
                        if (!nextresolved) {
                            current->unref();
                            return -ENOENT;
                        }
                        current->unref();
                        current = nextresolved;
                        symlink_depth++;
                    }
                }
            }

            if (!current) {
                return -ENOENT;
            }

            // Special handling for named pipes (FIFOs).
            if (current->getredirect()) {
                INode *redirected = current->getredirect();
                current->unref();
                current = redirected; // Follow redirect.
            }

            *nodeout = current;
            return 0;
        }

        ssize_t VFS::create(const char *path, INode **nodeout, struct stat attr, INode *relativeto, INode *procroot) {
            Path pobj = Path(path);

            if (!pobj.depth()) {
                return -EINVAL; // Cannot create root.
            }

            // Convert to absolute path if relative, same as resolve() does.
            if (!pobj.isabsolute()) {
                INode *base = relativeto ? relativeto : this->root;

                // Prepend elements to construct an absolute path.
                while (base && base != this->root) {
                    pobj.pushcomponent(base->getname(), false);
                    base = base->getparent();
                }

                pobj.setabsolute();
            }

            // Reconstruct to collapse any ".." components properly.
            const char *pobjstr = pobj.construct();
            Path abspobj = Path(pobjstr);
            delete[] pobjstr;

            // Check if path already exists.
            INode *existing = NULL;
            ssize_t res = this->resolve(path, &existing, relativeto, false, procroot);
            if (res == 0) {
                existing->unref();
                return -EEXIST; // Path already exists.
            }

            const char *parentpath = abspobj.dirname();
            INode *parent;
            res = this->resolve(parentpath, &parent, relativeto, true, procroot);
            delete parentpath; // Caller is expected to free `dirname()`.
            if (res < 0) {
                return res; // Parent doesn't already exist.
            }

            struct mntpoint *mount = this->findmount(&abspobj);
            if (!mount) {
                parent->unref(); // Don't leak parent reference.
                return -ENOENT; // Invalid mounting point.
            }

            INode *node = NULL;
            res = mount->fs->create(abspobj.basename(), &node, attr);
            if (res < 0) {
                parent->unref();
                return res; // Creation failed.
            }
            parent->add(node);
            parent->unref();

            node->ref(); // Increment refcount before returning, matching resolve() contract.
            *nodeout = node;
            return 0;
        }

        int VFS::unlink(const char *path, INode *relativeto, int flags, int uid, int gid, INode *procroot) {
            Path pobj = Path(path);

            if (!pobj.depth()) {
                return -EINVAL; // Cannot unlink root.
            }

            INode *node = NULL;
            ssize_t res = this->resolve(path, &node, relativeto, false, procroot);
            if (res < 0) {
                return res; // Failed to resolve path.
            }

            // Get parent directory.
            INode *parent = node->getparent();
            if (!parent) {
                node->unref();
                return -EINVAL; // Cannot unlink root node.
            }
            parent->ref();

            // Check if we're trying to unlink a directory.
            struct stat st = node->getattr();
            if (S_ISDIR(st.st_mode)) {
                if (!(flags & AT_REMOVEDIR)) {
                    // Trying to unlink a directory without AT_REMOVEDIR flag.
                    parent->unref();
                    node->unref();
                    return -EISDIR;
                }
                if (!node->empty()) {
                    // Directory is not empty.
                    parent->unref();
                    node->unref();
                    return -ENOTEMPTY;
                }
            } else {
                if (flags & AT_REMOVEDIR) {
                    // AT_REMOVEDIR specified but target is not a directory.
                    parent->unref();
                    node->unref();
                    return -ENOTDIR;
                }
            }

            if (!this->checkaccess(parent, O_RDWR | O_EXEC, uid, gid)) {
                parent->unref();
                node->unref();
                return -EACCES; // No write/search permission on parent directory.
            }

            // Call filesystem-specific unlink, it handles unreferencing our references to node and parent.
            int ret = node->fs->unlink(node, parent);

            return ret;
        }

        int VFS::rename(const char *oldpath, INode *oldrelativeto, const char *newpath, INode *newrelativeto, int uid, int gid, INode *procroot) {
            Path oldpobj = Path(oldpath);
            Path newpobj = Path(newpath);

            if (!oldpobj.depth()) {
                return -EINVAL; // Cannot rename root.
            }
            if (!newpobj.depth()) {
                return -EINVAL; // Cannot rename to root.
            }

            // Resolve the source node (without following final symlink).
            INode *srcnode = NULL;
            ssize_t res = this->resolve(oldpath, &srcnode, oldrelativeto, false, procroot);
            if (res < 0) {
                return res; // Failed to resolve source.
            }

            // Get source parent directory.
            INode *srcparent = srcnode->getparent();
            if (!srcparent) {
                srcnode->unref();
                return -EINVAL; // Cannot rename root node.
            }
            srcparent->ref();

            // Check write permission on source parent.
            if (!this->checkaccess(srcparent, O_RDWR | O_EXEC, uid, gid)) {
                srcparent->unref();
                srcnode->unref();
                return -EACCES;
            }

            // Resolve destination parent directory.
            const char *dstdirpath = newpobj.dirname();
            INode *dstparent = NULL;
            res = this->resolve(dstdirpath, &dstparent, newrelativeto, true, procroot);
            delete dstdirpath;
            if (res < 0) {
                srcparent->unref();
                srcnode->unref();
                return res; // Destination parent doesn't exist.
            }

            if (!S_ISDIR(dstparent->getattr().st_mode)) {
                dstparent->unref();
                srcparent->unref();
                srcnode->unref();
                return -ENOTDIR; // Destination parent is not a directory.
            }

            // Check write permission on destination parent.
            if (!this->checkaccess(dstparent, O_RDWR | O_EXEC, uid, gid)) {
                dstparent->unref();
                srcparent->unref();
                srcnode->unref();
                return -EACCES;
            }

            // Check if source and destination are on the same filesystem.
            if (srcnode->fs != dstparent->fs) {
                dstparent->unref();
                srcparent->unref();
                srcnode->unref();
                return -EXDEV; // Cross-device rename not supported.
            }

            // Check if destination already exists.
            const char *dstname = newpobj.basename();
            INode *dstnode = dstparent->lookup(dstname);

            // Handle various rename cases.
            if (dstnode) {
                struct stat srcst = srcnode->getattr();
                struct stat dstst = dstnode->getattr();

                // Check if source and destination are the same file.
                if (srcst.st_ino == dstst.st_ino && srcst.st_dev == dstst.st_dev) {
                    // Same file, nothing to do.
                    dstnode->unref();
                    dstparent->unref();
                    srcparent->unref();
                    srcnode->unref();
                    return 0;
                }

                if (S_ISDIR(srcst.st_mode)) {
                    if (!S_ISDIR(dstst.st_mode)) {
                        // Woah pal, source can't be a directory if destination isn't.
                        dstnode->unref();
                        dstparent->unref();
                        srcparent->unref();
                        srcnode->unref();
                        return -ENOTDIR;
                    }
                } else {
                    if (S_ISDIR(dstst.st_mode)) {
                        // Woah pal, destination can't be a directory if source isn't.
                        dstnode->unref();
                        dstparent->unref();
                        srcparent->unref();
                        srcnode->unref();
                        return -EISDIR;
                    }
                }
            }

            // Get the filesystem to handle it.
            int ret = srcnode->fs->rename(srcparent, srcnode, dstparent, dstname, dstnode);
            return ret;
        }

        void VFS::syncall(void) {
            NLib::ScopeSpinlock guard(&this->mountlock);

            NLib::DoubleList<struct mntpoint>::Iterator it = this->mounts.begin();
            for (; it.valid(); it.next()) {
                it.get()->fs->sync();
            }
        }

        int FileDescriptorTable::open(INode *node, int flags) {
            NLib::ScopeWriteLock guard(&this->lock);

            int fd = this->openfds.findfirst();
            if (fd == -1) {
                fd = this->openfds.getsize();
                if (fd + 32 > MAXFDS) {
                    return -EMFILE; // Too many open files.
                }

                if (!this->fds.resize(fd + 32)) {
                    return -ENOMEM;
                }

                if (!this->openfds.resize(fd + 32)) {
                    return -ENOMEM;
                }

                if (!this->closeonexec.resize(fd + 32)) {
                    return -ENOMEM;
                }
            }

            this->fds[fd] = new FileDescriptor(node, flags);
            if (!this->fds[fd]) {
                return -ENOMEM;
            }

            // Increment filesystem reference count for this open file.
            if (node && node->fs) {
                node->fs->fsref();
            }

            if (flags & O_CLOEXEC) {
                this->closeonexec.set(fd);
            }

            this->openfds.set(fd);
            return fd;
        }

        void FileDescriptorTable::reserve(int fd, INode *node, int flags) {
            NLib::ScopeWriteLock guard(&this->lock);

            this->fds[fd] = new FileDescriptor(node, flags);
            if (!this->fds[fd]) {
                return;
            }

            // Increment filesystem reference count for this open file.
            if (node && node->fs) {
                node->fs->fsref();
            }

            this->openfds.set(fd);
        }

        int FileDescriptorTable::close(int fd) {
            NLib::ScopeWriteLock guard(&this->lock);

            if (fd < 0 || fd >= (int)this->fds.getsize() || !this->fds[fd] || !this->openfds.test(fd)) {
                return -EBADF;
            }

            FileDescriptor *desc = this->fds[fd];
            int res = 0;
            if (desc->unref() == 0) {
                INode *node = desc->getnode();
                res = node->close(desc->getflags());

                // Decrement filesystem reference count when closing the last reference.
                if (node->fs) {
                    node->fs->fsunref();
                }

                node->unref();
                delete desc;
            }
            this->fds[fd] = NULL;
            this->openfds.clear(fd); // Mark as unallocated.
            this->closeonexec.clear(fd); // Mark as unallocated.
            return res;
        }

        int FileDescriptorTable::dup(int oldfd) {
            NLib::ScopeWriteLock guard(&this->lock);

            if (oldfd < 0 || oldfd >= (int)this->fds.getsize() || !this->fds[oldfd] || !this->openfds.test(oldfd)) {
                return -EBADF;
            }

            int newfd = this->openfds.findfirst();
            if (newfd == -1) { // None available. :broken_heart: emoji
                newfd = this->openfds.getsize(); // New FD will be the new bit from this resize. Simply saves another call to findfirst().
                if (newfd + 32 > MAXFDS) {
                    return -EMFILE; // Too many open files.
                }

                if (!this->fds.resize(newfd + 32)) { // Resize vector. It'll grow to accomodate the new data.

                    return -ENOMEM;
                }

                if (!this->openfds.resize(newfd + 32)) {
                    return -ENOMEM;
                }
                if (!this->closeonexec.resize(newfd + 32)) { // Both bitmaps needs to be maintained.
                    return -ENOMEM;
                }
            }

            this->fds[newfd] = this->fds[oldfd];
            this->fds[newfd]->ref(); // Increase reference count of descriptor. We're now referring to it by another additional FD.
            this->openfds.set(newfd); // Set bit to mark as allocated.
            return newfd;
        }

        int FileDescriptorTable::dup2(int oldfd, int newfd, bool fcntl) {
            NLib::ScopeWriteLock guard(&this->lock);

            if (oldfd < 0 || oldfd >= (int)this->fds.getsize() || !this->fds[oldfd] || !this->openfds.test(oldfd)) { // Discard if we can tell that the FD is bad.
                return -EBADF;
            }

            if (fcntl) {
                if (newfd < 0) {
                    return -EINVAL;
                }

                // Find lowest-numbered available fd >= newfd.
                int candidate = -1;
                for (int i = newfd; i < (int)this->openfds.getsize(); i++) {
                    if (!this->openfds.test(i)) {
                        candidate = i;
                        break;
                    }
                }

                if (candidate == -1) {
                    candidate = this->openfds.getsize();
                    if (candidate + 32 > MAXFDS) {
                        return -EMFILE;
                    }

                    if (!this->fds.resize(candidate + 32)) {
                        return -ENOMEM;
                    }

                    if (!this->openfds.resize(candidate + 32)) {
                        return -ENOMEM;
                    }

                    if (!this->closeonexec.resize(candidate + 32)) {
                        return -ENOMEM;
                    }
                }

                this->fds[candidate] = this->fds[oldfd];
                this->fds[candidate]->ref();
                this->openfds.set(candidate);
                return candidate;
            }

            // Non-fcntl (dup2) semantics: newfd is exact target.
            if (newfd < 0 || newfd > MAXFDS) { // Discard if this is a negative. Positive FDs are still valid, because we can just expand the FD table. Arbitrary maximum is imposed to prevent rampant memory consumption.
                return -EBADF;
            }

            if (oldfd == newfd) {
                return newfd; // Don't even bother.
            }

            if (newfd >= (int)this->fds.getsize()) {
                if (!this->fds.resize(newfd + 1)) {
                    return -ENOMEM;
                }

                if (!this->openfds.resize(newfd + 1)) {
                    return -ENOMEM;
                }
                if (!this->closeonexec.resize(newfd + 1)) { // Both bitmaps needs to be maintained.
                    return -ENOMEM;
                }
            }

            if (this->openfds.test(newfd)) { // Close the existing descriptor if open.
                FileDescriptor *olddesc = this->fds[newfd];
                if (olddesc->unref() == 0) { // Decrement reference within our table.
                    INode *node = olddesc->getnode();
                    node->close(olddesc->getflags());
                    node->unref();
                    delete olddesc;
                }
            }

            this->fds[newfd] = this->fds[oldfd];
            this->fds[newfd]->ref();
            this->openfds.set(newfd); // Occupy new FD.
            this->closeonexec.clear(newfd); // dup2 clears close-on-exec per POSIX.
            return newfd;
        }

        FileDescriptor *FileDescriptorTable::get(int fd) {
            NLib::ScopeReadLock guard(&this->lock);

            if (fd < 0 || fd >= (int)this->fds.getsize() || !this->openfds.test(fd)) {
                // If the fd is negative, over our current maximum, or not currently allocated:
                return NULL;
            }
            return this->fds[fd]; // Otherwise: Return it.
        }

        FileDescriptorTable *FileDescriptorTable::fork(void) {
            NLib::ScopeWriteLock guard(&this->lock);

            FileDescriptorTable *newtable = new FileDescriptorTable();

            if (!newtable->fds.resize(this->fds.getsize()) || !newtable->openfds.resize(this->fds.getsize()) || !newtable->closeonexec.resize(this->fds.getsize())) { // Attempt to resize all tracking of FDs, failure returns NULL, and deletes the allocation (for the sake of memory usage).
                delete newtable;
                return NULL;
            }

            for (size_t i = 0; i < this->fds.getsize(); i++) {
                if (this->openfds.test(i)) { // There is an open FD, copy it.
                    newtable->fds[i] = this->fds[i]; // Copy reference to same FileDescriptor.
                    newtable->fds[i]->ref(); // Increase refcount.
                    newtable->openfds.set(i); // Mark as allocated.


                    if (this->closeonexec.test(i)) { // If this is also marked as close on exec.
                        newtable->closeonexec.set(i); // Mark as allocated.
                    }
                } else {
                    this->openfds.clear(i);
                    this->closeonexec.clear(i);
                }
            }

            return newtable;
        }

        bool FileDescriptorTable::iscloseonexec(int fd) {
            NLib::ScopeReadLock guard(&this->lock);

            if (fd < 0 || fd >= (int)this->fds.getsize() || !this->openfds.test(fd)) {
                return false;
            }

            return this->closeonexec.test(fd);
        }

        void FileDescriptorTable::setcloseonexec(int fd, bool closeit) {
            NLib::ScopeWriteLock guard(&this->lock);

            if (fd < 0 || fd >= (int)this->fds.getsize() || !this->openfds.test(fd)) {
                return;
            }

            if (closeit) {
                this->closeonexec.set(fd);
            } else {
                this->closeonexec.clear(fd);
            }
        }

        void FileDescriptorTable::doexec(void) {
            NLib::ScopeWriteLock guard(&this->lock);

            for (size_t i = 0; i < this->closeonexec.getsize(); i++) { // Effectively the same logic as closeall(), but we only close FDs marked as close-on-exec.
                if (this->closeonexec.test(i)) {
                    FileDescriptor *desc = this->fds[i];
                    if (desc->unref() == 0) {
                        INode *node = desc->getnode();
                        node->close(desc->getflags());
                        node->unref();
                        delete desc;
                    }
                    this->fds[i] = NULL;
                    this->openfds.clear(i);
                    this->closeonexec.clear(i);
                }
            }
        }

        void FileDescriptorTable::closeall(void) {
            NLib::ScopeWriteLock guard(&this->lock);

            for (size_t i = 0; i < this->openfds.getsize(); i++) {
                if (this->openfds.test(i)) { // Allocated. Free associated if without reference.
                    FileDescriptor *desc = this->fds[i];
                    if (desc->unref() == 0) {
                        INode *node = desc->getnode();
                        node->close(desc->getflags());
                        node->unref();
                        delete desc; // Delete descriptor itself if we ran out of references.
                    }
                    this->fds[i] = NULL;
                    this->openfds.clear(i);
                    this->closeonexec.clear(i);
                }
            }
        }

        bool VFS::checkaccess(INode *node, int flags, uint32_t uid, uint32_t gid) {
            struct stat st = node->getattr();

            // Root always bypasses.
            if (uid == 0) {
                return true;
            }

            if ((flags & O_ACCMODE) == O_RDONLY || (flags & O_ACCMODE) == O_RDWR) {
                if (uid == st.st_uid) {
                    if (!(st.st_mode & S_IRUSR)) {
                        return false;
                    }
                } else if (gid == st.st_gid) {
                    if (!(st.st_mode & S_IRGRP)) {
                        return false;
                    }
                } else {
                    if (!(st.st_mode & S_IROTH)) {
                        return false;
                    }
                }
            }

            if ((flags & O_ACCMODE) == O_WRONLY || (flags & O_ACCMODE) == O_RDWR) {
                if (uid == st.st_uid) {
                    if (!(st.st_mode & S_IWUSR)) {
                        return false;
                    }
                } else if (gid == st.st_gid) {
                    if (!(st.st_mode & S_IWGRP)) {
                        return false;
                    }
                } else {
                    if (!(st.st_mode & S_IWOTH)) {
                        return false;
                    }
                }
            }

            if (flags & O_EXEC || S_ISDIR(st.st_mode)) {
                if (uid == st.st_uid) {
                    if (!(st.st_mode & S_IXUSR)) {
                        return false;
                    }
                } else if (gid == st.st_gid) {
                    if (!(st.st_mode & S_IXGRP)) {
                        return false;
                    }
                } else {
                    if (!(st.st_mode & S_IXOTH)) {
                        return false;
                    }
                }
            }

            return true;
        }


        int VFS::identifyfs(const char *src) {
            // XXX: Implement filesystem auto-detection.
            return -ENODEV;
        }

        VFS::VFS(void) : mountlock(), mounts(), root(NULL) {
            this->readaheadwq = new NSched::WorkQueue("readahead", NSched::WQ_UNBOUND | NSched::WQ_INTENSIVE); // Mark as intensive, because it can be blocking on sync fallback.
        }
    }
}
