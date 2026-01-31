#include <dev/block.hpp>
#include <lib/string.hpp>
#include <lib/sync.hpp>
#include <mm/pagecache.hpp>
#include <sched/event.hpp>
#include <sched/sched.hpp>
#include <mm/ucopy.hpp>
#include <util/kprint.hpp>

#ifdef __x86_64__
#include <arch/x86_64/pmm.hpp>
#endif

#define MIN(a, b) ((a) < (b) ? (a) : (b))

namespace NDev {

    BlockDevice::~BlockDevice() {
        // Sync and invalidate cache on destruction.
        this->syncdevice();
        this->invalidatecache();
    }

    NMem::RadixTree *BlockDevice::getpagecache(void) {
        if (!this->pagecache) {
            this->pagecache = new NMem::RadixTree();
        }
        return this->pagecache;
    }

    NMem::CachePage *BlockDevice::findcachedpage(off_t offset) {
        NMem::RadixTree *cache = this->getpagecache();
        if (!cache) {
            return NULL;
        }

        off_t index = offset / NArch::PAGESIZE;
        return cache->lookupandlock(index);
    }

    NMem::CachePage *BlockDevice::getorcachepage(off_t offset) {
        NMem::RadixTree *cache = this->getpagecache();
        if (!cache) {
            return NULL;
        }

        off_t pageoffset = (offset / NArch::PAGESIZE) * NArch::PAGESIZE;
        off_t index = pageoffset / NArch::PAGESIZE;

        // Check if page already exists (use lookupandlock to prevent race with eviction).
        NMem::CachePage *page = cache->lookupandlock(index);
        if (page) {
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

        page->inode = NULL; // Block device pages don't have an inode.
        page->blockdev = this; // Set owning block device for writeback support.
        page->offset = pageoffset;
        page->flags = 0;

        // Try to insert into radix tree.
        int err = cache->insert(index, page);
        if (err == -EEXIST) {
            // Another thread inserted the page, use that one.
            if (page->pagemeta) {
                page->pagemeta->flags &= ~NArch::PMM::PageMeta::PAGEMETA_PAGECACHE;
                page->pagemeta->cacheentry = NULL;
                page->pagemeta->unref();
            }
            NArch::PMM::free(phys, NArch::PAGESIZE);
            delete page;

            // Use lookupandlock to prevent race with eviction.
            return cache->lookupandlock(index);
        } else if (err < 0) {
            // Allocation failure in radix tree.
            if (page->pagemeta) {
                page->pagemeta->flags &= ~NArch::PMM::PageMeta::PAGEMETA_PAGECACHE;
                page->pagemeta->cacheentry = NULL;
                page->pagemeta->unref();
            }
            NArch::PMM::free(phys, NArch::PAGESIZE);
            delete page;
            return NULL;
        }

        // Add to global page cache LRU.
        if (NMem::pagecache) {
            NMem::pagecache->addpage(page);
        }

        // Take a ref for the caller, matching the contract of lookupandlock.
        // The cache holds one ref (from addpage), caller gets another.
        page->ref();

        page->pagelock();
        return page;
    }

    void BlockDevice::invalidatecache(void) {
        NMem::RadixTree *cache = this->pagecache;
        if (!cache) {
            return;
        }

        // Use collect-then-process pattern to avoid blocking on pagelock while holding treelock.
        static constexpr size_t BATCHSIZE = 32;
        NMem::CachePage *batch[BATCHSIZE];
        off_t resumeindex = 0;
        size_t count;

        // Collect all pages (no filter needed).
        while ((count = cache->foreachcollect(batch, BATCHSIZE, NULL, NULL, &resumeindex)) > 0) {
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
                    page->pagemeta->unref();  // Release cache's pagemeta ref.
                }

                page->pageunlock();
                if (page->pagemeta) {
                    page->pagemeta->unref();  // Release foreachcollect's pagemeta ref.
                }
                // Release refs: foreachcollect ref + cache ref (from addpage).
                page->unref();  // foreachcollect ref.
                page->unref();  // cache ref, this triggers delete.
            }

            if (resumeindex < 0) {
                break;
            }
        }

        delete cache;
        this->pagecache = NULL;
    }

    // Read block-wise from device. Must be implemented by driver.
    ssize_t BlockDevice::readblock(uint64_t lba, void *buffer) {
        (void)lba;
        (void)buffer;
        return -1;
    }

    // Write block-wise to device. Must be implemented by driver.
    ssize_t BlockDevice::writeblock(uint64_t lba, const void *buffer) {
        (void)lba;
        (void)buffer;
        return -1;
    }

    // Read multiple contiguous blocks from device. Driver should override for better performance.
    ssize_t BlockDevice::readblocks(uint64_t lba, size_t count, void *buffer) {
        uint8_t *buf = (uint8_t *)buffer;
        for (size_t i = 0; i < count; i++) {
            ssize_t res = this->readblock(lba + i, buf + (i * this->blksize));
            if (res < 0) {
                return res;
            }
        }
        return 0;
    }

    // Write multiple contiguous blocks to device. Driver should override for better performance.
    ssize_t BlockDevice::writeblocks(uint64_t lba, size_t count, const void *buffer) {
        const uint8_t *buf = (const uint8_t *)buffer;
        for (size_t i = 0; i < count; i++) {
            ssize_t res = this->writeblock(lba + i, buf + (i * this->blksize));
            if (res < 0) {
                return res;
            }
        }
        return 0;
    }


    // Read raw bytes from block device with context-aware caching.
    ssize_t BlockDevice::readbytes(void *buf, size_t count, off_t offset, int fdflags, IOContext ctx) {
        (void)fdflags;

        if (ctx & (IO_METADATA | IO_RAW)) {
            return this->readbytespagecache(buf, count, offset);
        }

        // Direct I/O for file data and default case.
        return this->readbytesdirect(buf, count, offset);
    }


    // Write raw bytes to block device with context-aware caching.
    ssize_t BlockDevice::writebytes(const void *buf, size_t count, off_t offset, int fdflags, IOContext ctx) {
        (void)fdflags;

        if (ctx & (IO_METADATA | IO_RAW)) {
            return this->writebytespagecache(buf, count, offset);
        }

        // Direct I/O for file data and default case.
        return this->writebytesdirect(buf, count, offset);
    }

    // Direct read bypassing page cache (for filesystem page I/O).
    ssize_t BlockDevice::readbytesdirect(void *buf, size_t count, off_t offset) {
        if (!buf || count == 0) {
            return 0;
        }

        uint8_t *dest = (uint8_t *)buf;
        ssize_t totalread = 0;

        size_t blkoff = offset % this->blksize;
        if (blkoff != 0) {
            // Read unaligned beginning block.
            uint64_t lba = offset / this->blksize;
            size_t toread = MIN(this->blksize - blkoff, count);

            uint8_t *blkbuf = new uint8_t[this->blksize];
            if (!blkbuf) {
                return -ENOMEM;
            }

            ssize_t res = this->readblock(lba, blkbuf);
            if (res < 0) {
                delete[] blkbuf;
                return res;
            }

            if (NMem::UserCopy::iskernel(dest, toread)) {
                NLib::memcpy(dest, blkbuf + blkoff, toread);
            } else {
                ssize_t ret = NMem::UserCopy::copyto(dest, blkbuf + blkoff, toread);
                if (ret < 0) {
                    delete[] blkbuf;
                    return ret;
                }
            }
            delete[] blkbuf;

            dest += toread;
            offset += toread;
            count -= toread;
            totalread += toread;
        }

        size_t fullblocks = count / this->blksize;
        if (fullblocks > 0) {
            // Read full blocks.
            ssize_t res = this->readblocks(offset / this->blksize, fullblocks, dest);
            if (res < 0) {
                return totalread > 0 ? totalread : res;
            }
            size_t bytesread = fullblocks * this->blksize;
            dest += bytesread;
            offset += bytesread;
            count -= bytesread;
            totalread += bytesread;
        }

        if (count > 0) {
            // Read unaligned ending block.
            uint64_t lba = offset / this->blksize;

            uint8_t *blkbuf = new uint8_t[this->blksize];
            if (!blkbuf) {
                return totalread > 0 ? totalread : -ENOMEM;
            }

            ssize_t res = this->readblock(lba, blkbuf);
            if (res < 0) {
                delete[] blkbuf;
                return totalread > 0 ? totalread : res;
            }

            if (NMem::UserCopy::iskernel(dest, count)) {
                NLib::memcpy(dest, blkbuf, count);
            } else {
                ssize_t ret = NMem::UserCopy::copyto(dest, blkbuf, count);
                if (ret < 0) {
                    delete[] blkbuf;
                    return totalread > 0 ? totalread : ret;
                }
            }
            delete[] blkbuf;

            totalread += count;
        }

        return totalread;
    }

    // Direct write bypassing page cache (for filesystem page I/O).
    ssize_t BlockDevice::writebytesdirect(const void *buf, size_t count, off_t offset) {
        if (!buf || count == 0) {
            return 0;
        }

        const uint8_t *src = (const uint8_t *)buf;
        ssize_t totalwritten = 0;

        size_t blkoff = offset % this->blksize;
        if (blkoff != 0) {
            // Write unaligned beginning block.
            uint64_t lba = offset / this->blksize;
            size_t towrite = MIN(this->blksize - blkoff, count);
            uint8_t *blkbuf = new uint8_t[this->blksize];
            if (!blkbuf) {
                return -ENOMEM;
            }
            // Read existing block data.
            ssize_t res = this->readblock(lba, blkbuf);
            if (res < 0) {
                delete[] blkbuf;
                return res;
            }
            if (NMem::UserCopy::iskernel((void *)src, towrite)) {
                NLib::memcpy(blkbuf + blkoff, (void *)src, towrite);
            } else {
                ssize_t ret = NMem::UserCopy::copyto(blkbuf + blkoff, (void *)src, towrite);
                if (ret < 0) {
                    delete[] blkbuf;
                    return ret;
                }
            }
            // Write updated block back.
            res = this->writeblock(lba, blkbuf);
            if (res < 0) {
                delete[] blkbuf;
                return res;
            }
            delete[] blkbuf;
            src += towrite;
            offset += towrite;
            count -= towrite;
            totalwritten += towrite;
        }

        size_t fullblocks = count / this->blksize;
        if (fullblocks > 0) {
            // Write full blocks.
            ssize_t res = this->writeblocks(offset / this->blksize, fullblocks, src);
            if (res < 0) {
                return totalwritten > 0 ? totalwritten : res;
            }
            size_t byteswritten = fullblocks * this->blksize;
            src += byteswritten;
            offset += byteswritten;
            count -= byteswritten;
            totalwritten += byteswritten;
        }

        if (count > 0) {
            // Write unaligned ending block.
            uint64_t lba = offset / this->blksize;
            uint8_t *blkbuf = new uint8_t[this->blksize];
            if (!blkbuf) {
                return totalwritten > 0 ? totalwritten : -ENOMEM;
            }
            // Read existing block data.
            ssize_t res = this->readblock(lba, blkbuf);
            if (res < 0) {
                delete[] blkbuf;
                return totalwritten > 0 ? totalwritten : res;
            }
            if (NMem::UserCopy::iskernel((void *)src, count)) {
                NLib::memcpy(blkbuf, (void *)src, count);
            } else {
                ssize_t ret = NMem::UserCopy::copyfrom(blkbuf, (void *)src, count);
                if (ret < 0) {
                    delete[] blkbuf;
                    return totalwritten > 0 ? totalwritten : ret;
                }
            }
            // Write updated block back.
            res = this->writeblock(lba, blkbuf);
            if (res < 0) {
                delete[] blkbuf;
                return totalwritten > 0 ? totalwritten : res;
            }
            delete[] blkbuf;
            totalwritten += count;
        }

        return totalwritten;
    }

    int BlockDevice::readpagedata(void *pagebuf, off_t pageoffset) {
        // Calculate how many blocks fit in a page.
        size_t blocksperpage = NArch::PAGESIZE / this->blksize;
        if (blocksperpage == 0) {
            blocksperpage = 1; // Block size larger than page (unusual but possible).
        }

        uint64_t lba = pageoffset / this->blksize;

        // Read blocks into page buffer.
        ssize_t res = this->readblocks(lba, blocksperpage, pagebuf);
        if (res < 0) {
            return (int)res;
        }

        return 0;
    }

    int BlockDevice::writepagedata(const void *pagebuf, off_t pageoffset) {
        // Calculate how many blocks fit in a page.
        size_t blocksperpage = NArch::PAGESIZE / this->blksize;
        if (blocksperpage == 0) {
            blocksperpage = 1;
        }

        uint64_t lba = pageoffset / this->blksize;

        // Write blocks from page buffer.
        ssize_t res = this->writeblocks(lba, blocksperpage, pagebuf);
        if (res < 0) {
            return (int)res;
        }

        return 0;
    }

    ssize_t BlockDevice::readbytespagecache(void *buf, size_t count, off_t offset) {
        if (!buf || count == 0) {
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

            // Find or create page in device cache.
            NMem::CachePage *page = this->getorcachepage(offset);
            if (!page) {
                if (totalread > 0) {
                    return totalread;
                }
                return -ENOMEM;
            }

            // If page is not up to date, read from device.
            if (!page->testflag(NMem::PAGE_UPTODATE)) {
                int err = this->readpagedata(page->data(), pageoffset);
                if (err < 0) {
                    page->pageunlock();
                    page->unref();
                    if (totalread > 0) {
                        return totalread;
                    }
                    return err;
                }
                page->setflag(NMem::PAGE_UPTODATE);
            }

            // Copy requested portion to user buffer
            if (NMem::UserCopy::iskernel(dest, toread)) {
                NLib::memcpy(dest, (uint8_t *)page->data() + offwithinpage, toread);
            } else {
                ssize_t res = NMem::UserCopy::copyto(dest, (uint8_t *)page->data() + offwithinpage, toread);
                if (res < 0) {
                    page->pageunlock();
                    page->unref();
                    if (totalread > 0) {
                        return totalread;
                    }
                    return res;
                }
            }

            page->setflag(NMem::PAGE_REFERENCED);
            page->pageunlock();
            page->unref();

            dest += toread;
            offset += toread;
            count -= toread;
            totalread += toread;
        }

        return totalread;
    }

    ssize_t BlockDevice::writebytespagecache(const void *buf, size_t count, off_t offset) {
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

            // Find or create page in device cache.
            NMem::CachePage *page = this->getorcachepage(offset);
            if (!page) {
                if (totalwritten > 0) {
                    return totalwritten;
                }
                return -ENOMEM;
            }

            // If partial page write and page not up to date, read existing data first.
            if (!page->testflag(NMem::PAGE_UPTODATE) && (offwithinpage != 0 || towrite < NArch::PAGESIZE)) {
                int err = this->readpagedata(page->data(), pageoffset);
                if (err < 0) {
                    // New region, zero page.
                    NLib::memset(page->data(), 0, NArch::PAGESIZE);
                }
            }

            // Copy user data into page.
            if (NMem::UserCopy::iskernel((void *)src, towrite)) {
                NLib::memcpy((uint8_t *)page->data() + offwithinpage, (void *)src, towrite);
            } else {
                ssize_t res = NMem::UserCopy::copyfrom((uint8_t *)page->data() + offwithinpage, (void *)src, towrite);
                if (res < 0) {
                    page->pageunlock();
                    page->unref();
                    if (totalwritten > 0) {
                        return totalwritten;
                    }
                    return res;
                }
            }

            page->setflag(NMem::PAGE_UPTODATE);
            page->markdirty();
            page->pageunlock();
            page->unref();

            // Throttle if too many dirty pages to prevent unbounded dirty page growth.
            if (NMem::pagecache && NMem::pagecache->shouldthrottle()) {
                NMem::pagecache->wakewriteback();
                NSched::yield(); // Give writeback thread a chance to run.
            }

            src += towrite;
            offset += towrite;
            count -= towrite;
            totalwritten += towrite;
        }

        return totalwritten;
    }

    int BlockDevice::cancelbio(struct bioreq *req) {
        (void)req;
        return -ENOSYS;
    }

    // Synchronous fallback for drivers that do not support async I/O.
    int BlockDevice::submitbio(struct bioreq *req) {
        ssize_t res;
        if (req->op == bioreq::BIO_READ) {
            res = this->readblocks(req->lba, req->count, req->buffer);
        } else if (req->op == bioreq::BIO_WRITE) {
            res = this->writeblocks(req->lba, req->count, req->buffer);
        } else {
            return -EINVAL;
        }

        req->status = (res < 0) ? (int)res : 0;

        __atomic_store_n(&req->completed, true, memory_order_release);

        if (req->callback) {
            req->callback(req);
        }

        req->wq.wake();
        return req->status;
    }

    int BlockDevice::waitbio(struct bioreq *req) {
        waitevent(&req->wq, __atomic_load_n(&req->completed, memory_order_acquire));
        return req->status;
    }

    int BlockDevice::submitbiobatch(struct bioreq **reqs, size_t count) {
        for (size_t i = 0; i < count; i++) {
            int res = this->submitbio(reqs[i]);
            if (res < 0) {
                return res;
            }
        }
        return 0;
    }

    int BlockDevice::waitbiobatch(struct bioreq **reqs, size_t count) {
        // Wait for all requests to complete.
        int firsterror = 0;
        for (size_t i = 0; i < count; i++) {
            int res = this->waitbio(reqs[i]);
            if (res < 0 && firsterror == 0) {
                firsterror = res;
            }
        }
        return firsterror;
    }

    int BlockDevice::readblocks_async(uint64_t lba, size_t count, void *buf, struct bioreq **outreq) {
        struct bioreq *req = new struct bioreq();
        if (!req) {
            return -ENOMEM;
        }

        req->init(this, bioreq::BIO_READ, lba, count, buf, count * this->blksize);

        int res = this->submitbio(req);
        if (res < 0) {
            delete req;
            return res;
        }

        *outreq = req;
        return 0;
    }

    int BlockDevice::writeblocks_async(uint64_t lba, size_t count, const void *buf, struct bioreq **outreq) {
        struct bioreq *req = new struct bioreq();
        if (!req) {
            return -ENOMEM;
        }

        req->init(this, bioreq::BIO_WRITE, lba, count, (void *)buf, count * this->blksize);

        int res = this->submitbio(req);
        if (res < 0) {
            delete req;
            return res;
        }

        *outreq = req;
        return 0;
    }


    int BlockDevice::syncdevice(void) {
        NUtil::printf("[dev/block]: Syncing block device ID %lu...\n", this->id);
        NMem::RadixTree *cache = this->pagecache;
        if (!cache) {
            return 0;
        }

        // Use collect-then-process pattern to avoid holding treelock during I/O.
        static constexpr size_t MAXBATCH = 32;
        NMem::CachePage *collected[MAXBATCH];
        NMem::CachePage *dirtypages[MAXBATCH];
        struct bioreq *requests[MAXBATCH];
        int errors = 0;

        off_t resumeindex = 0;
        size_t count;

        // Filter for dirty pages that are not already being written back.
        auto dirtyfilter = [](NMem::CachePage *page, void *) -> bool {
            return page->testflag(NMem::PAGE_DIRTY) && !page->testflag(NMem::PAGE_WRITEBACK);
        };

        // Iterate in batches, releasing treelock between batches.
        while ((count = cache->foreachcollect(collected, MAXBATCH, dirtyfilter, NULL, &resumeindex)) > 0) {
            size_t submitted = 0;

            // Try-lock and submit I/O (NO treelock held).
            for (size_t i = 0; i < count; i++) {
                NMem::CachePage *page = collected[i];

                // Try to lock the page. If we can't, skip it (another thread has it).
                if (!page->trypagelock()) {
                    page->unref();
                    if (page->pagemeta) {
                        page->pagemeta->unref();
                    }
                    continue;
                }

                // Re-check dirty flag after acquiring page lock (may have been cleaned).
                if (!page->testflag(NMem::PAGE_DIRTY)) {
                    page->pageunlock();
                    page->unref();
                    if (page->pagemeta) {
                        page->pagemeta->unref();
                    }
                    continue;
                }

                page->setflag(NMem::PAGE_WRITEBACK);

                // Calculate LBA for this page.
                size_t blocksperpage = NArch::PAGESIZE / this->blksize;
                if (blocksperpage == 0) {
                    blocksperpage = 1;
                }
                uint64_t lba = page->offset / this->blksize;

                // Create async write request.
                struct bioreq *req = new struct bioreq();
                if (!req) {
                    page->clearflag(NMem::PAGE_WRITEBACK);
                    page->pageunlock();
                    page->unref();
                    if (page->pagemeta) {
                        page->pagemeta->unref();
                    }
                    errors++;
                    continue;
                }

                req->init(this, bioreq::BIO_WRITE, lba, blocksperpage, page->data(), NArch::PAGESIZE);

                // Submit async.
                int res = this->submitbio(req);
                if (res < 0) {
                    delete req;
                    page->clearflag(NMem::PAGE_WRITEBACK);
                    page->errorcount++;
                    if (page->errorcount >= 10) {
                        page->setflag(NMem::PAGE_ERROR);
                    }
                    page->pageunlock();
                    page->unref();
                    if (page->pagemeta) {
                        page->pagemeta->unref();
                    }
                    errors++;
                    continue;
                }

                dirtypages[submitted] = page;
                requests[submitted] = req;
                submitted++;
            }

            // Await completion.
            if (submitted > 0) {
                this->waitbiobatch(requests, submitted);

                // Process completed requests.
                for (size_t i = 0; i < submitted; i++) {
                    NMem::CachePage *pg = dirtypages[i];
                    struct bioreq *rq = requests[i];

                    pg->clearflag(NMem::PAGE_WRITEBACK);
                    if (rq->status < 0) {
                        pg->errorcount++;
                        if (pg->errorcount >= 10) {
                            pg->setflag(NMem::PAGE_ERROR);
                        }
                        errors++;
                    } else {
                        pg->markclean();
                        pg->errorcount = 0;
                    }
                    pg->pageunlock();
                    pg->unref();
                    if (pg->pagemeta) {
                        pg->pagemeta->unref();
                    }
                    delete rq;
                }
            }

            // If resumeindex is -1, we've finished iterating.
            if (resumeindex < 0) {
                break;
            }
        }

        return errors;
    }

    struct parttableinfo *getpartinfo(BlockDevice *dev) {
        // Check if MBR or GPT.
        uint8_t mbrsector[512];
        ssize_t res = dev->readbytes(mbrsector, sizeof(mbrsector), 0, 0, IO_METADATA);
        if (res != sizeof(mbrsector)) {
            NUtil::printf("[dev/block]: Failed to read MBR sector for partition info (err=%d).\n", (int)res);
            return NULL;
        }

        // Check MBR signature.
        if (mbrsector[510] == 0x55 && mbrsector[511] == 0xAA) {
            // Check if this is a protective MBR for GPT.
            struct mbrpartentry *mbrents = (struct mbrpartentry *)&mbrsector[446];
            if (mbrents[0].type == 0xEE) {
                // This is a protective MBR, read GPT header from LBA 1.
                uint8_t gptheadersector[512];
                res = dev->readbytes(gptheadersector, sizeof(gptheadersector), 512, 0, IO_METADATA);
                if (res != sizeof(gptheadersector)) {
                    NUtil::printf("[dev/block]: Failed to read GPT header sector (err=%d).\n", (int)res);
                    return NULL;
                }

                struct gptheader *hdr = (struct gptheader *)gptheadersector;

                // Validate GPT signature "EFI PART".
                uint64_t gptsig = 0x5452415020494645ULL; // "EFI PART" in little-endian.
                if (hdr->signature != gptsig) {
                    NUtil::printf("[dev/block]: Invalid GPT signature.\n");
                    return NULL;
                }

                // Read partition entries.
                size_t partarraysize = hdr->numparts * hdr->partsize;
                uint8_t *partarray = new uint8_t[partarraysize];
                if (!partarray) {
                    NUtil::printf("[dev/block]: Failed to allocate GPT partition array.\n");
                    return NULL;
                }

                off_t partoffset = hdr->partlba * dev->blksize;
                res = dev->readbytes(partarray, partarraysize, partoffset, 0, IO_METADATA);
                if (res != (ssize_t)partarraysize) {
                    NUtil::printf("[dev/block]: Failed to read GPT partition entries (err=%d).\n", (int)res);
                    delete[] partarray;
                    return NULL;
                }

                // Count valid partitions (non-zero type GUID).
                size_t validparts = 0;
                for (size_t i = 0; i < hdr->numparts; i++) {
                    struct gptpartentry *ent = (struct gptpartentry *)(partarray + (i * hdr->partsize));
                    bool iszero = true;
                    for (size_t j = 0; j < 16; j++) {
                        if (ent->tuid[j] != 0) {
                            iszero = false;
                            break;
                        }
                    }
                    if (!iszero) {
                        validparts++;
                    }
                }

                struct partinfo *parts = new struct partinfo[validparts];
                if (!parts) {
                    NUtil::printf("[dev/block]: Failed to allocate GPT partition info.\n");
                    delete[] partarray;
                    return NULL;
                }

                // Populate partition info.
                size_t partidx = 0;
                for (size_t i = 0; i < hdr->numparts; i++) {
                    struct gptpartentry *ent = (struct gptpartentry *)(partarray + (i * hdr->partsize));
                    bool iszero = true;
                    for (size_t j = 0; j < 16; j++) {
                        if (ent->tuid[j] != 0) {
                            iszero = false;
                            break;
                        }
                    }
                    if (!iszero) {
                        parts[partidx].firstlba = ent->firstlba;
                        parts[partidx].lastlba = ent->lastlba;
                        partidx++;
                    }
                }

                delete[] partarray;

                struct parttableinfo *ptinfo = new struct parttableinfo;
                if (!ptinfo) {
                    NUtil::printf("[dev/block]: Failed to allocate GPT parttableinfo struct.\n");
                    delete[] parts;
                    return NULL;
                }

                ptinfo->type = PARTTYPE_GPT;
                ptinfo->numparts = validparts;
                ptinfo->partitions = parts;
                return ptinfo;
            }

            // Standard MBR partition table.
            struct partinfo *parts = new struct partinfo[4];
            if (!parts) {
                NUtil::printf("[dev/block]: Failed to allocate MBR partition info.\n");
                return NULL;
            }

            struct parttableinfo *ptinfo = new struct parttableinfo;
            if (!ptinfo) {
                NUtil::printf("[dev/block]: Failed to allocate MBR parttableinfo struct.\n");
                delete[] parts;
                return NULL;
            }
            ptinfo->numparts = 0;

            struct mbrpartentry *entries = (struct mbrpartentry *)&mbrsector[446];
            for (size_t i = 0; i < 4; i++) {
                if (entries[i].type != 0) {
                    parts[i].firstlba = entries[i].firstlba;
                    parts[i].lastlba = entries[i].firstlba + entries[i].sectors - 1;
                    ptinfo->numparts++;
                }
            }
            ptinfo->type = PARTTYPE_MBR;
            ptinfo->partitions = parts;
            return ptinfo;
        }

        return NULL;
    }
}