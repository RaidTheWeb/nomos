#include <dev/block.hpp>
#include <lib/string.hpp>
#include <lib/sync.hpp>
#include <mm/pagecache.hpp>
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
        NMem::CachePage *page = cache->lookup(index);
        if (page) {
            page->pagelock();
        }
        return page;
    }

    NMem::CachePage *BlockDevice::getorcachepage(off_t offset) {
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

    void BlockDevice::invalidatecache(void) {
        NMem::RadixTree *cache = this->pagecache;
        if (!cache) {
            return;
        }

        // Iterate and remove all pages.
        cache->foreach([](NMem::CachePage *page, void *ctx) -> bool {
            (void)ctx;
            page->pagelock();

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

            page->pageunlock();
            delete page;
            return true;
        }, NULL);

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


    // Read raw bytes from block device, goes through cache.
    ssize_t BlockDevice::readbytes(void *buf, size_t count, off_t offset, int fdflags) {
        (void)fdflags;
        return this->readbytespagecache(buf, count, offset);
    }


    // Write raw bytes to block device, goes through page cache.
    ssize_t BlockDevice::writebytes(const void *buf, size_t count, off_t offset, int fdflags) {
        (void)fdflags;
        return this->writebytespagecache(buf, count, offset);
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
                    if (totalread > 0) {
                        return totalread;
                    }
                    return err;
                }
                page->setflag(NMem::PAGE_UPTODATE);
            }

            // Copy requested portion to user buffer.
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

    int BlockDevice::syncdevice(void) {
        NMem::RadixTree *cache = this->pagecache;
        if (!cache) {
            return 0;
        }

        int errors = 0;
        cache->foreach([](NMem::CachePage *page, void *ctx) -> bool {
            int *errp = (int *)ctx;
            BlockDevice *dev = (BlockDevice *)((void **)ctx)[1];
            if (page->testflag(NMem::PAGE_DIRTY)) {
                if (page->trypagelock()) {
                    page->setflag(NMem::PAGE_WRITEBACK);
                    int err = dev->writepagedata(page->data(), page->offset);
                    page->clearflag(NMem::PAGE_WRITEBACK);

                    if (err < 0) {
                        page->errorcount++;
                        if (page->errorcount >= 10) {
                            page->setflag(NMem::PAGE_ERROR);
                        }
                        (*errp)++;
                    } else {
                        page->markclean();
                        page->errorcount = 0;
                    }
                    page->pageunlock();
                }
            }
            return true;
        }, (void *[]){ &errors, this });

        return errors;
    }

    struct parttableinfo *getpartinfo(BlockDevice *dev) {
        // Check if MBR or GPT.
        uint8_t mbrsector[512];
        ssize_t res = dev->readbytes(mbrsector, sizeof(mbrsector), 0, 0);
        if (res != sizeof(mbrsector)) {
            NUtil::printf("[dev/block]: Failed to read MBR sector for partition info (err=%d).\n", (int)res);
            return NULL;
        }

        // Check MBR signature.
        if (mbrsector[510] == 0x55 && mbrsector[511] == 0xAA) {
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