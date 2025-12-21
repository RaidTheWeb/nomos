#include <dev/block.hpp>
#include <dev/blockcache.hpp>
#include <mm/ucopy.hpp>
#include <std/stddef.h>

namespace NDev {
    // TODO: Implement asynchronous prefetching of blocks for read-ahead.

    #define MAX(a, b) ((a) > (b) ? (a) : (b))

    static void writebackworker(void *arg) {
        // TODO: Improve writeback strategy.

        BlockCache *cache = (BlockCache *)arg;
        while (true) {
            // Scan for dirty blocks and write them back.
            cache->flush();
            NSched::sleep(5000); // Sleep for 5 seconds between writebacks.
        }
    }

    BlockCache::BlockCache(BlockDevice *dev, size_t capacity, size_t blocksize) {
        this->dev = dev;
        this->capacity = MAX(capacity, 1); // Ensure at least 1 entry capacity.
        this->blocksize = blocksize;
        this->head = NULL;
        this->tail = NULL;
        // Start writeback worker thread.
        NSched::Thread *wbthread = new NSched::Thread(NSched::kprocess, NSched::DEFAULTSTACKSIZE, (void *)writebackworker, (void *)this);
        NSched::schedulethread(wbthread);
    }

    BlockCache::~BlockCache() {
        // Free all cache entries and inflight structures.
        this->cachelock.acquire();

        // Remove and free linked list entries.
        struct cacheentry *cur = this->head;
        while (cur) {
            struct cacheentry *next = cur->next;
            if (cur->data) {
                delete[] cur->data;
            }
            delete cur;
            cur = next;
        }
        this->head = this->tail = NULL;

        this->cachemap.clear();

        // Free any inflight entries stored in the inflight map.
        for (auto it = this->inflightmap.begin(); it.valid(); it.next()) {
            struct inflight *inf = *it.value();
            if (inf) {
                delete inf;
            }
        }
        this->inflightmap.clear();

        this->cachelock.release();
    }

    struct cacheentry *BlockCache::selectvict(void) {
        struct cacheentry *victim = this->tail;
        while (victim) {
            if (!victim->dirty) {
                // Found clean victim.
                return victim;
            } else if (true) { // XXX: Implement LCR Lchip check here (IEEE. 8512727).
                return victim;
            }

            victim = victim->prev;
        }
        return NULL;
    }

    static void promoteentry(struct cacheentry **head, struct cacheentry **tail, struct cacheentry *entry) {
        // If entry is NULL or already the head (MRU), nothing to do.
        if (!entry || *head == entry) {
            return;
        }

        // Unlink entry from its current position.
        if (entry->prev) {
            entry->prev->next = entry->next;
        } else {
            *head = entry->next;
        }
        if (entry->next) {
            entry->next->prev = entry->prev;
        } else {
            *tail = entry->prev;
        }

        // Insert at front (MRU).
        entry->next = *head;
        entry->prev = NULL;
        if (*head) {
            (*head)->prev = entry;
        }
        *head = entry;
        if (!*tail) {
            *tail = entry;
        }
    }

    int BlockCache::readwrite(uint64_t lba, void *buffer, size_t off, size_t len, bool iswrite) {
        this->cachelock.acquire();

        while (true) {
            struct cacheentry **hit = this->cachemap.find(lba);
            if (hit) {
                struct cacheentry *entry = *hit;

                // Move to front of LRU list (MRU).
                promoteentry(&this->head, &this->tail, entry);

                if (iswrite) {
                    NLib::memcpy(entry->data + off, buffer, len);
                    entry->dirty = true;
                } else {
                    NLib::memcpy(buffer, entry->data + off, len);
                }
                this->cachelock.release();
                return 0;
            }

            struct inflight **infp = this->inflightmap.find(lba);
            if (infp) { // If another thread is already handling this LBA.
                struct inflight *inf = *infp;
                inf->refcount++;

                // Wait until our inflight load is done.
                // Since most wake() calls happen while holding the cache lock on the owner thread, we will likely end up spinning until the lock is released.
                waiteventlocked(&inf->wq, inf->done, &this->cachelock);

                int err = inf->error;
                inf->refcount--;
                if (inf->refcount == 0) {
                    delete inf; // No more waiters, safe to delete.
                }

                if (err) {
                    this->cachelock.release();
                    return err;
                }
                continue; // Retry lookup
            }
            break;
        }

        struct inflight *newinf = new struct inflight;
        if (!newinf) {
            this->cachelock.release();
            return -ENOMEM;
        }
        newinf->entry = NULL;
        newinf->done = false;
        newinf->refcount = 0;
        newinf->error = 0;
        this->inflightmap.insert(lba, newinf); // Insert into map, so other threads know we're loading this LBA.

        // Cache miss!
        this->evict(); // Evict if we need to.

        this->cachelock.release(); // Release lock while doing IO.
        struct cacheentry *newentry = new struct cacheentry;
        if (!newentry) {
            this->cachelock.acquire();
            newinf->done = true; // Mark as done.
            newinf->error = -ENOMEM;
            this->inflightmap.remove(lba);
            newinf->wq.wake(); // Wake up waiters.

            if (newinf->refcount == 0) {
                delete newinf; // No waiters, safe to delete.
            }

            this->cachelock.release();
            return -ENOMEM;
        }

        newentry->data = new uint8_t[this->blocksize];
        if (!newentry->data) {
            this->cachelock.acquire();
            newinf->done = true; // Mark as done.
            newinf->error = -ENOMEM;
            this->inflightmap.remove(lba);
            newinf->wq.wake(); // Wake up waiters.
            if (newinf->refcount == 0) {
                delete newinf; // No waiters, safe to delete.
            }

            this->cachelock.release();

            delete newentry;
            return -ENOMEM;
        }

        ssize_t res = this->dev->readblock(lba, newentry->data);

        this->cachelock.acquire(); // Re-acquire lock after IO.
        if (res < 0) {
            newinf->done = true; // Mark as done, but provide no entry, indicating failure.
            newinf->error = -EIO;
            this->inflightmap.remove(lba);
            newinf->wq.wake(); // Wake up waiters.
            if (newinf->refcount == 0) {
                delete newinf; // No waiters, safe to delete.
            }
            this->cachelock.release();

            delete[] newentry->data;
            delete newentry;
            return -EIO;
        }

        struct cacheentry **race = this->cachemap.find(lba);
        if (race) {
            // Another thread beat us to it, use their entry instead.
            delete[] newentry->data;
            delete newentry;

            newinf->done = true;
            newinf->error = 0;
            newinf->entry = *race; // Notify waiters of the existing entry.

            this->inflightmap.remove(lba);

            struct cacheentry *entry = *race;
            // Promote to MRU.
            promoteentry(&this->head, &this->tail, entry);

            if (iswrite) {
                NLib::memcpy(entry->data + off, buffer, len);
                entry->dirty = true;
            } else {
                NLib::memcpy(buffer, entry->data + off, len);
            }

            newinf->wq.wake(); // Wake up waiters.

            if (newinf->refcount == 0) {
                delete newinf; // No waiters, safe to delete.
            }

            this->cachelock.release();
            return 0;
        }


        newentry->lba = lba;
        newentry->dirty = false;

        if (iswrite) {
            NLib::memcpy(newentry->data + off, buffer, len);
            newentry->dirty = true;
        } else {
            NLib::memcpy(buffer, newentry->data + off, len);
        }

        // Insert at front of LRU list (MRU).
        newentry->next = this->head;
        newentry->prev = NULL;
        if (this->head) {
            this->head->prev = newentry;
        }
        this->head = newentry;
        if (!this->tail) {
            this->tail = newentry;
        }
        this->cachemap.insert(lba, newentry);

        newinf->entry = newentry;
        newinf->error = 0;
        newinf->done = true;
        this->inflightmap.remove(lba);


        newinf->wq.wake(); // Wake up waiters.
        if (newinf->refcount == 0) {
            delete newinf; // No waiters, safe to delete.
        }

        this->cachelock.release();
        return 0;
    }

    int BlockCache::read(uint64_t lba, void *buffer, size_t off, size_t len) {
        return this->readwrite(lba, buffer, off, len, false);
    }

    int BlockCache::write(uint64_t lba, const void *buffer, size_t off, size_t len) {
        return this->readwrite(lba, (void *)buffer, off, len, true);
    }

    void BlockCache::flush(void) {
        while (true) { // We're literally just dumping all dirty entries until none remain.
            this->cachelock.acquire();
            struct cacheentry *cur = this->head;
            while (cur && !cur->dirty) {
                cur = cur->next;
            }
            if (!cur) {
                this->cachelock.release();
                break; // No more entries.
            }

            uint64_t lba = cur->lba;
            uint8_t *scratch = new uint8_t[this->blocksize]; // Allocate scratch buffer for writeback.
            if (!scratch) {
                this->cachelock.release();
                NUtil::printf("[dev/blockcache]: Failed to allocate scratch buffer during flush.\n");
                break; // Can't allocate scratch buffer, give up.
            }
            NLib::memcpy(scratch, cur->data, this->blocksize);
            this->cachelock.release(); // Release lock while doing IO.

            ssize_t res = this->dev->writeblock(lba, scratch);

            this->cachelock.acquire();
            if (res == 0) {
                struct cacheentry **entryp = this->cachemap.find(lba);
                if (entryp && *entryp) {
                    if (NLib::memcmp(scratch, (*entryp)->data, this->blocksize) == 0) {
                        (*entryp)->dirty = false;
                    }
                }
            } else {
                NUtil::printf("[dev/blockcache]: Failed to write back block %llu during flush (err=%d).\n", lba, (int)res);
                NArch::panic("[dev/blockcache]: Flush writeback failure.\n");
            }
            delete[] scratch;
            this->cachelock.release();
        }
    }

    void BlockCache::evict(void) {
        struct cacheentry *victim = NULL;
        if (this->cachemap.size() < this->capacity) {
            return; // No need to evict.
        }

        while (this->cachemap.size() >= this->capacity) { // We're going to add one, so evict until under capacity.
            victim = this->selectvict();
            if (!victim) {
                NUtil::printf("[dev/blockcache]: No victim found during eviction.\n");
                break; // No victim found, should not happen.
            }

            if (victim->prev) {
                victim->prev->next = victim->next;
            } else {
                this->head = victim->next;
            }
            if (victim->next) {
                victim->next->prev = victim->prev;
            } else {
                this->tail = victim->prev;
            }
            this->cachemap.remove(victim->lba);

            ssize_t res = 0;
            struct inflight *inf = NULL;
            if (victim->dirty) {
                inf = new struct inflight;
                if (inf) {
                    inf->done = false;
                    inf->refcount = 0;
                    inf->error = 0;
                    inf->entry = NULL;
                    this->inflightmap.insert(victim->lba, inf);
                }

                this->cachelock.release();
                res = this->dev->writeblock(victim->lba, victim->data); // Make sure to write back if dirty, so we aren't discarding our changes.
                this->cachelock.acquire();
            }

            if (res < 0) { // If we failed to write back, we should stop eviction here.
                NUtil::printf("[dev/blockcache]: Failed to write back dirty block %llu during eviction.\n", victim->lba);
                if (!this->cachemap.find(victim->lba)) { // If victim not already re-inserted.
                    victim->prev = NULL;
                    victim->next = this->head;
                    if (this->head) {
                        this->head->prev = victim;
                    }
                    this->head = victim;
                    if (!this->tail) {
                        this->tail = victim;
                    }
                    this->cachemap.insert(victim->lba, victim);
                } else { // Victim was re-inserted during writeback. DATA LOSS!
                    NUtil::printf("[dev/blockcache]: Victim block %llu was re-inserted during eviction writeback, not restoring.\n", victim->lba);
                    delete[] victim->data;
                    delete victim;
                }

                if (inf) {
                    inf->done = true;
                    this->inflightmap.remove(victim->lba);
                    inf->wq.wake();
                    if (inf->refcount == 0) {
                        delete inf;
                    }
                }
                break; // Stop eviction on failure to write back.
            }

            if (inf) {
                inf->done = true;
                this->inflightmap.remove(victim->lba);
                inf->wq.wake();
                if (inf->refcount == 0) {
                    delete inf;
                }
            }

            delete[] victim->data;
            delete victim;
        }
    }
}