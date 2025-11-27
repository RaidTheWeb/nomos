#include <dev/block.hpp>
#include <dev/blockcache.hpp>
#include <mm/ucopy.hpp>
#include <std/stddef.h>

namespace NDev {

    #define MAX(a, b) ((a) > (b) ? (a) : (b))

    BlockCache::BlockCache(BlockDevice *dev, size_t capacity, size_t blocksize) {
        this->dev = dev;
        this->capacity = MAX(capacity, 1); // Ensure at least 1 entry capacity.
        this->blocksize = blocksize;
        this->head = NULL;
        this->tail = NULL;
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

        // Clear cache map (buckets freed by KVHashMap destructor/clear())
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
        // TODO: More advanced eviction policy.
        return this->tail;
    }

    static void promoteentry(struct cacheentry **head, struct cacheentry **tail, struct cacheentry *entry) {
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

    int BlockCache::read(uint64_t lba, void *buffer) {
        this->cachelock.acquire();

        struct cacheentry **hit = this->cachemap.find(lba);
        if (hit) {
            struct cacheentry *entry = *hit;

            // Move to front of LRU list (MRU).
            promoteentry(&this->head, &this->tail, entry);

            NLib::memcpy(buffer, (*hit)->data, this->blocksize);
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

            struct cacheentry *entry = inf->entry; // We should have the entry now.
            inf->refcount--;
            int err = inf->error;
            if (inf->refcount == 0) {
                delete inf; // No more waiters, safe to delete.
            }

            if (entry && err == 0) {
                // Promote to MRU.
                promoteentry(&this->head, &this->tail, entry);
                NLib::memcpy(buffer, entry->data, this->blocksize);
                this->cachelock.release();
                return 0;
            } else {
                this->cachelock.release();
                return err; // Failed to load entry.
            }
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

        NUtil::printf("Block %llu not found in cache, reading from device.\n", lba);

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

            NLib::memcpy(buffer, entry->data, this->blocksize);

            newinf->wq.wake(); // Wake up waiters.

            if (newinf->refcount == 0) {
                delete newinf; // No waiters, safe to delete.
            }

            this->cachelock.release();
            return 0;
        }


        newentry->lba = lba;
        newentry->dirty = false;

        NLib::memcpy(buffer, newentry->data, this->blocksize);

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

    int BlockCache::write(uint64_t lba, const void *buffer) {
        (void)lba;
        (void)buffer;
        return -1;
    }

    void BlockCache::flush(void) {
    }

    void BlockCache::evict(void) {
        struct cacheentry *victim = NULL;
        if (this->cachemap.size() < this->capacity) {
            return; // No need to evict.
        }

        NUtil::printf("Evicting entries to maintain cache capacity of %llu.\n", this->capacity);
        while (this->cachemap.size() >= this->capacity) { // We're going to add one, so evict until under capacity.
            victim = this->selectvict();
            if (!victim) {
                break; // No victim found, should not happen.
            }
            NUtil::printf("Evicting block %llu from cache.\n", victim->lba);

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
            if (victim->dirty) {
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
                break; // Stop eviction on failure to write back.
            }

            delete[] victim->data;
            delete victim;
        }
    }
}