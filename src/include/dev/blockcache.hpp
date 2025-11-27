#ifndef __DEV__BLOCKCACHE_HPP
#define __DEV__BLOCKCACHE_HPP


#include <lib/list.hpp>
#include <lib/sync.hpp>
#include <sched/event.hpp>
#include <sched/sched.hpp>
#include <stdint.h>

namespace NDev {

    class BlockDevice;

    struct cacheentry {
        uint64_t lba;
        bool dirty;
        uint8_t *data;
        // LRU links. We don't use a DoubleList here, because it's non-intrusive.
        struct cacheentry *next;
        struct cacheentry *prev;
    };

    struct inflight {
        bool done;
        NSched::WaitQueue wq;
        int refcount = 0; // Number of waiters.
        struct cacheentry *entry;
        int error;
    };

    class BlockCache {
        private:
            struct cacheentry *head = NULL;
            struct cacheentry *tail = NULL;

            NLib::KVHashMap<uint64_t, struct cacheentry *> cachemap;

            NLib::KVHashMap<uint64_t, struct inflight *> inflightmap; // Map of LBAs currently being loaded.

            NArch::Spinlock cachelock;
            size_t capacity;
            size_t blocksize;
            BlockDevice *dev = NULL;
        public:
            BlockCache(BlockDevice *dev, size_t capacity, size_t blocksize);
            ~BlockCache();

            // Get a victim to evict from cache.
            struct cacheentry *selectvict(void);
            // Evict entries until under capacity.
            void evict(void);

            // Read a block from cache or device.
            int read(uint64_t lba, void *buffer);
            // Write a block to cache and mark dirty.
            int write(uint64_t lba, const void *buffer);
            void flush(void);
    };

}

#endif