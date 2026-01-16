#ifndef _DEV__BLOCK_HPP
#define _DEV__BLOCK_HPP

#include <dev/dev.hpp>
#include <sched/event.hpp>

// Forward declaration for page cache support.
namespace NMem {
    class PageCache;
    class RadixTree;
    class CachePage;
}

namespace NDev {

    // Forward declaration for bioreq.
    class BlockDevice;

    // MBR partition entry structure.
    struct mbrpartentry {
        uint8_t bootable; // Can we boot from this partition?
        uint8_t starthead;
        uint8_t startsector;
        uint8_t startcylinder;
        uint8_t type; // What type of partition this is?
        uint8_t endhead;
        uint8_t endsector;
        uint8_t endcylinder;
        uint32_t firstlba; // Offset of partition.
        uint32_t sectors; // Size of partition in sectors.
    } __attribute__((packed));

    // GPT header structure.
    struct gptheader {
        uint64_t signature; // "EFI PART" signature.
        uint32_t rev; // Revision.
        uint32_t size; // Size of header in bytes.
        uint32_t crc32; // CRC32 of header.
        uint32_t rsvd0;
        uint64_t hdrlba; // LBA of this header.
        uint64_t altlba; // LBA of alternate header.
        uint64_t firstlba; // First usable LBA for partitions.
        uint64_t lastlba; // Last usable LBA for partitions.
        uint8_t guid[16]; // Disk GUID.
        uint64_t partlba; // Starting LBA of partition entries.
        uint32_t numparts; // Number of partition entries.
        uint32_t partsize; // Size of a single partition entry.
        uint32_t partcrc32; // CRC32 of partition entries.
    } __attribute__((packed));

    // GPT partition entry structure.
    struct gptpartentry {
        uint8_t tuid[16]; // Partition type GUID.
        uint8_t uguid[16]; // Unique partition GUID.
        uint64_t firstlba;
        uint64_t lastlba;
        uint64_t attrs;
        uint16_t name[36]; // Partition name.
    } __attribute__((packed));

    enum parttype {
        PARTTYPE_NONE   = 0,
        PARTTYPE_MBR    = 1,
        PARTTYPE_GPT    = 2
    };


    // Async I/O request structure.
    struct bioreq {
        enum opcode {
            BIO_READ,
            BIO_WRITE
        };

        BlockDevice *dev = NULL;
        enum opcode op;
        uint64_t lba; // Starting LBA.
        size_t count; // Number of blocks.
        void *buffer = NULL;
        size_t bufsize = 0;

        NSched::WaitQueue wq;
        volatile bool submitted = false; // Has the I/O been submitted?
        volatile bool completed = false; // Has the I/O completed?
        volatile int status = 0; // Status code (zero means success).

        void *udata; // Driver-specific private data.
        void *ddata; // Driver-specific data for tracking pending I/O.

        void (*callback)(struct bioreq *req) = NULL; // Callback to call on completion.

        struct bioreq *next = NULL; // Next request in batch (for batch async I/O).

        void init(BlockDevice *dev, enum opcode op, uint64_t lba, size_t count, void *buffer, size_t bufsize) {
            this->dev = dev;
            this->op = op;
            this->lba = lba;
            this->count = count;
            this->buffer = buffer;
            this->bufsize = bufsize;
            this->udata = NULL;
            this->next = NULL;
        }
    };

    // I/O context flags for block device operations.
    enum IOContext {
        IO_DIRECT     = 0,        // Direct I/O, bypass cache (default, used by readpage/writepage when writing filedata from readpage/writepage methods).
        IO_METADATA   = (1 << 0), // Metadata read/write, safe to cache.
        IO_RAW        = (1 << 1), // Raw device access from userspace (eg. read from /dev/nvme0n1), safe to cache.
    };

    // Block devices are also fairly complicated.
    // Generally speaking, the driver should implement a BlockDevice subclass
    // that implements readblock() and writeblock() methods (and optionally readblocks()/writeblocks() for better performance).
    // The BlockDevice class implements higher-level readbytes() and writebytes() methods that handle
    // unaligned reads/writes and context-aware caching via page cache.
    // Partitions should be handled by creating PartitionBlockDevice instances that wrap a parent custom BlockDevice subclass.

    // Block device base class.
    class BlockDevice : public Device {
        protected:
            NMem::RadixTree *pagecache = NULL; // Device-level page cache.
        public:
            size_t blksize = 512;
            uint64_t startlba = 0;
            uint64_t lastlba = 0;

            BlockDevice(uint64_t id, DevDriver *driver) : Device(id, driver) { }
            ~BlockDevice();

            // Block-wise read/write methods.

            // Read block-wise from device. Must be implemented by driver.
            virtual ssize_t readblock(uint64_t lba, void *buf) = 0;
            // Write block-wise to device. Must be implemented by driver.
            virtual ssize_t writeblock(uint64_t lba, const void *buf) = 0;

            virtual ssize_t readblocks(uint64_t lba, size_t count, void *buf);
            virtual ssize_t writeblocks(uint64_t lba, size_t count, const void *buf);


            // Byte-wise read/write wrapping block I/O.

            // Read/write raw bytes from block device with context-aware caching.
            // CRITICAL: Never call with IO_METADATA from within readpage/writepage!
            virtual ssize_t readbytes(void *buf, size_t count, off_t offset, int fdflags, IOContext ctx = IO_DIRECT);
            virtual ssize_t writebytes(const void *buf, size_t count, off_t offset, int fdflags, IOContext ctx = IO_DIRECT);

            // Direct I/O methods (bypass page cache), used internally and by page I/O.
            ssize_t readbytesdirect(void *buf, size_t count, off_t offset);
            ssize_t writebytesdirect(const void *buf, size_t count, off_t offset);

            // Page cache I/O methods (use page cache), used internally and by metadata/raw I/O.
            ssize_t readbytespagecache(void *buf, size_t count, off_t offset);
            ssize_t writebytespagecache(const void *buf, size_t count, off_t offset);


            // Async I/O methods.
            virtual int submitbio(struct bioreq *req);
            virtual int waitbio(struct bioreq *req);
            virtual int cancelbio(struct bioreq *req);

            virtual int submitbiobatch(struct bioreq **reqs, size_t count);
            virtual int waitbiobatch(struct bioreq **reqs, size_t count);

            virtual int readblocks_async(uint64_t lba, size_t count, void *buf, struct bioreq **outreq);
            virtual int writeblocks_async(uint64_t lba, size_t count, const void *buf, struct bioreq **outreq);



            // Page I/O implementations.

            // Read a page from device into page cache entry.
            int readpagedata(void *pagebuf, off_t pageoffset);
            // Write a page from page cache entry to device.
            int writepagedata(const void *pagebuf, off_t pageoffset);

            // Get or create page cache radix tree.
            NMem::RadixTree *getpagecache(void);

            // Find cached page by offset.
            NMem::CachePage *findcachedpage(off_t offset);

            // Find or create cached page.
            NMem::CachePage *getorcachepage(off_t offset);

            // Sync all cached data to device.
            int syncdevice(void);

            // Invalidate all cached pages.
            void invalidatecache(void);
    };

    class PartitionBlockDevice : public BlockDevice {
        public:
            BlockDevice *parent = NULL;

            PartitionBlockDevice(uint64_t id, DevDriver *driver, BlockDevice *parent, uint64_t startlba, uint64_t lastlba) : BlockDevice(id, driver) {
                this->parent = parent;
                this->blksize = parent->blksize;
                this->startlba = startlba;
                this->lastlba = lastlba;
            }

            ~PartitionBlockDevice() = default;

            ssize_t readblock(uint64_t lba, void *buffer) override {
                return this->parent->readblock(lba + this->startlba, buffer);
            }

            ssize_t writeblock(uint64_t lba, const void *buffer) override {
                return this->parent->writeblock(lba + this->startlba, buffer);
            }

            ssize_t readblocks(uint64_t lba, size_t count, void *buffer) override {
                return this->parent->readblocks(lba + this->startlba, count, buffer);
            }

            ssize_t writeblocks(uint64_t lba, size_t count, const void *buffer) override {
                return this->parent->writeblocks(lba + this->startlba, count, buffer);
            }
    };

    struct partinfo {
        uint64_t firstlba = 0;
        uint64_t lastlba = 0;
    };

    struct parttableinfo {
        enum parttype type = PARTTYPE_NONE;
        size_t numparts = 0;
        struct partinfo *partitions = NULL;
    };

    // Get partition table info from block device, owner is expected to free returned struct.
    struct parttableinfo *getpartinfo(BlockDevice *dev);
}

#endif