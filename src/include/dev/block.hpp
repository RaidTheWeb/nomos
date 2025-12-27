#ifndef _DEV__BLOCK_HPP
#define _DEV__BLOCK_HPP

#include <dev/dev.hpp>

// Forward declaration for page cache support.
namespace NMem {
    class PageCache;
    class RadixTree;
    class CachePage;
}

namespace NDev {

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

    class BlockDevice : public Device {
        protected:
            NMem::RadixTree *pagecache = NULL; // Device-level page cache.
        public:
            size_t blksize = 512;
            uint64_t startlba = 0;
            uint64_t lastlba = 0;

            BlockDevice(uint64_t id, DevDriver *driver) : Device(id, driver) { }
            ~BlockDevice();

            // Read block-wise from device. Must be implemented by driver.
            virtual ssize_t readblock(uint64_t lba, void *buf) = 0;
            // Write block-wise to device. Must be implemented by driver.
            virtual ssize_t writeblock(uint64_t lba, const void *buf) = 0;

            virtual ssize_t readblocks(uint64_t lba, size_t count, void *buf);
            virtual ssize_t writeblocks(uint64_t lba, size_t count, const void *buf);

            // Read raw bytes from block device, goes through cache.
            virtual ssize_t readbytes(void *buf, size_t count, off_t offset, int fdflags);
            // Write raw bytes to block device, goes through cache.
            virtual ssize_t writebytes(const void *buf, size_t count, off_t offset, int fdflags);

            ssize_t readbytespagecache(void *buf, size_t count, off_t offset);
            ssize_t writebytespagecache(const void *buf, size_t count, off_t offset);

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