#ifndef __DEV__BLOCK_HPP
#define __DEV__BLOCK_HPP

#include <dev/dev.hpp>
#include <dev/blockcache.hpp>

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
            BlockCache *cache = NULL;
        public:
            size_t blksize = 512;
            bool ispart = false;
            uint64_t startlba = 0;
            uint64_t lastlba = 0;

            BlockDevice(uint64_t id, DevDriver *driver) : Device(id, driver) { }
            BlockDevice(uint64_t id, DevDriver *driver, uint64_t startlba, uint64_t lastlba) : Device(id, driver) {
                // Adds additional offset for partition.
                this->ispart = true;
                this->startlba = startlba;
                this->lastlba = lastlba;
            }
            ~BlockDevice() = default;

            // Read block-wise from device. Must be implemented by driver.
            virtual ssize_t readblock(uint64_t lba, void *buf) = 0;
            // Write block-wise to device. Must be implemented by driver.
            virtual ssize_t writeblock(uint64_t lba, const void *buf) = 0;

            // Read raw bytes from block device, goes through cache.
            virtual ssize_t readbytes(void *buf, size_t count, off_t offset, int fdflags);
            // Write raw bytes to block device, goes through cache.
            virtual ssize_t writebytes(const void *buf, size_t count, off_t offset, int fdflags);
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