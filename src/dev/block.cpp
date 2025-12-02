#include <dev/block.hpp>
#include <mm/ucopy.hpp>

#define MIN(a, b) ((a) < (b) ? (a) : (b))

namespace NDev {

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


    // Read raw bytes from block device, goes through cache.
    ssize_t BlockDevice::readbytes(void *buf, size_t count, off_t offset, int fdflags) {
        for (size_t pos = 0; pos < count; ) {
            uint64_t lba = (offset + pos) / this->blksize;
            size_t blkoff = (offset + pos) % this->blksize;
            size_t toread = MIN(this->blksize - blkoff, count - pos);

            int res = this->cache->read(lba + this->startlba, (uint8_t *)buf + pos, blkoff, toread);
            if (res != 0) {
                return res;
            }

            pos += toread;
        }
        return count;
    }


    // Write raw bytes to block device, goes through cache.
    ssize_t BlockDevice::writebytes(const void *buf, size_t count, off_t offset, int fdflags) {
        for (size_t pos = 0; pos < count; ) {
            uint64_t lba = (offset + pos) / this->blksize;
            size_t blkoff = (offset + pos) % this->blksize;
            size_t towrite = MIN(this->blksize - blkoff, count - pos);

            int res = this->cache->write(lba + this->startlba, (const uint8_t *)buf + pos, blkoff, towrite);
            if (res != 0) {
                return res;
            }

            pos += towrite;
        }
        return count;
    }

    struct parttableinfo *getpartinfo(BlockDevice *dev) {
        // Check if MBR or GPT.
        uint8_t mbrsector[512];
        ssize_t res = dev->readblock(0, mbrsector); // XXX: Use cached read.
        if (res != 0) {
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