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

            int res = this->cache->read(lba, (uint8_t *)buf + pos, blkoff, toread);
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

            int res = this->cache->write(lba, (const uint8_t *)buf + pos, blkoff, towrite);
            if (res != 0) {
                return res;
            }

            pos += towrite;
        }
        this->cache->flush();
        return count;
    }
}