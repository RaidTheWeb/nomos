#include <dev/block.hpp>
#include <mm/ucopy.hpp>

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
        return -1;
    }


    // Write raw bytes to block device, goes through cache.
    ssize_t BlockDevice::writebytes(const void *buf, size_t count, off_t offset, int fdflags) {
        return -1;
    }
}