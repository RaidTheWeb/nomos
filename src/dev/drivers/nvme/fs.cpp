#include <dev/block.hpp>
#include <dev/blockcache.hpp>
#include <dev/drivers/nvme/driver.hpp>
#include <fs/devfs.hpp>

#include <mm/slab.hpp>
#include <mm/ucopy.hpp>

namespace NDev {
    using namespace NFS;

    ssize_t NVMEDriver::read(uint64_t dev, void *buf, size_t count, off_t offset, int fdflags) {
        uint32_t major = DEVFS::major(dev);
        NUtil::printf("Hello!.\n");

        if (major == NSBLKMAJOR) {

            // Find the block device.
            NVMEBlockDevice *blkdev = (NVMEBlockDevice *)registry->get(dev);

            if (blkdev) {
                return blkdev->readbytes(buf, count, offset, fdflags);
            }
            return -ENODEV;
        }

        return -1;
    }

    ssize_t NVMEDriver::write(uint64_t dev, const void *buf, size_t count, off_t offset, int fdflags) {
        (void)dev;
        (void)buf;
        (void)count;
        (void)offset;
        (void)fdflags;
        return 0;
    }

    int NVMEDriver::mmap(uint64_t dev, void *addr, size_t offset, uint64_t flags, int fdflags) {
        (void)dev;
        (void)addr;
        (void)offset;
        (void)flags;
        (void)fdflags;
        return -EFAULT;
    }

    int NVMEDriver::munmap(uint64_t dev, void *addr, int fdflags) {
        (void)dev;
        (void)addr;
        (void)fdflags;
        return -EFAULT;
    }
}