#include <dev/block.hpp>
#include <dev/drivers/ata/driver.hpp>
#include <fs/devfs.hpp>

#include <mm/slab.hpp>
#include <mm/ucopy.hpp>


namespace NDev {
    ssize_t AHCIDriver::read(uint64_t dev, void *buf, size_t count, off_t offset, int fdflags) {
        if (NFS::DEVFS::major(dev) != AHCIDriver::ATABLKMAJOR && NFS::DEVFS::major(dev) != AHCIDriver::ATAPIBLKMAJOR) {
            return -ENODEV;
        }

        BlockDevice *blkdev = (BlockDevice *)registry->get(dev);
        if (!blkdev) {
            return -ENODEV;
        }

        if (!NMem::UserCopy::valid(buf, count)) {
            return -EFAULT;
        }

        return blkdev->readbytes(buf, count, offset, fdflags, NDev::IO_RAW);
    }

    ssize_t AHCIDriver::write(uint64_t dev, const void *buf, size_t count, off_t offset, int fdflags) {
        if (NFS::DEVFS::major(dev) != AHCIDriver::ATABLKMAJOR && NFS::DEVFS::major(dev) != AHCIDriver::ATAPIBLKMAJOR) {
            return -ENODEV;
        }

        BlockDevice *blkdev = (BlockDevice *)registry->get(dev);
        if (!blkdev) {
            return -ENODEV;
        }

        if (!NMem::UserCopy::valid(buf, count)) {
            return -EFAULT;
        }

        return blkdev->writebytes(buf, count, offset, fdflags, NDev::IO_RAW);
    }
}