#ifndef _DEV__DRIVERS__NVME__DRIVER_HPP
#define _DEV__DRIVERS__NVME__DRIVER_HPP

#include <dev/drivers/nvme/defs.hpp>
#include <dev/block.hpp>
#include <dev/blockcache.hpp>
#include <std/stddef.h>

namespace NDev {
    using namespace NFS;

    class NVMEDriver : public DevDriver {
        public:
            static const uint32_t NSBLKMAJOR = 259; // NVMe specification major version we support.
            struct nvmectrl controllers[MAXCTRL];
            size_t ctrlcount = 0;
            NVMEDriver();
            ~NVMEDriver();

            void initnamespace(struct nvmectrl *ctrl, struct nvmens *ns);
            void probe(struct devinfo info) override;


            int iorequest(struct nvmectrl *ctrl, uint16_t id, uint8_t opcode, uint32_t nsid, uint64_t lba, uint16_t sectors, void *buffer, size_t size);

            ssize_t read(uint64_t dev, void *buf, size_t count, off_t offset, int fdflags) override;
            ssize_t write(uint64_t dev, const void *buf, size_t count, off_t offset, int fdflags) override;

            int mmap(uint64_t dev, void *addr, size_t offset, uint64_t flags, int fdflags) override;
            int munmap(uint64_t dev, void *addr, int fdflags) override;
    };

    class NVMEBlockDevice : public BlockDevice {
        public:
            struct nvmectrl *ctrl;
            struct nvmens *ns;
        public:
            NVMEBlockDevice(uint64_t id, NVMEDriver *driver, struct nvmectrl *ctrl, struct nvmens *ns) : BlockDevice(id, driver) {
                this->ctrl = ctrl;
                this->ns = ns;
                this->blksize = ns->blksize;
                this->cache = new BlockCache(this, 2, ns->blksize); // 64MB cache.
            }
            ~NVMEBlockDevice();

            ssize_t readblock(uint64_t lba, void *buffer) override {
                size_t blksize = ns->blksize;
                return ((NVMEDriver *)driver)->iorequest(ctrl, ns->nsnum + 1, IOREAD, ns->nsid, lba, 1, buffer, blksize);
            }

            ssize_t writeblock(uint64_t lba, const void *buffer) override {
                return -1;
            }
    };
}

#endif