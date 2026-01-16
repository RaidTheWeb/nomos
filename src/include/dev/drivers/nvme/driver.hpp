#ifndef _DEV__DRIVERS__NVME__DRIVER_HPP
#define _DEV__DRIVERS__NVME__DRIVER_HPP

#include <dev/drivers/nvme/defs.hpp>
#include <dev/block.hpp>
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
            int iorequest_async(struct nvmectrl *ctrl, uint16_t id, uint8_t opcode, uint32_t nsid, uint64_t lba, uint16_t sectors, void *buffer, size_t size, struct nvmepending **pending);

            int waitpending(struct nvmepending *pending);
            int waitmultiple(struct nvmepending **pendings, size_t count);


            ssize_t read(uint64_t dev, void *buf, size_t count, off_t offset, int fdflags) override;
            ssize_t write(uint64_t dev, const void *buf, size_t count, off_t offset, int fdflags) override;

            int mmap(uint64_t dev, void *addr, size_t count, size_t offset, uint64_t flags, int fdflags) override;
            int munmap(uint64_t dev, void *addr, size_t count, size_t offset, int fdflags) override;
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
            }

            ~NVMEBlockDevice();

            ssize_t readblock(uint64_t lba, void *buffer) override {
                size_t blksize = ns->blksize;
                return ((NVMEDriver *)driver)->iorequest(ctrl, ns->nsnum + 1, IOREAD, ns->nsid, lba, 1, buffer, blksize);
            }

            ssize_t writeblock(uint64_t lba, const void *buffer) override {
                size_t blksize = ns->blksize;
                return ((NVMEDriver *)driver)->iorequest(ctrl, ns->nsnum + 1, IOWRITE, ns->nsid, lba, 1, (void *)buffer, blksize);
            }

            // Multi-block read using single NVMe command for better performance.
            ssize_t readblocks(uint64_t lba, size_t count, void *buffer) override {
                if (count == 0) {
                    return 0;
                }
                if (count == 1) {
                    return readblock(lba, buffer);
                }

                size_t maxsectors = 256;
                size_t blksize = ns->blksize;
                uint8_t *buf = (uint8_t *)buffer;
                size_t remaining = count;
                uint64_t curlba = lba;
                while (remaining > 0) {
                    size_t batch = (remaining > maxsectors) ? maxsectors : remaining;
                    ssize_t res = ((NVMEDriver *)driver)->iorequest(ctrl, ns->nsnum + 1, IOREAD, ns->nsid, curlba, batch, buf, batch * blksize);

                    if (res < 0) {
                        return res;
                    }

                    buf += batch * blksize;
                    curlba += batch;
                    remaining -= batch;
                }
                return 0;
            }

            ssize_t writeblocks(uint64_t lba, size_t count, const void *buffer) override {
                if (count == 0) {
                    return 0;
                }
                if (count == 1) {
                    return writeblock(lba, buffer);
                }

                size_t maxsectors = 256;
                size_t blksize = ns->blksize;
                const uint8_t *buf = (const uint8_t *)buffer;
                size_t remaining = count;
                uint64_t curlba = lba;
                while (remaining > 0) {
                    size_t batch = (remaining > maxsectors) ? maxsectors : remaining;
                    ssize_t res = ((NVMEDriver *)driver)->iorequest(ctrl, ns->nsnum + 1, IOWRITE, ns->nsid, curlba, batch, (void *)buf, batch * blksize);

                    if (res < 0) {
                        return res;
                    }

                    buf += batch * blksize;
                    curlba += batch;
                    remaining -= batch;
                }
                return 0;
            }

            int submitbio(struct bioreq *req) override {
                struct nvmepending *pending = NULL;
                int res = ((NVMEDriver *)driver)->iorequest_async(ctrl, ns->nsnum + 1,
                    req->op == bioreq::BIO_READ ? IOREAD : IOWRITE,
                    ns->nsid,
                    req->lba,
                    req->count,
                    req->buffer,
                    req->bufsize,
                    &pending);

                if (res < 0) {
                    return res;
                }

                req->ddata = (void *)pending;
                pending->bio = req;
                __atomic_store_n(&req->submitted, true, memory_order_release);
                return 0;
            }

            int waitbio(struct bioreq *req) override {
                struct nvmepending *pending = (struct nvmepending *)req->ddata;
                if (!pending) {
                    return -EINVAL;
                }
                int res = ((NVMEDriver *)driver)->waitpending(pending);
                req->status = res;
                __atomic_store_n(&req->completed, true, memory_order_release);

                req->wq.wake();
                return res;
            }
    };
}

#endif