#ifndef _DEV__DRIVERES__ATA__DRIVER_HPP
#define _DEV__DRIVERES__ATA__DRIVER_HPP

#include <dev/block.hpp>
#include <dev/drivers/ata/defs.hpp>

#include <std/stddef.h>

namespace NDev {


    class AHCIDriver : public DevDriver {
        public:
            static const uint32_t ATABLKMAJOR = 8; // XXX: Create a major registry, so we can handle allocations.
            static const uint32_t ATAPIBLKMAJOR = 11; // SCSI CD-ROM major number, used for ATAPI devices.
            struct ahcictrl controllers[MAXCTRLS];
            size_t ctrlcount = 0;

            AHCIDriver();
            ~AHCIDriver();

            void probe(struct devinfo info) override;

            void initport(struct ahcictrl *ctrl, struct ahciport *port);

            int atacommand(struct ahcictrl *ctrl, struct ahciport *port, uint8_t cmd, uint64_t lba, uint16_t count, void *buf, size_t size, bool iswrite);
            int atacommand_async(struct ahcictrl *ctrl, struct ahciport *port, uint8_t cmd, uint64_t lba, uint16_t count, void *buf, size_t size, bool iswrite, struct ahcipending **pending, struct bioreq *bio = NULL);
            int atapicommand(struct ahcictrl *ctrl, struct ahciport *port, const uint8_t *cdb, size_t cdblen, void *buf, size_t size, bool iswrite);
            int atapicommand_async(struct ahcictrl *ctrl, struct ahciport *port, const uint8_t *cdb, size_t cdblen, void *buf, size_t size, bool iswrite, struct ahcipending **pending, struct bioreq *bio = NULL);

            int waitpending(struct ahcipending *pending);
            int waitmultiple(struct ahcipending **pendings, size_t count);

            ssize_t read(uint64_t dev, void *buf, size_t count, off_t offset, int fdflags) override;
            ssize_t write(uint64_t dev, const void *buf, size_t count, off_t offset, int fdflags) override;
    };

    static inline uint32_t ataminor(uint32_t ctrl, uint32_t port, uint32_t part) {
        return (ctrl << 8) | (port << 4) | (part & 0xf);
    }

    class ATABlockDevice : public BlockDevice {
        public:
            struct ahcictrl *ctrl;
            struct ahciport *port;

            ATABlockDevice(uint64_t id, AHCIDriver *driver, struct ahcictrl *ctrl, struct ahciport *port) : BlockDevice(id, driver) {
                this->ctrl = ctrl;
                this->port = port;
                this->blksize = port->sectorsize;
                this->startlba = 0;
                this->lastlba = port->numsectors - 1;
            }

            ssize_t readblock(uint64_t lba, void *buffer) override {
                return ((AHCIDriver *)driver)->atacommand(ctrl, port, ATACMD_READDMAEXT, lba, 1, buffer, port->sectorsize, false);
            }

            ssize_t writeblock(uint64_t lba, const void *buffer) override {
                return ((AHCIDriver *)driver)->atacommand(ctrl, port, ATACMD_WRITEDMAEXT, lba, 1, (void *)buffer, port->sectorsize, true);
            }

            ssize_t readblocks(uint64_t lba, size_t count, void *buffer) override {
                if (count == 0) {
                    return 0;
                }
                if (count == 1) {
                    return readblock(lba, buffer);
                }

                size_t maxsectors = 256;
                size_t blksize = port->sectorsize;
                uint8_t *buf = (uint8_t *)buffer;
                size_t remaining = count;
                uint64_t curlba = lba;
                while (remaining > 0) {
                    size_t batch = (remaining > maxsectors) ? maxsectors : remaining;
                    ssize_t res = ((AHCIDriver *)driver)->atacommand(ctrl, port, ATACMD_READDMAEXT, curlba, batch, buf, batch * blksize, false);

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
                size_t blksize = port->sectorsize;
                const uint8_t *buf = (const uint8_t *)buffer;
                size_t remaining = count;
                uint64_t curlba = lba;
                while (remaining > 0) {
                    size_t batch = (remaining > maxsectors) ? maxsectors : remaining;
                    ssize_t res = ((AHCIDriver *)driver)->atacommand(ctrl, port, ATACMD_WRITEDMAEXT, curlba, batch, (void *)buf, batch * blksize, true);

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
                struct ahcipending *pending = NULL;
                int res = ((AHCIDriver *)driver)->atacommand_async(ctrl, port,
                    req->op == bioreq::BIO_READ ? ATACMD_READDMAEXT : ATACMD_WRITEDMAEXT,
                    req->lba,
                    req->count,
                    req->buffer,
                    req->count * port->sectorsize,
                    req->op == bioreq::BIO_WRITE,
                    &pending,
                    req);

                if (res < 0) {
                    return res;
                }

                req->ddata = pending;
                __atomic_store_n(&req->submitted, true, memory_order_release);
                return 0;
            }

            int waitbio(struct bioreq *req) override {
                struct ahcipending *pending = (struct ahcipending *)req->ddata;
                if (!pending) {
                    return -EINVAL;
                }

                int res = ((AHCIDriver *)driver)->waitpending(pending);
                req->status = res;
                __atomic_store_n(&req->completed, true, memory_order_release);

                req->wq.wake();
                return res;
            }

            bool hasasyncio() const override {
                return true;
            }
    };

    class ATAPIBlockDevice : public BlockDevice {
        public:
            struct ahcictrl *ctrl;
            struct ahciport *port;

            ATAPIBlockDevice(uint64_t id, AHCIDriver *driver, struct ahcictrl *ctrl, struct ahciport *port) : BlockDevice(id, driver) {
                this->ctrl = ctrl;
                this->port = port;
                this->blksize = port->sectorsize;
                this->startlba = 0;
                this->lastlba = port->numsectors > 0 ? port->numsectors - 1 : 0;
            }

            ssize_t readblock(uint64_t lba, void *buffer) override {
                uint8_t cdb[12] = {};
                cdb[0] = SCSICMD_READ10;
                cdb[2] = (uint8_t)((lba >> 24) & 0xff);
                cdb[3] = (uint8_t)((lba >> 16) & 0xff);
                cdb[4] = (uint8_t)((lba >> 8) & 0xff);
                cdb[5] = (uint8_t)(lba & 0xff);
                cdb[7] = 0;
                cdb[8] = 1;
                return ((AHCIDriver *)driver)->atapicommand(ctrl, port, cdb, 12, buffer, port->sectorsize, false);
            }

            ssize_t writeblock(uint64_t lba, const void *buffer) override {
                uint8_t cdb[12] = {};
                cdb[0] = SCSICMD_WRITE10;
                cdb[2] = (uint8_t)((lba >> 24) & 0xff);
                cdb[3] = (uint8_t)((lba >> 16) & 0xff);
                cdb[4] = (uint8_t)((lba >> 8) & 0xff);
                cdb[5] = (uint8_t)(lba & 0xff);
                cdb[7] = 0;
                cdb[8] = 1;
                return ((AHCIDriver *)driver)->atapicommand(ctrl, port, cdb, 12, (void *)buffer, port->sectorsize, true);
            }

            ssize_t readblocks(uint64_t lba, size_t count, void *buffer) override {
                if (count == 0) {
                    return 0;
                }

                size_t maxsectors = (PRDTMAX * 0x1000) / port->sectorsize;
                if (maxsectors > 65535) {
                    maxsectors = 65535;
                }

                uint8_t *buf = (uint8_t *)buffer;
                size_t remaining = count;
                uint64_t curlba = lba;

                while (remaining > 0) {
                    size_t batch = (remaining > maxsectors) ? maxsectors : remaining;

                    uint8_t cdb[12] = {};
                    cdb[0] = SCSICMD_READ10;
                    cdb[2] = (uint8_t)((curlba >> 24) & 0xff);
                    cdb[3] = (uint8_t)((curlba >> 16) & 0xff);
                    cdb[4] = (uint8_t)((curlba >> 8) & 0xff);
                    cdb[5] = (uint8_t)(curlba & 0xff);
                    cdb[7] = (uint8_t)((batch >> 8) & 0xff);
                    cdb[8] = (uint8_t)(batch & 0xff);

                    ssize_t res = ((AHCIDriver *)driver)->atapicommand(ctrl, port, cdb, 12, buf, batch * port->sectorsize, false);
                    if (res < 0) {
                        return res;
                    }

                    buf += batch * port->sectorsize;
                    curlba += batch;
                    remaining -= batch;
                }

                return 0;
            }

            ssize_t writeblocks(uint64_t lba, size_t count, const void *buffer) override {
                if (count == 0) {
                    return 0;
                }

                size_t maxsectors = (PRDTMAX * 0x1000) / port->sectorsize;
                if (maxsectors > 65535) {
                    maxsectors = 65535;
                }

                const uint8_t *buf = (const uint8_t *)buffer;
                size_t remaining = count;
                uint64_t curlba = lba;

                while (remaining > 0) {
                    size_t batch = (remaining > maxsectors) ? maxsectors : remaining;

                    uint8_t cdb[12] = {};
                    cdb[0] = SCSICMD_WRITE10;
                    cdb[2] = (uint8_t)((curlba >> 24) & 0xff);
                    cdb[3] = (uint8_t)((curlba >> 16) & 0xff);
                    cdb[4] = (uint8_t)((curlba >> 8) & 0xff);
                    cdb[5] = (uint8_t)(curlba & 0xff);
                    cdb[7] = (uint8_t)((batch >> 8) & 0xff);
                    cdb[8] = (uint8_t)(batch & 0xff);

                    ssize_t res = ((AHCIDriver *)driver)->atapicommand(ctrl, port, cdb, 12, (void *)buf, batch * port->sectorsize, true);
                    if (res < 0) {
                        return res;
                    }

                    buf += batch * port->sectorsize;
                    curlba += batch;
                    remaining -= batch;
                }

                return 0;
            }

            int submitbio(struct bioreq *req) override {
                uint8_t cdb[12] = {};
                cdb[0] = (req->op == bioreq::BIO_READ) ? SCSICMD_READ10 : SCSICMD_WRITE10;
                cdb[2] = (uint8_t)((req->lba >> 24) & 0xff);
                cdb[3] = (uint8_t)((req->lba >> 16) & 0xff);
                cdb[4] = (uint8_t)((req->lba >> 8) & 0xff);
                cdb[5] = (uint8_t)(req->lba & 0xff);
                cdb[7] = (uint8_t)((req->count >> 8) & 0xff);
                cdb[8] = (uint8_t)(req->count & 0xff);

                struct ahcipending *pending = NULL;
                int res = ((AHCIDriver *)driver)->atapicommand_async(ctrl, port, cdb, 12, req->buffer, req->count * port->sectorsize, req->op == bioreq::BIO_WRITE, &pending, req);
                if (res < 0) {
                    return res;
                }

                req->ddata = pending;
                __atomic_store_n(&req->submitted, true, memory_order_release);
                return 0;
            }

            int waitbio(struct bioreq *req) override {
                struct ahcipending *pending = (struct ahcipending *)req->ddata;
                if (!pending) {
                    return -EINVAL;
                }

                int res = ((AHCIDriver *)driver)->waitpending(pending);
                req->status = res;
                __atomic_store_n(&req->completed, true, memory_order_release);
                req->wq.wake();
                return res;
            }

            bool hasasyncio() const override {
                return true;
            }
    };
}

#endif