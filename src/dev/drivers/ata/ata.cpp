#ifdef __x86_64__
#include <arch/x86_64/interrupts.hpp>
#include <arch/x86_64/cpu.hpp>
#include <arch/x86_64/tsc.hpp>
#include <arch/x86_64/vmm.hpp>
#endif

#include <dev/drivers/ata/defs.hpp>
#include <dev/drivers/ata/driver.hpp>
#include <dev/pci.hpp>

namespace NDev {
    static constexpr uint64_t IOTIMEOUTUS = 5000000;

    int waitio(struct ahcipending *pending) {
        uint64_t hz = NArch::TSC::hz;
        uint64_t submittsc = __atomic_load_n(&pending->submittsc, memory_order_acquire);
        uint64_t deadline = submittsc + (IOTIMEOUTUS * hz) / 1000000;

        pending->wq.waitinglock.acquire();
        while (!__atomic_load_n(&pending->done, memory_order_acquire)) {
            uint64_t now = NArch::TSC::query();
            if (now > deadline) {
                pending->wq.waitinglock.release();
                NUtil::printf("[dev/ata]: I/O request timed out after %lu us.\n", IOTIMEOUTUS);

                struct ahciport *port = pending->port;
                port->portlock.acquire();
                __atomic_store_n(&pending->issued, false, memory_order_release);
                // Acquire status under lock.
                bool alreadydone = __atomic_load_n(&pending->done, memory_order_acquire);
                port->portlock.release();

                if (alreadydone) { // Bail out early if possible.
                    int status = __atomic_load_n(&pending->status, memory_order_acquire);
                    __atomic_store_n(&pending->inuse, false, memory_order_release);
                    return status;
                }

                __atomic_store_n(&pending->inuse, false, memory_order_release);
                return -ETIMEDOUT;
            }

            pending->wq.preparewait();
            pending->wq.waitinglock.release();
            NSched::yield();
            pending->wq.waitinglock.acquire();
            pending->wq.finishwait(true);
        }

        pending->wq.waitinglock.release();
        int status = __atomic_load_n(&pending->status, memory_order_acquire);
        __atomic_store_n(&pending->inuse, false, memory_order_release);
        return status;
    }

    int allocslot(struct ahcictrl *ctrl, struct ahciport *port, int *outslot, struct ahcipending **outpending) {
        int retries = 0;
        while (true) {
            for (size_t i = 0; i <= ctrl->nslots; i++) {
                bool expected = false;
                if (__atomic_compare_exchange_n(&port->pendings[i].inuse, &expected, true, false, memory_order_acq_rel, memory_order_acquire)) {
                    struct ahcipending *pending = &port->pendings[i];
                    pending->port = port;
                    __atomic_store_n(&pending->done, false, memory_order_release);
                    __atomic_store_n(&pending->status, 0, memory_order_release);
                    __atomic_store_n(&pending->issued, false, memory_order_release);
                    pending->callback = NULL;
                    pending->udata = NULL;
                    pending->bio = NULL;
                    *outslot = (int)i;
                    *outpending = pending;
                    return 0;
                }
            }

            if (retries++ > 100) {
                NUtil::printf("[dev/ata]: No pending slots available after %d retries.\n", retries);
                return -EBUSY;
            }

            NSched::yield();
        }
    }

    static int setupcommand(struct ahcictrl *ctrl, struct ahciport *port, int slot, struct ahcipending *pending, uint8_t cmd, uint64_t lba, uint16_t count, void *buf, size_t size, bool iswrite) {
        struct ahcicmdhdr *hdr = &port->cmdlist[slot];
        NLib::memset(hdr, 0, sizeof(struct ahcicmdhdr));

        uintptr_t ctphys = NArch::VMM::virt2phys(&NArch::VMM::kspace, (uintptr_t)&port->cmdtables[slot]);
        hdr->ctba = (uint32_t)(ctphys & 0xffffffff);
        hdr->ctbau = (uint32_t)(ctphys >> 32);

        hdr->cfl = sizeof(struct atah2d) / sizeof(uint32_t);
        hdr->w = iswrite ? 1 : 0;
        hdr->c = 1; // Clear busy upon R_OK.
        hdr->prdtl = 0; // Will be set by PRDT building below.

        struct ahcicmdtable *cmdtable = &port->cmdtables[slot];
        NLib::memset(cmdtable, 0, sizeof(struct ahcicmdtable));

        // Initialise command FIS.
        struct atah2d *cfis = (struct atah2d *)cmdtable->cfis;
        cfis->type = FISTYPE_H2D;
        cfis->c = 1;
        cfis->cmd = cmd;
        cfis->device = FISDEVLBA;

        cfis->lba0 = (uint8_t)(lba & 0xff);
        cfis->lba1 = (uint8_t)((lba >> 8) & 0xff);
        cfis->lba2 = (uint8_t)((lba >> 16) & 0xff);
        cfis->lba3 = (uint8_t)((lba >> 24) & 0xff);
        cfis->lba4 = (uint8_t)((lba >> 32) & 0xff);
        cfis->lba5 = (uint8_t)((lba >> 40) & 0xff);

        cfis->count = count;

        if (size > 0 && buf) {
            // Scatter-gather the buffer into the PRDT.
            uintptr_t virt = (uintptr_t)buf;
            size_t remaining = size;
            size_t prdtidx = 0;

            while (remaining > 0 && prdtidx < PRDTMAX) {
                uintptr_t phys = NArch::VMM::virt2phys(&NArch::VMM::kspace, virt);
                size_t pageoff = virt & (NArch::PAGESIZE - 1);
                size_t chunk = NArch::PAGESIZE - pageoff;
                if (chunk > remaining) {
                    chunk = remaining;
                }

                cmdtable->prdt[prdtidx].dba = (uint32_t)(phys & 0xffffffff);
                cmdtable->prdt[prdtidx].dbau = (uint32_t)(phys >> 32);
                cmdtable->prdt[prdtidx].dbc = chunk - 1;
                cmdtable->prdt[prdtidx].i = 0;

                prdtidx++;
                virt += chunk;
                remaining -= chunk;
            }

            if (remaining > 0) {
                NUtil::printf("[dev/ata]: Buffer too fragmented for PRDT (need more than %lu entries).\n", (unsigned long)PRDTMAX);
                __atomic_store_n(&pending->inuse, false, memory_order_release);
                return -EINVAL;
            }

            // Set interrupt-on-completion on the last PRDT entry.
            cmdtable->prdt[prdtidx - 1].i = 1;
            hdr->prdtl = prdtidx;
        }

        (void)ctrl;
        (void)port;
        return 0;
    }

    // Issue command on the hardware and record the submission timestamp.
    void issuecommand(struct ahcictrl *ctrl, struct ahciport *port, int slot, struct ahcipending *pending) {
        __atomic_store_n(&pending->submittsc, NArch::TSC::query(), memory_order_release);
        port->portlock.acquire();
        __atomic_store_n(&pending->issued, true, memory_order_release);
        // Serialise this write so we aren't clobbering in-flight issues.
        write32(&ctrl->pcibar, PORTREG(port->num, PORTREGCI), read32(&ctrl->pcibar, PORTREG(port->num, PORTREGCI)) | (1 << slot));
        port->portlock.release();
    }

    // Synchronous ATA command: build, issue, and wait for completion.
    int AHCIDriver::atacommand(struct ahcictrl *ctrl, struct ahciport *port, uint8_t cmd, uint64_t lba, uint16_t count, void *buf, size_t size, bool iswrite) {
        int slot = -1;
        struct ahcipending *pending = NULL;

        int res = allocslot(ctrl, port, &slot, &pending);
        if (res < 0) {
            return res;
        }

        res = setupcommand(ctrl, port, slot, pending, cmd, lba, count, buf, size, iswrite);
        if (res < 0) {
            return res;
        }

        issuecommand(ctrl, port, slot, pending);

        res = waitio(pending);

// Seed entropy from timestamp.
#ifdef __x86_64__
        uint64_t tsc = NArch::TSC::query();
        NArch::CPU::get()->entropypool->addentropy((uint8_t *)&tsc, sizeof(tsc), 1);
#endif

        return res;
    }

    int AHCIDriver::atacommand_async(struct ahcictrl *ctrl, struct ahciport *port, uint8_t cmd, uint64_t lba, uint16_t count, void *buf, size_t size, bool iswrite, struct ahcipending **outpending, struct bioreq *bio) {
        int slot = -1;
        struct ahcipending *pending = NULL;

        int res = allocslot(ctrl, port, &slot, &pending);
        if (res < 0) {
            return res;
        }

        res = setupcommand(ctrl, port, slot, pending, cmd, lba, count, buf, size, iswrite);
        if (res < 0) {
            return res;
        }

        pending->bio = bio;

        issuecommand(ctrl, port, slot, pending);

        *outpending = pending;
        return 0;
    }

    int AHCIDriver::waitpending(struct ahcipending *pending) {
        return waitio(pending);
    }

    int AHCIDriver::waitmultiple(struct ahcipending **pendings, size_t count) {
        uint64_t hz = NArch::TSC::hz;
        uint64_t deadline = NArch::TSC::query() + (IOTIMEOUTUS * hz) / 1000000;

        size_t remaining = count;
        int firsterror = 0;

        // Simple bitmap via stack array (MAXSLOTS is 32, count is small).
        bool done[MAXSLOTS];
        for (size_t i = 0; i < count; i++) {
            done[i] = false;
        }

        while (remaining > 0) {
            uint64_t now = NArch::TSC::query();
            if (now > deadline) {
                for (size_t i = 0; i < count; i++) {
                    if (!done[i]) {
                        struct ahciport *port = pendings[i]->port;
                        port->portlock.acquire();
                        __atomic_store_n(&pendings[i]->issued, false, memory_order_release);
                        bool alreadydone = __atomic_load_n(&pendings[i]->done, memory_order_acquire);
                        port->portlock.release();

                        if (alreadydone) {
                            // ISR completed this slot concurrently.
                            done[i] = true;
                            remaining--;
                            int status = __atomic_load_n(&pendings[i]->status, memory_order_acquire);
                            if (status != 0 && firsterror == 0) {
                                firsterror = status;
                            }
                        } else {
                            if (firsterror == 0) {
                                firsterror = -ETIMEDOUT;
                            }
                        }

                        __atomic_store_n(&pendings[i]->inuse, false, memory_order_release);
                    }
                }
                return firsterror;
            }

            bool anycompleted = false;
            for (size_t i = 0; i < count; i++) {
                if (done[i]) {
                    continue;
                }
                if (__atomic_load_n(&pendings[i]->done, memory_order_acquire)) {
                    done[i] = true;
                    remaining--;
                    anycompleted = true;

                    int status = __atomic_load_n(&pendings[i]->status, memory_order_acquire);
                    __atomic_store_n(&pendings[i]->inuse, false, memory_order_release);
                    if (status != 0 && firsterror == 0) {
                        firsterror = status;
                    }
                }
            }

            if (!anycompleted && remaining > 0) {
                // Wait on the first incomplete request's wait queue.
                for (size_t i = 0; i < count; i++) {
                    if (!done[i]) {
                        struct ahcipending *p = pendings[i];
                        p->wq.waitinglock.acquire();
                        if (!__atomic_load_n(&p->done, memory_order_acquire)) {
                            p->wq.preparewait();
                            p->wq.waitinglock.release();
                            NSched::yield();
                            p->wq.waitinglock.acquire();
                            p->wq.finishwait(true);
                        }
                        p->wq.waitinglock.release();
                        break;
                    }
                }
            }
        }

        return firsterror;
    }

}