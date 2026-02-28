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

    int waitio(struct ahcipending *pending);
    int allocslot(struct ahcictrl *ctrl, struct ahciport *port, int *outslot, struct ahcipending **outpending, bool blocking);
    void issuecommand(struct ahcictrl *ctrl, struct ahciport *port, int slot, struct ahcipending *pending);

    static int setupatapicommand(struct ahcictrl *ctrl, struct ahciport *port, int slot, struct ahcipending *pending, const uint8_t *cdb, size_t cdblen, void *buf, size_t size, bool iswrite) {
        struct ahcicmdhdr *hdr = &port->cmdlist[slot];
        NLib::memset(hdr, 0, sizeof(struct ahcicmdhdr));

        uintptr_t ctphys = NArch::VMM::virt2phys(&NArch::VMM::kspace, (uintptr_t)&port->cmdtables[slot]);
        hdr->ctba = (uint32_t)(ctphys & 0xffffffff);
        hdr->ctbau = (uint32_t)(ctphys >> 32);

        hdr->cfl = sizeof(struct atah2d) / sizeof(uint32_t);
        hdr->a = 1; // ATAPI command.
        hdr->w = iswrite ? 1 : 0;
        hdr->c = 1; // Clear busy upon R_OK.
        hdr->prdtl = 0;

        struct ahcicmdtable *cmdtable = &port->cmdtables[slot];
        NLib::memset(cmdtable, 0, sizeof(struct ahcicmdtable));

        // Build H2D register FIS for the ATA PACKET command.
        struct atah2d *cfis = (struct atah2d *)cmdtable->cfis;
        cfis->type = FISTYPE_H2D;
        cfis->c = 1;
        cfis->cmd = ATACMD_PACKET;
        cfis->device = 0;

        // Feature register: bit 0 = DMA mode, bit 2 = host-to-device direction.
        cfis->featurel = 0x01; // DMA.
        if (iswrite) {
            cfis->featurel |= 0x04;
        }

        // Byte count limit in lba1:lba2 (used by PIO fallback; set for spec compliance).
        cfis->lba1 = (uint8_t)(size & 0xff);
        cfis->lba2 = (uint8_t)((size >> 8) & 0xff);

        // Copy the SCSI CDB into the ATAPI command area of the command table.
        if (cdblen > 16) {
            cdblen = 16; // Clamp to reasonable max for ATAPI.
        }
        NLib::memcpy(cmdtable->acmd, (void *)cdb, cdblen);

        // Same scatter-gather deal as in ATA.
        if (size > 0 && buf) {
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
                NUtil::printf("[dev/ata]: ATAPI buffer too fragmented for PRDT (need more than %lu entries).\n", (unsigned long)PRDTMAX);
                __atomic_store_n(&pending->inuse, false, memory_order_release);
                port->slotavailwq.wakeone();
                return -EINVAL;
            }

            cmdtable->prdt[prdtidx - 1].i = 1; // Interrupt on last entry.
            hdr->prdtl = prdtidx;
        }

        (void)ctrl;
        (void)port;
        return 0;
    }

    int AHCIDriver::atapicommand(struct ahcictrl *ctrl, struct ahciport *port, const uint8_t *cdb, size_t cdblen, void *buf, size_t size, bool iswrite) {
        int slot = -1;
        struct ahcipending *pending = NULL;

        int res = allocslot(ctrl, port, &slot, &pending, true); // Sync: block until a slot is available.
        if (res < 0) {
            return res;
        }

        res = setupatapicommand(ctrl, port, slot, pending, cdb, cdblen, buf, size, iswrite);
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

    int AHCIDriver::atapicommand_async(struct ahcictrl *ctrl, struct ahciport *port, const uint8_t *cdb, size_t cdblen, void *buf, size_t size, bool iswrite, struct ahcipending **outpending, struct bioreq *bio) {
        int slot = -1;
        struct ahcipending *pending = NULL;

        int res = allocslot(ctrl, port, &slot, &pending, false); // Async: never block; caller retries.
        if (res < 0) {
            return res;
        }

        res = setupatapicommand(ctrl, port, slot, pending, cdb, cdblen, buf, size, iswrite);
        if (res < 0) {
            return res;
        }

        pending->bio = bio;

        issuecommand(ctrl, port, slot, pending);

        *outpending = pending;
        return 0;
    }

}