#ifdef __x86_64__
#include <arch/x86_64/interrupts.hpp>
#include <arch/x86_64/cpu.hpp>
#include <arch/x86_64/smp.hpp>
#include <arch/x86_64/tsc.hpp>
#include <arch/x86_64/vmm.hpp>
#endif

#include <dev/block.hpp>
#include <dev/drivers/ata/defs.hpp>
#include <dev/drivers/ata/driver.hpp>
#include <dev/pci.hpp>

#include <lib/assert.hpp>

#include <fs/devfs.hpp>

namespace NDev {

    static AHCIDriver *instance = NULL;

    static NSched::WorkerPool *completionpool = NULL;
    static NSched::WorkQueue *workqueue = NULL;

    AHCIDriver::AHCIDriver(void) {
        __atomic_store_n(&instance, this, memory_order_release);

        size_t ncpus = NArch::SMP::awakecpus;
        completionpool = new NSched::WorkerPool(-1, NSched::WQ_UNBOUND | NSched::WQ_HIGHPRI, ncpus, ncpus * 2);
        for (size_t i = 0; i < ncpus; i++) {
            completionpool->spawnworker();
        }

        workqueue = new NSched::WorkQueue("ahci_iocomplete", NSched::WQ_UNBOUND | NSched::WQ_HIGHPRI, completionpool);
    }

    AHCIDriver::~AHCIDriver(void) {
        // Prevent ISR from entering driver code.
        __atomic_store_n(&instance, (AHCIDriver *)NULL, memory_order_seq_cst);

        for (size_t i = 0; i < this->ctrlcount; i++) {
            struct ahcictrl *ctrl = &this->controllers[i];

            if (!__atomic_load_n(&ctrl->initialised, memory_order_acquire)) {
                continue;
            }

            // Signal ISR to stop processing this controller.
            __atomic_store_n(&ctrl->dead, true, memory_order_release);
            __atomic_thread_fence(memory_order_seq_cst);

            // Disable interrupt vectors and unregister ISR handler.
            PCI::disablevectors(&ctrl->info, 1, &ctrl->vec);

            for (size_t j = 0; j < 32; j++) {
                if (!(ctrl->portimpl & (1 << j))) {
                    continue;
                }

                struct ahciport *port = &ctrl->ports[j];
                if (!port->initialised) {
                    continue;
                }

                // Stop command processing.
                uint32_t pcmd = read32(&ctrl->pcibar, PORTREG(j, PORTREGCMD));
                pcmd &= ~AHCIPCMD_ST;
                write32(&ctrl->pcibar, PORTREG(j, PORTREGCMD), pcmd);

                for (int w = 0; w < 500; w++) {
                    if (!(read32(&ctrl->pcibar, PORTREG(j, PORTREGCMD)) & AHCIPCMD_CR)) {
                        break;
                    }
                    for (int p = 0; p < 10000; p++) {
                        asm volatile("pause");
                    }
                }

                // Disable FIS receive.
                pcmd = read32(&ctrl->pcibar, PORTREG(j, PORTREGCMD));
                pcmd &= ~AHCIPCMD_FRE;
                write32(&ctrl->pcibar, PORTREG(j, PORTREGCMD), pcmd);

                for (int w = 0; w < 500; w++) {
                    if (!(read32(&ctrl->pcibar, PORTREG(j, PORTREGCMD)) & AHCIPCMD_FR)) {
                        break;
                    }
                    for (int p = 0; p < 10000; p++) {
                        asm volatile("pause");
                    }
                }

                // Disable port interrupts.
                write32(&ctrl->pcibar, PORTREG(j, PORTREGIE), 0);

                // Complete all pending I/Os with error.
                for (size_t k = 0; k <= ctrl->nslots; k++) {
                    struct ahcipending *pending = &port->pendings[k];
                    if (__atomic_load_n(&pending->inuse, memory_order_acquire)) {
                        __atomic_store_n(&pending->status, -EIO, memory_order_release);
                        __atomic_store_n(&pending->done, true, memory_order_release);
                        pending->wq.wakeone();
                    }
                }

                // Tear down partition devices.
                for (size_t k = 0; k < port->numparts; k++) {
                    if (port->partnames[k][0]) {
                        NFS::DEVFS::unregisterdevfile(port->partnames[k]);
                    }
                    if (port->partdevs[k]) {
                        registry->remove(port->partdevs[k]);
                        delete port->partdevs[k];
                        port->partdevs[k] = NULL;
                    }
                }

                // Tear down main block device.
                if (port->devname[0]) {
                    NFS::DEVFS::unregisterdevfile(port->devname);
                }
                if (port->blkdev) {
                    registry->remove(port->blkdev);
                    delete port->blkdev;
                    port->blkdev = NULL;
                }

                // Free DMA buffers.
                if (port->clphys) {
                    NArch::PMM::free((void *)port->clphys, 32 * sizeof(struct ahcicmdhdr));
                    port->clphys = 0;
                }
                if (port->fbphys) {
                    NArch::PMM::free((void *)port->fbphys, 256);
                    port->fbphys = 0;
                }
                if (port->ctphys) {
                    NArch::PMM::free((void *)port->ctphys, (ctrl->nslots + 1) * sizeof(struct ahcicmdtable));
                    port->ctphys = 0;
                }

                port->initialised = false;
            }

            // Disable AHCI.
            uint32_t ghcr = read32(&ctrl->pcibar, REGGHCR);
            ghcr &= ~AHCIGHC_IE;
            write32(&ctrl->pcibar, REGGHCR, ghcr);
            ghcr &= ~AHCIGHC_AE;
            write32(&ctrl->pcibar, REGGHCR, ghcr);

            PCI::unmapbar(ctrl->pcibar);

            __atomic_store_n(&ctrl->initialised, false, memory_order_release);
        }

        // Drain workqueue after all controllers are disabled.
        if (workqueue) {
            workqueue->drain();
        }
    }

    static void completionwork(struct NSched::work *work) {
        struct ahcipending *pending = (struct ahcipending *)work->udata;
        assert(pending != NULL, "No pending pointer in AHCI completion work item.");

        if (pending->bio) {
            pending->bio->status = __atomic_load_n(&pending->status, memory_order_acquire);
            __atomic_store_n(&pending->bio->completed, true, memory_order_release);

            if (pending->bio->callback) {
                pending->bio->callback(pending->bio);
            }
        }

        if (pending->callback) {
            pending->callback(pending);
        }

        pending->wq.wakeone();

        // Release this slot.
        __atomic_store_n(&pending->inuse, false, memory_order_release);
    }

    static void queuecompletion(struct ahcipending *pending) {
        NSched::initwork(&pending->work, completionwork, pending);
        workqueue->queue(&pending->work);
    }

    static void iohandler(struct NArch::Interrupts::isr *isr, struct NArch::CPU::context *ctx) {
        (void)isr;
        (void)ctx;

        AHCIDriver *drv = __atomic_load_n(&instance, memory_order_acquire);
        if (!drv) {
            return;
        }

        for (size_t i = 0; i < drv->ctrlcount; i++) {
            struct ahcictrl *ctrl = &drv->controllers[i];
            if (!__atomic_load_n(&ctrl->initialised, memory_order_acquire)) {
                continue;
            }

            if (__atomic_load_n(&ctrl->dead, memory_order_acquire)) {
                continue;
            }

            uint32_t gis = read32(&ctrl->pcibar, REGIS);
            if (!gis) {
                continue; // Not our interrupt.
            }


            for (size_t j = 0; j < 32; j++) {
                if (!(gis & (1 << j))) {
                    continue;
                }

                struct ahciport *port = &ctrl->ports[j];
                if (!port->initialised) {
                    write32(&ctrl->pcibar, PORTREG(j, PORTREGIS),
                            read32(&ctrl->pcibar, PORTREG(j, PORTREGIS))); // Acknowledge port interrupt to clear it, even if we don't know what it is.
                    continue;
                }

                port->portlock.acquire();

                uint32_t pis = read32(&ctrl->pcibar, PORTREG(j, PORTREGIS));
                write32(&ctrl->pcibar, PORTREG(j, PORTREGIS), pis); // Acknowledge port interrupt.

                bool iserror = (pis & AHCIPIS_TFES) != 0;

                uint32_t ci = read32(&ctrl->pcibar, PORTREG(j, PORTREGCI));

                for (size_t k = 0; k < ctrl->nslots + 1; k++) {
                    struct ahcipending *pending = &port->pendings[k];

                    if (!__atomic_load_n(&pending->inuse, memory_order_acquire)) {
                        continue;
                    }

                    // Skip slots that haven't been issued.
                    if (!__atomic_load_n(&pending->issued, memory_order_acquire)) {
                        continue;
                    }

                    if (ci & (1 << k)) {
                        if (!iserror) {
                            continue; // Command still in progress.
                        }
                        // Error occurred while in progress.
                    }

                    // Mark as processed, so subsequent ISRs skip.
                    __atomic_store_n(&pending->issued, false, memory_order_release);

                    int status = 0;
                    if (iserror) { // Handle errors.
                        if (ci & (1 << k)) {
                            status = -EIO;
                        } else {
                            uint32_t tfd = read32(&ctrl->pcibar, PORTREG(j, PORTREGTFD));
                            if (tfd & (AHCITFD_SERR | AHCITFD_SRBSY)) {
                                status = -EIO;
                            }
                        }
                    }

                    __atomic_store_n(&pending->status, status, memory_order_release);
                    __atomic_store_n(&pending->done, true, memory_order_release);

                    if (pending->callback || (pending->bio && pending->bio->callback)) {
                        queuecompletion(pending);
                    } else {
                        pending->wq.wakeone();
                    }
                }

                if (iserror) { // Recover from error.
                    uint32_t pcmd = read32(&ctrl->pcibar, PORTREG(j, PORTREGCMD));
                    pcmd &= ~AHCIPCMD_ST; // Stop the port.
                    write32(&ctrl->pcibar, PORTREG(j, PORTREGCMD), pcmd);

                    for (int w = 0; w < 1000; w++) {
                        if (!(read32(&ctrl->pcibar, PORTREG(j, PORTREGCMD)) & AHCIPCMD_CR)) {
                            break;
                        }
                        asm volatile("pause");
                    }

                    // Clear errors.
                    write32(&ctrl->pcibar, PORTREG(j, PORTREGSERR), 0xffffffff);
                    write32(&ctrl->pcibar, PORTREG(j, PORTREGIS), 0xffffffff);

                    pcmd = read32(&ctrl->pcibar, PORTREG(j, PORTREGCMD));
                    pcmd |= AHCIPCMD_ST; // Start.
                    write32(&ctrl->pcibar, PORTREG(j, PORTREGCMD), pcmd);

                    // We should be good now, I reckon.
                }

                port->portlock.release();
            }

            write32(&ctrl->pcibar, REGIS, gis); // Acknowledge any remaining controller-level interrupt.
        }
    }



    void AHCIDriver::probe(struct devinfo info) {
        NUtil::printf("[dev/ata]: Discovered AHCI controller: %04x:%04x.\n", info.info.pci.vendor, info.info.pci.device);

        struct PCI::bar bar = PCI::getbar(&info, 5);

        if (!bar.mmio) {
            NUtil::printf("[dev/ata]: Controller does not support MMIO.\n");
            PCI::unmapbar(bar);
            return;
        }

        // Enable bus mastering and MMIO.
        uint16_t cmd = PCI::read(&info, 0x4, 2);
        cmd |= (1 << 2) | (1 << 1);
        PCI::write(&info, 0x4, cmd, 2);

        struct ahcictrl *ctrl = &this->controllers[this->ctrlcount];
        NLib::memset(ctrl, 0, sizeof(struct ahcictrl));
        ctrl->num = this->ctrlcount;
        ctrl->info = info;
        ctrl->pcibar = bar;

        uint32_t cap = read32(&bar, REGCAP);

        ctrl->nslots = (cap & AHCICAP_NCS) >> AHCICAP_NCSS; // Number of slots is in 12:08 according to AHCI spec.
        ctrl->supports64bit = cap & AHCICAP_S64; // Supports 64-bit addressing if bit 31 is set.

        uint32_t ghcr = read32(&bar, REGGHCR);
        ghcr |= AHCIGHC_AE; // AHCI Enable.
        ghcr |= AHCIGHC_IE; // AHCI Interrupt Enable.
        write32(&bar, REGGHCR, ghcr);

        uint32_t portimpl = read32(&bar, REGPI);
        ctrl->portimpl = portimpl;

        int vecres = PCI::enablevectors(&ctrl->info, 1, &ctrl->vec, iohandler);
        if (vecres < 0) {
            NUtil::printf("[dev/ata]: Failed to enable interrupt vector for controller: error %d.\n", vecres);
            // We could still operate without interrupts, but performance would be terrible, so we just disable the controller instead.
            write32(&bar, REGGHCR, ghcr & ~AHCIGHC_IE); // Disable AHCI interrupts.
            write32(&bar, REGGHCR, ghcr & ~AHCIGHC_AE); // Disable AHCI.
            PCI::unmapbar(bar);
            return;
        }

        // Controller is done. It's just the ports now.
        __atomic_store_n(&ctrl->initialised, true, memory_order_release);
        this->ctrlcount++;

        // Count set bits in portimpl to determine number of ports.
        for (size_t i = 0; i < 32; i++) {
            if (!(portimpl & (1 << i))) {
                continue;
            }

            struct ahciport *port = &ctrl->ports[i];
            port->num = i;
            port->type = ahciport::NONE;

            // Spec seems to suggest that the port should be idle before anything is done. That makes sense to me.

            uint32_t pcmd = read32(&bar, PORTREG(i, PORTREGCMD));
            pcmd &= ~AHCIPCMD_ST; // Clear start bit to stop port.
            write32(&bar, PORTREG(i, PORTREGCMD), pcmd);

            for (size_t j = 0; j < 500; j++) {
                if (!(read32(&bar, PORTREG(i, PORTREGCMD)) & AHCIPCMD_CR)) { // Wait for port to report not busy (CR).
                    break;
                }

                for (size_t p = 0; p < 10000; p++) { // Wait a bit before checking again.
                    asm volatile("pause");
                }
            }

            pcmd = read32(&bar, PORTREG(i, PORTREGCMD));
            pcmd &= ~AHCIPCMD_FRE; // Clear FRE bit to disable FIS receive.
            write32(&bar, PORTREG(i, PORTREGCMD), pcmd);

            for (size_t j = 0; j < 500; j++) {
                if (!(read32(&bar, PORTREG(i, PORTREGCMD)) & AHCIPCMD_FR)) { // Wait for port to report not busy (FR).
                    break;
                }

                for (size_t p = 0; p < 10000; p++) { // Wait a bit before checking again.
                    asm volatile("pause");
                }
            }

            // Check status and signature to allow us to bail out early, so we don't waste our time (and memory) on a useless port.

            uint32_t ssts = read32(&bar, PORTREG(i, PORTREGSSTS));
            if ((ssts & 0xf) != 0x3) { // Check that the device actually exists at all.
                continue;
            }

            uint32_t sig = read32(&bar, PORTREG(i, PORTREGSIG));
            if (sig != 0x00000101 && sig != 0xeb140101) { // Check for ATA or ATAPI signature.
                continue; // We don't support this.
            }

            // Initialise command list.
            size_t clsize = 32 * sizeof(struct ahcicmdhdr);
            port->clphys = (uintptr_t)NArch::PMM::alloc(clsize, NArch::PMM::FLAGS_DEVICE);
            if (!port->clphys) {
                NUtil::printf("[dev/ata]: Failed to allocate command list for port %lu.\n", i);
                continue;
            }
            void *clvirt = NArch::hhdmoff((void *)port->clphys);
            NLib::memset(clvirt, 0, clsize);

            // Initialise FIS receive area.
            size_t fbsize = 256; // FIS receive area is 256 bytes as per AHCI spec.
            port->fbphys = (uintptr_t)NArch::PMM::alloc(fbsize, NArch::PMM::FLAGS_DEVICE);
            if (!port->fbphys) {
                NUtil::printf("[dev/ata]: Failed to allocate FIS receive buffer for port %lu.\n", i);
                NArch::PMM::free((void *)port->clphys, clsize);
                continue;
            }

            void *fbvirt = NArch::hhdmoff((void *)port->fbphys);
            NLib::memset(fbvirt, 0, fbsize);

            // Command tables: one per slot.
            size_t ctsize = (ctrl->nslots + 1) * sizeof(struct ahcicmdtable);
            port->ctphys = (uintptr_t)NArch::PMM::alloc(ctsize, NArch::PMM::FLAGS_DEVICE);
            if (!port->ctphys) {
                NUtil::printf("[dev/ata]: Failed to allocate command tables for port %lu.\n", i);
                NArch::PMM::free((void *)port->clphys, clsize);
                NArch::PMM::free((void *)port->fbphys, fbsize);
                continue;
            }

            void *ctvirt = NArch::hhdmoff((void *)port->ctphys);
            NLib::memset(ctvirt, 0, ctsize);


            port->cmdlist = (struct ahcicmdhdr *)clvirt;
            port->cmdtables = (struct ahcicmdtable *)ctvirt;

            // Point command list entry to command table for each slot.
            for (size_t j = 0; j <= ctrl->nslots; j++) {
                uintptr_t phys = NArch::VMM::virt2phys(&NArch::VMM::kspace, (uintptr_t)&port->cmdtables[j]);
                port->cmdlist[j].ctba = (uint32_t)(phys & 0xffffffff);
                port->cmdlist[j].ctbau = (uint32_t)(phys >> 32); // Upper 32 bits of command table address, if supported.
            }

            // Inform controller of our buffers.
            write32(&bar, PORTREG(i, PORTREGCLB), (uint32_t)(port->clphys & 0xffffffff));
            write32(&bar, PORTREG(i, PORTREGCLBU), (uint32_t)(port->clphys >> 32)); // Upper 32 bits of command list address, if supported.
            write32(&bar, PORTREG(i, PORTREGBFB), (uint32_t)(port->fbphys & 0xffffffff));
            write32(&bar, PORTREG(i, PORTREGBFBU), (uint32_t)(port->fbphys >> 32)); // Upper 32 bits of FIS receive buffer address, if supported.

            // Clear stales.
            write32(&bar, PORTREG(i, PORTREGSERR), 0xffffffff);
            write32(&bar, PORTREG(i, PORTREGIS), 0xffffffff);

            pcmd = read32(&bar, PORTREG(i, PORTREGCMD));
            pcmd |= AHCIPCMD_FRE; // Set FRE bit to enable FIS receive.
            write32(&bar, PORTREG(i, PORTREGCMD), pcmd);
            pcmd |= AHCIPCMD_ST; // Set start bit to start port.
            write32(&bar, PORTREG(i, PORTREGCMD), pcmd);

            write32(&bar, PORTREG(i, PORTREGIE), AHCIPIS_DHRS | AHCIPIS_PSS | AHCIPIS_DSS | AHCIPIS_TFES); // Enable interrupts for this port.

            ssts = read32(&bar, PORTREG(i, PORTREGSSTS));
            if ((ssts & 0xf) != 0x3) { // Check that the device is still present after starting the port.
                NUtil::printf("[dev/ata]: Device disappeared from port %lu after starting port.\n", i);
                continue;
            }

            if (sig == 0x00000101) {
                port->type = ahciport::ATA;
                NUtil::printf("[dev/ata]: Detected ATA drive at port %lu.\n", i);
            } else if (sig == 0xeb140101) {
                port->type = ahciport::ATAPI;
                NUtil::printf("[dev/ata]: Detected ATAPI drive at port %lu.\n", i);
            }

            port->initialised = true;
            NUtil::printf("[dev/ata]: Port %lu initialised successfully.\n", i);

            this->initport(ctrl, port);

            ctrl->portcount++;
        }

        if (ctrl->portcount == 0) {
            NUtil::printf("[dev/ata]: No usable ports found on controller.\n");
            write32(&bar, REGGHCR, ghcr & ~AHCIGHC_IE); // Disable AHCI interrupts.
            write32(&bar, REGGHCR, ghcr & ~AHCIGHC_AE); // Disable AHCI.
            PCI::unmapbar(bar);
            PCI::disablevectors(&ctrl->info, 1, &ctrl->vec);
            return;
        }
    }

    void AHCIDriver::initport(struct ahcictrl *ctrl, struct ahciport *port) {

        void *idbufphys = NArch::PMM::alloc(512, NArch::PMM::FLAGS_DEVICE);
        if (!idbufphys) {
            NUtil::printf("[dev/ata]: Failed to allocate buffer for IDENTIFY data for port %lu.\n", port->num);
            return;
        }
        void *idbuf = NArch::hhdmoff(idbufphys);
        NLib::memset(idbuf, 0, 512);

        uint8_t idcmd = (port->type == ahciport::ATA) ? ATACMD_IDENTIFY : ATACMD_IDENTIFYPACKET;
        int res = this->atacommand(ctrl, port, idcmd, 0, 0, idbuf, 512, false);
        if (res < 0) {
            NUtil::printf("[dev/ata]: IDENTIFY command failed for port %lu with error %d.\n", port->num, res);
            NArch::PMM::free(idbufphys, 512);
            return;
        }

        struct ataid *id = (struct ataid *)idbuf;

        // Copy out model string, trimming whitespace.
        for (size_t i = 0; i < 40; i += 2) {
            char tmp = id->model[i];
            id->model[i] = id->model[i + 1];
            id->model[i + 1] = tmp;
        }

        NLib::memcpy(port->model, id->model, 40);
        port->model[40] = '\0'; // Ensure null termination.
        for (int i = 39; i >= 0 && port->model[i] == ' '; i--) {
            port->model[i] = '\0';
        }

        if (id->cmdset2 & ATAID_LBA48) {
            port->numsectors = id->lba48sectors;
        } else {
            port->numsectors = id->lba28sectors;
        }

        if ((id->secsize & (1 << 12)) && !(id->secsize & (1 << 15))) {
            port->sectorsize = id->logsecsize * 2;
        } else {
            port->sectorsize = 512; // Default sector size.
        }

        NArch::PMM::free(idbufphys, 512);

        if (port->type == ahciport::ATAPI) {
            // Use SCSI READ CAPACITY(10) to determine the real device geometry. This will obviously fail if there is no optical media to give us capacity info.

            // XXX: We're technically allocating an ENTIRE page just to use 8 bytes (PMM is page-wise). Not amazing.
            void *capbufphys = NArch::PMM::alloc(8, NArch::PMM::FLAGS_DEVICE); // We'll need a buffer to dump our response in, so we'll get that now.
            if (!capbufphys) {
                NUtil::printf("[dev/ata]: Port %lu: Failed to allocate READ CAPACITY buffer.\n", port->num);
                return;
            }
            void *capbuf = NArch::hhdmoff(capbufphys);
            NLib::memset(capbuf, 0, 8);

            uint8_t cdb[12] = {};
            cdb[0] = SCSICMD_READCAPACITY;

            int capres = this->atapicommand(ctrl, port, cdb, 12, capbuf, 8, false);
            if (capres < 0) { // If the drive exists but we have nothing in it.
                NUtil::printf("[dev/ata]: Port %lu: ATAPI model: %s. READ CAPACITY failed (%d). Likely no media.\n", port->num, port->model, capres);
                NArch::PMM::free(capbufphys, 8);
                return;
            }

            uint8_t *cap = (uint8_t *)capbuf;
            // Convert from big-endian to little-endian, as per SCSI spec.
            uint32_t lastlba = ((uint32_t)cap[0] << 24) | ((uint32_t)cap[1] << 16) | ((uint32_t)cap[2] << 8) | (uint32_t)cap[3];
            uint32_t blklen = ((uint32_t)cap[4] << 24) | ((uint32_t)cap[5] << 16) | ((uint32_t)cap[6] << 8) | (uint32_t)cap[7];

            NArch::PMM::free(capbufphys, 8);

            if (blklen == 0) {
                blklen = 2048; // Default CD-ROM sector size.
            }

            port->numsectors = (uint64_t)lastlba + 1;
            port->sectorsize = blklen;

            NUtil::printf("[dev/ata]: Port %lu: ATAPI model: %s, Sectors: %lu, Sector size: %u.\n", port->num, port->model, port->numsectors, port->sectorsize);

            static size_t sridx = 0;
            uint32_t minor = ataminor(ctrl->num, port->num, 0);
            uint64_t devid = NFS::DEVFS::makedev(ATAPIBLKMAJOR, minor);

            ATAPIBlockDevice *blkdev = new ATAPIBlockDevice(devid, this, ctrl, port);
            registry->add(blkdev);

            struct NFS::VFS::stat st = { };
            st.st_mode = 0644 | NFS::VFS::S_IFBLK;
            st.st_uid = 0;
            st.st_gid = 0;
            st.st_rdev = devid;
            st.st_size = port->numsectors * port->sectorsize;
            st.st_blksize = port->sectorsize;
            st.st_blocks = (st.st_size + 511) / 512;

            char devname[32];
            NUtil::snprintf(devname, sizeof(devname), "sr%lu", sridx++);
            NFS::DEVFS::registerdevfile(devname, st);

            port->blkdev = blkdev;
            NLib::memcpy(port->devname, devname, sizeof(port->devname));
            return;
        }

        NUtil::printf("[dev/ata]: Port %lu: Model: %s, Sectors: %lu, Sector size: %u.\n", port->num, port->model, port->numsectors, port->sectorsize);

        uint32_t minor = ataminor(ctrl->num, port->num, 0);
        uint64_t devid = NFS::DEVFS::makedev(ATABLKMAJOR, minor);

        ATABlockDevice *blkdev = new ATABlockDevice(devid, this, ctrl, port);
        registry->add(blkdev);

        struct NFS::VFS::stat st = { };
        st.st_mode = 0644 | NFS::VFS::S_IFBLK;
        st.st_uid = 0;
        st.st_gid = 0;
        st.st_rdev = devid;
        st.st_size = port->numsectors * port->sectorsize;
        st.st_blksize = port->sectorsize;
        st.st_blocks = (st.st_size + 511) / 512;

        size_t diskidx = ctrl->num * MAXPORTS + port->num;
        char devname[32];
        NUtil::snprintf(devname, sizeof(devname), "sd%c", 'a' + diskidx);
        NFS::DEVFS::registerdevfile(devname, st);

        port->blkdev = blkdev;
        NLib::memcpy(port->devname, devname, sizeof(port->devname));

        struct parttableinfo *ptinfo = getpartinfo(blkdev);
        if (ptinfo) {
            for (size_t i = 0; i < ptinfo->numparts; i++) {
                struct partinfo *part = &ptinfo->partitions[i];

                uint32_t partminor = ataminor(ctrl->num, port->num, i + 1);
                uint64_t partdevid = NFS::DEVFS::makedev(ATABLKMAJOR, partminor);

                PartitionBlockDevice *partdev = new PartitionBlockDevice(partdevid, this, blkdev, part->firstlba, part->lastlba);
                registry->add(partdev);

                NUtil::snprintf(devname, sizeof(devname), "sd%c%u", 'a' + diskidx, (unsigned)(i + 1));
                st.st_rdev = partdevid;
                st.st_size = (part->lastlba - part->firstlba + 1) * port->sectorsize;
                st.st_blocks = (st.st_size + 511) / 512;
                NFS::DEVFS::registerdevfile(devname, st);

                if (port->numparts < ahciport::MAXPARTS) {
                    port->partdevs[port->numparts] = partdev;
                    NLib::memcpy(port->partnames[port->numparts], devname, sizeof(port->partnames[0]));
                    port->numparts++;
                }
            }
        }
    }

    static struct reginfo info = {
        .name = "ahci",
        .type = reginfo::PCI,
        .match = {
            .pci = {
                .pciclass       = 0x01, // Mass storage controller.
                .pcisubclass    = 0x06, // SATA controller.
                .pciprogif      = 0x01, // AHCI 1.0.
                .flags          = PCI_MATCHCLASS | PCI_MATCHSUBCLASS | PCI_MATCHPROGIF,
                .vendor         = 0,
                .devcount       = 0,
                .devices        = { }
            }
        }
    };

    REGDRIVER(AHCIDriver, &info);
}