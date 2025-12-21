#ifdef __x86_64__
#include <arch/x86_64/apic.hpp>
#include <arch/x86_64/cpu.hpp>
#include <arch/x86_64/e9.hpp>
#include <arch/x86_64/vmm.hpp>
#endif

#include <dev/dev.hpp>
#include <dev/drivers/nvme/defs.hpp>
#include <dev/drivers/nvme/driver.hpp>
#include <dev/pci.hpp>

#include <fs/devfs.hpp>

#include <lib/align.hpp>
#include <sched/event.hpp>
#include <stddef.h>
#include <dev/block.hpp>

namespace NDev {
    using namespace NFS;

    // Allocate DMA-capable memory.
    static void *dmaalloc(size_t size) {
        return NArch::hhdmoff(NArch::PMM::alloc(size, NArch::PMM::FLAGS_DEVICE));
    }

    // Free DMA-capable memory.
    static void dmafree(void *ptr, size_t size) {
        NArch::PMM::free(NArch::hhdmsub(ptr), size);
    }

    static NVMEDriver *instance = NULL;

    // Convert a controller ID, namespace ID and partition ID into a block device minor number.
    static inline uint32_t nsblktominor(uint32_t cid, uint32_t nsid, uint32_t pid) {
        const uint32_t CTRLBITS = 12;
        const uint32_t NSBITS = 12;
        const uint32_t PIDBITS = 8;

        const uint32_t CTRLMAX = (1 << CTRLBITS) - 1;
        const uint32_t NSMAX = (1 << NSBITS) - 1;
        const uint32_t PIDMAX = (1 << PIDBITS) - 1;
        if (cid > CTRLMAX || nsid > NSMAX || pid > PIDMAX) {
            return 0xffffffff;
        }
        uint32_t base = ((cid & CTRLMAX) << (NSBITS + PIDBITS));
        base |= ((nsid & NSMAX) << PIDBITS);
        base |= (pid & PIDMAX);
        return base;
    }

    // Extract controller ID from block device minor number.
    static inline uint32_t minortocid(uint32_t minor) {
        return (minor >> 20) & 0xfff;
    }

    // Extract namespace ID from block device minor number.
    static inline uint32_t minortonsid(uint32_t minor) {
        return (minor >> 8) & 0xfff;
    }

    // Extract partition ID from block device minor number.
    static inline uint32_t minortopid(uint32_t minor) {
        return minor & 0xff;
    }

    NVMEDriver::NVMEDriver(void) {
        instance = this;
    }

    NVMEDriver::~NVMEDriver(void) {
        for (size_t i = 0; i < this->ctrlcount; i++) {
            struct nvmectrl *ctrl = &this->controllers[i];

            if (ctrl->initialised) {
                // Disable controller.
                ctrl->cc.en = 0;
                write32(&ctrl->pcibar, REGCC, *((uint32_t *)&ctrl->cc));

                // Free admin queues.
                dmafree(ctrl->asq.entries, QUEUESIZE * sizeof(struct nvmesqe));
                dmafree(ctrl->acq.entries, QUEUESIZE * sizeof(struct nvmecqe));

                // Free I/O queues.
                for (size_t q = 0; q < MAXQUEUES; q++) {
                    if (ctrl->iosq[q].entries) {
                        dmafree(ctrl->iosq[q].entries, ctrl->iosq[q].size * sizeof(struct nvmesqe));
                    }
                    if (ctrl->iocq[q].entries) {
                        dmafree(ctrl->iocq[q].entries, ctrl->iocq[q].size * sizeof(struct nvmecqe));
                    }
                }

                // Free identification structure.
                dmafree(ctrl->id, PAGESIZE);
            }
            PCI::unmapbar(ctrl->pcibar);
        }
    }

    // Create a queue (submission or completion).
    int createqueue(struct nvmequeue *queue, uint32_t size, uint32_t id, uint16_t cqvec, bool iscq) {
        queue->size = size;
        queue->id = id;
        queue->cqvec = cqvec;
        queue->head = 0;
        queue->tail = 0;
        queue->phase = 1;
        queue->nextcid = 0;

        size_t entsize = size * (iscq ? sizeof(struct nvmecqe) : sizeof(struct nvmesqe));
        queue->entries = dmaalloc(entsize);
        if (!queue->entries) {
            return -1;
        }

        NLib::memset(queue->entries, 0, entsize);

        queue->dmaaddr = NArch::VMM::virt2phys(&NArch::VMM::kspace, (uintptr_t)queue->entries); // Reveal the physical address of our DMA.
        return 0;
    }

    // Waits for completion of an admin command.
    int waitadmin(struct nvmectrl *ctrl) {
        for (;;) {
            volatile struct nvmecqe *cqe = &((struct nvmecqe *)ctrl->acq.entries)[ctrl->acq.head];

            uint16_t phase = cqe->p;

            if (phase != ctrl->acq.phase) {
                asm volatile ("pause");
                continue;
            }

            struct nvmecqe *res = (struct nvmecqe *)cqe;

            uint16_t status = res->sc;
            if (status != 0) {
                // Consume CQE
                ctrl->acq.head++;
                if (ctrl->acq.head >= ctrl->acq.size) {
                    ctrl->acq.head = 0;
                    ctrl->acq.phase = !ctrl->acq.phase; // Flip phase whenever we wrap around.
                }

                write32(&ctrl->pcibar, COMPQUEUEDB(0, ctrl->caps.stride), ctrl->acq.head); // Write to doorbell.
                return -1;
            }

            // Consume successful CQE
            ctrl->acq.head++;
            if (ctrl->acq.head >= ctrl->acq.size) {
                ctrl->acq.head = 0;
                ctrl->acq.phase = !ctrl->acq.phase;
            }

            write32(&ctrl->pcibar, COMPQUEUEDB(0, ctrl->caps.stride), ctrl->acq.head); // Write to doorbell.

            return 0;
        }
    }

    // Submit commands to the admin queue (in the form of submission queue entries).
    int submitadmin(struct nvmectrl *ctrl, struct nvmesqe *cmd) {
        uint16_t tail = ctrl->asq.tail;
        struct nvmesqe *next = &((struct nvmesqe *)ctrl->asq.entries)[tail];

        NLib::memcpy(next, cmd, sizeof(struct nvmesqe)); // Copy our command into this queue entry.

#ifdef __x86_64__
        asm volatile ("sfence" : : : "memory"); // Ensure we've written the command to the queue.
#endif

        tail = (tail + 1) % QUEUESIZE;
        ctrl->asq.tail = tail;

        write32(&ctrl->pcibar, SUBQUEUEDB(0, ctrl->caps.stride), tail); // Write to doorbell.

        return 0;
    }

    // Create an I/O submission queue.
    int createiosqueue(struct nvmectrl *ctrl, uint16_t id, uint32_t size, uint8_t prio) {
        struct nvmesqe ciocmd = { };
        NLib::memset(&ciocmd, 0, sizeof(struct nvmesqe));

        if (createqueue(&ctrl->iosq[id], size, id, 0, false) != 0) {
            return -1;
        }

        ciocmd.op = ADMINCREATESQ; // Create I/O command queue.
        ciocmd.prp1 = ctrl->iosq[id].dmaaddr; // Pass the DMA to the command.

        ciocmd.cdw10 = (size - 1) << 16 | id;
        ciocmd.cdw11 = (id << 16) | (prio << 1) | (1 << 1) | (1 << 0); // Use priority and include CQID.
        submitadmin(ctrl, &ciocmd);

        if (waitadmin(ctrl) != 0) {
            dmafree(ctrl->iosq[id].entries, size * sizeof(struct nvmesqe));
            return -1;
        }
        return 0;
    }

    // Create an I/O completion queue.
    int createiocqueue(struct nvmectrl *ctrl, uint16_t id, uint32_t size, uint16_t vec) {
        struct nvmesqe ciocmd = { };
        NLib::memset(&ciocmd, 0, sizeof(struct nvmesqe));

        if (createqueue(&ctrl->iocq[id], size, id, vec, true) != 0) {
            return -1;
        }

        ciocmd.op = ADMINCREATECQ; // Create I/O command queue.
        ciocmd.prp1 = ctrl->iocq[id].dmaaddr; // Pass the DMA to the command.

        ciocmd.cdw10 = (id & 0xffff) | (size - 1) << 16;
        ciocmd.cdw11 = (vec << 16) | (1 << 1) | (1 << 0); // Bit 0 (use interrupts), Bit 1 (DMA is contiguous).

        submitadmin(ctrl, &ciocmd);

        if (waitadmin(ctrl) != 0) {
            dmafree(ctrl->iocq[id].entries, size * sizeof(struct nvmecqe));
            return -1;
        }
        return 0;
    }

    // Create a PRP list for a buffer larger than two pages.
    uintptr_t createprplist(void *buffer, size_t size) {
        uintptr_t start = (uintptr_t)buffer;
        uintptr_t end = start + size;
        uintptr_t firstpage = NLib::aligndown(start, PAGESIZE);
        uintptr_t lastpage = NLib::alignup(end, PAGESIZE);

        size_t numpages = (lastpage - firstpage) / PAGESIZE;

        if (numpages <= 2) { // Already can fit within the two PRP qwords.
            return 0;
        }

        const size_t entries_per_page = PAGESIZE / sizeof(uint64_t);
        size_t numlistpages = (numpages - 2 + entries_per_page - 1) / entries_per_page;

        uintptr_t listsphys = (uintptr_t)NArch::PMM::alloc(numlistpages * PAGESIZE);
        if (!listsphys) {
            return 0;
        }

        // Zero the list pages in the kernel virtual map before filling.
        struct nvmeprplist *base = (struct nvmeprplist *)NArch::hhdmoff((void *)listsphys);
        NLib::memset(base, 0, numlistpages * PAGESIZE);

        size_t currentidx = 0;
        struct nvmeprplist *curr = base; // Virtual pointer to current list page.

        for (size_t i = 2; i < numpages; i++) {
            uintptr_t virt = firstpage + (i * PAGESIZE);
            uintptr_t phys = NArch::VMM::virt2phys(&NArch::VMM::kspace, virt);

            curr->entries[currentidx++] = phys;

            if (currentidx >= entries_per_page) {
                currentidx = 0;
                // Advance to next list page (virtual address space).
                curr = (struct nvmeprplist *)((uintptr_t)curr + PAGESIZE);
            }
        }

        return listsphys;
    }

    // Prepare PRPs for a command.
    int setupprps(struct nvmesqe *cmd, void *buffer, size_t size) {
        if (size == 0) { // My bad king, I had no idea it was like that.
            cmd->prp1 = 0;
            cmd->prp2 = 0;
            return -1;
        }

        uint64_t bufferphys = NArch::VMM::virt2phys(&NArch::VMM::kspace, (uintptr_t)buffer);

        if (size <= PAGESIZE) { // Fits within first PRP.
            cmd->prp1 = bufferphys;
            cmd->prp2 = 0;
        } else if (size <= (2 * PAGESIZE)) { // Fits within two PRPs.
            cmd->prp1 = bufferphys;
            cmd->prp2 = bufferphys + PAGESIZE;
        } else { // Needs a PRP list.
            cmd->prp1 = bufferphys; // First PRP is direct.

            uintptr_t listphys = createprplist(buffer, size);
            if (!listphys) {
                return -1;
            }

            cmd->prp2 = listphys; // Subsequent PRPs are in the list.
        }

        return 0;
    }

    // Prepare a pending operation slot.
    static int preparewait(struct nvmectrl *ctrl, uint16_t qid, uint16_t cid, struct nvmepending **outpending) {
        size_t idx = qid * QUEUESIZE + (cid % QUEUESIZE);
        struct nvmepending *pending = &ctrl->pending[idx];

        bool expected = false;
        bool desired = true;
        if (!__atomic_compare_exchange_n(&pending->inuse, &expected, desired, false, memory_order_acq_rel, memory_order_acquire)) {
            return -1; // Slot is already in use.
        }

        __atomic_store_n(&pending->done, false, memory_order_relaxed);
        __atomic_thread_fence(memory_order_release);
        pending->status = 0;

        *outpending = pending;
        return 0;
    }

    // Sleep calling thread until command is complete (used for I/O commands).
    static int waitio(struct nvmepending *pending) {
        waitevent(&pending->wq, __atomic_load_n(&pending->done, memory_order_acquire) == true);
        int status = pending->status;
        __atomic_store_n(&pending->inuse, false, memory_order_release); // After this, we can no longer guarantee the pending struct is valid.
        return status ? -1 : 0; // Non-zero status indicates error.
    }

    int NVMEDriver::iorequest(struct nvmectrl *ctrl, uint16_t id, uint8_t opcode, uint32_t nsid, uint64_t lba, uint16_t sectors, void *buffer, size_t size) {
        struct nvmequeue *sq = &ctrl->iosq[id];

        sq->qlock.acquire(); // Lock the submission queue. This only needs to be done for the scope of submission queue manipulation.

        uint16_t cid = sq->nextcid++;

        struct nvmepending *pending;
        if (preparewait(ctrl, id, cid, &pending) != 0) {
            sq->qlock.release();
            return -1;
        }

        uint32_t tail = sq->tail;
        uint32_t nexttail = (tail + 1) % sq->size;

        // Simple full-queue check
        if (nexttail == sq->head) {
            sq->qlock.release();
            return -1; // queue full
        }

        struct nvmesqe *next = &((struct nvmesqe *)sq->entries)[tail];
        NLib::memset(next, 0, sizeof(struct nvmesqe));

        next->op = opcode;
        next->nsid = nsid;
        next->cid = cid;
        next->psdt = 0;
        next->fuse = 0;

        next->cdw10 = (uint32_t)(lba & 0xffffffff);
        next->cdw11 = (uint32_t)((lba >> 32) & 0xffffffff);
        next->cdw12 = (sectors - 1) & 0xffff;
        next->cdw12 |= (0 << 14) | (0 << 15); // FUA and limited retry.

        if (setupprps(next, buffer, size) != 0) {
            sq->qlock.release();
            return -1;
        }

    #ifdef __x86_64__
        asm volatile ("sfence" : : : "memory");
    #endif

        sq->tail = nexttail;
        write32(&ctrl->pcibar, SUBQUEUEDB(id, ctrl->caps.stride), sq->tail);
        sq->qlock.release();

        // Wait for completion on CQ (extracted to helper for IRQ transition)
        if (waitio(pending) != 0) {
            return -1;
        }

        return 0;
    }

    // I/O completion queue interrupt handler.
    static void ioqueue(struct NArch::Interrupts::isr *isr, struct NArch::CPU::context *ctx) {
        uint8_t vec = (uint8_t)(isr->id & 0xff);

        // Find which controller this interrupt belongs to.
        for (size_t i = 0; i < instance->ctrlcount; i++) {
            struct nvmectrl *ctrl = &instance->controllers[i];
            for (size_t j = 0; j < ctrl->nscount; j++) {
                struct nvmens *ns = &ctrl->namespaces[j];
                if (ctrl->qvecs[ns->nsnum + 1] == vec) {
                    while (true) {
                        volatile struct nvmecqe *cqe = &((struct nvmecqe *)ctrl->iocq[ns->nsnum + 1].entries)[ctrl->iocq[ns->nsnum + 1].head];
                        uint16_t phase = cqe->p;

                        if (phase != ctrl->iocq[ns->nsnum + 1].phase) {
                            break; // No more completions.
                        }

                        // Ensure we see the other fields after seeing the phase bit
                        asm volatile ("" : : : "memory");


                        // Signal waiting thread that this command is complete.
                        uint16_t cid = cqe->cid;
                        struct nvmepending *pending = &ctrl->pending[(ns->nsnum + 1) * QUEUESIZE + (cid % QUEUESIZE)];
                        pending->status = cqe->sc;
                        __atomic_store_n(&pending->done, true, memory_order_release);
                        pending->wq.wakeone(); // Generally speaking, there should only be one waiter per I/O.

                        // Consume!
                        ctrl->iocq[ns->nsnum + 1].head++;
                        if (ctrl->iocq[ns->nsnum + 1].head >= ctrl->iocq[ns->nsnum + 1].size) {
                            ctrl->iocq[ns->nsnum + 1].head = 0;
                            ctrl->iocq[ns->nsnum + 1].phase = !ctrl->iocq[ns->nsnum + 1].phase;
                        }

                        write32(&ctrl->pcibar, COMPQUEUEDB(ns->nsnum + 1, ctrl->caps.stride), ctrl->iocq[ns->nsnum + 1].head);
                    }
                }
            }
        }
    }

    // Initialise an NVMe namespace.
    void NVMEDriver::initnamespace(struct nvmectrl *ctrl, struct nvmens *ns) {
        ns->id = (struct nvmensid *)dmaalloc(sizeof(struct nvmensid));
        if (!ns->id) {
            NUtil::printf("[dev/nvme]: Failed to initialise namespace, could not allocate PRP for Identify command.\n");
            return;
        }

        struct nvmesqe idcmd = { };
        NLib::memset(&idcmd, 0, sizeof(struct nvmesqe));


        idcmd.nsid = ns->nsid;
        idcmd.op = ADMINIDENTIFY;

        idcmd.fuse = 0;
        idcmd.psdt = 0;
        idcmd.cid = ctrl->asq.nextcid++;

        idcmd.prp1 = NArch::VMM::virt2phys(&NArch::VMM::kspace, (uintptr_t)ns->id);
        idcmd.cdw10 = 0x00; // Identify namespace.

        submitadmin(ctrl, &idcmd);

        if (waitadmin(ctrl) != 0) {
            NUtil::printf("[dev/nvme]: Admin identify namespace failed for ns %u\n", ns->nsid);
            dmafree(ns->id, sizeof(struct nvmensid));
            return;
        }

        int fmt = ns->id->flbasize & 0xf;
        ns->blksize = 1 << ns->id->lbaf[fmt].lbadatasize;
        ns->capacity = ns->id->nscap;

        NArch::CPU::get()->currthread->disablemigrate();

        // Register the interrupt onto the allocated vector for this queue's MSI/MSI-X IRQ (ns->nsnum + 1).
        NArch::Interrupts::regisr(ctrl->qvecs[ns->nsnum + 1], ioqueue, true);

        NArch::CPU::get()->currthread->enablemigrate();

        if (createiocqueue(ctrl, ns->nsnum + 1, QUEUESIZE, ns->nsnum + 1) != 0) {
            NUtil::printf("[dev/nvme]: Failed to initialise namespace, could not create I/O completion queue.\n");
            dmafree(ns->id, sizeof(struct nvmensid));
            return;
        }

        // Submission queue must be created after completion queue, because it needs reference to the completion queue ID.
        if (createiosqueue(ctrl, ns->nsnum + 1, QUEUESIZE, 0) != 0) {
            NUtil::printf("[dev/nvme]: Failed to initialise namespace, could not create I/O submission queue.\n");
            dmafree(ctrl->iocq[ns->nsnum + 1].entries, QUEUESIZE * sizeof(struct nvmecqe));
            dmafree(ns->id, sizeof(struct nvmensid));
            return;
        }

        ns->active = true;
        NUtil::printf("[dev/nvme]: Successfully initialised namespace %u.\n", ns->nsid);

        // Add block device to registry and create device node.
        NVMEBlockDevice *nsblkdev = new NVMEBlockDevice(DEVFS::makedev(NSBLKMAJOR, nsblktominor(ctrl->num, ns->nsnum, 0)), this, ctrl, ns);
        registry->add(nsblkdev);

        struct VFS::stat st {
            .st_mode = (VFS::S_IFBLK | 0644),
            .st_uid = 0,
            .st_gid = 0,
            .st_rdev = DEVFS::makedev(NSBLKMAJOR, nsblktominor(ctrl->num, ns->nsnum, 0)),
            .st_size = ns->capacity * ns->blksize,
            .st_blksize = ns->blksize,
            .st_blocks = (ns->capacity * ns->blksize) / 512,
        };
        char namebuf[64];
        NUtil::snprintf(namebuf, sizeof(namebuf), "/dev/nvme%un%u", ctrl->num, ns->nsnum + 1);
        VFS::INode *devnode;
        ssize_t res = VFS::vfs->create(namebuf, &devnode, st);
        assert(res == 0, "Failed to create NVMe block device node.");
        devnode->unref();

        struct parttableinfo *ptinfo = getpartinfo(nsblkdev);
        if (ptinfo) {
            for (size_t i = 0; i < ptinfo->numparts; i++) {
                struct partinfo *part = &ptinfo->partitions[i];

                NUtil::snprintf(namebuf, sizeof(namebuf), "/dev/nvme%un%up%u", ctrl->num, ns->nsnum + 1, i + 1);
                st.st_size = (part->lastlba - part->firstlba + 1) * ns->blksize;
                st.st_blocks = st.st_size / 512;
                st.st_rdev = DEVFS::makedev(NSBLKMAJOR, nsblktominor(ctrl->num, ns->nsnum, i + 1));

                PartitionBlockDevice *partblkdev = new PartitionBlockDevice(
                    DEVFS::makedev(NSBLKMAJOR, nsblktominor(ctrl->num, ns->nsnum, i + 1)),
                    this, nsblkdev, part->firstlba, part->lastlba
                );
                registry->add(partblkdev);

                res = VFS::vfs->create(namebuf, &devnode, st);
                assert(res == 0, "Failed to create NVMe partition block device node.");
                devnode->unref();
            }
        }
    }

    void NVMEDriver::probe(struct devinfo info) {
        NUtil::printf("[dev/nvme]: Discovered a new NVMe controller: %04x:%04x.\n", info.info.pci.vendor, info.info.pci.device);
        struct PCI::bar bar = PCI::getbar(&info, 0);

        if (!bar.mmio) {
            NUtil::printf("[dev/nvme]: Failed to initialise driver, due to unsupported PCI configuration.\n");
            PCI::unmapbar(bar); // Cleanup.
            return;
        }

        uint16_t cmd = PCI::read(&info, 0x4, 2);
        cmd |= (1 << 2) | (1 << 1); // Bus mastering + MMIO.
        PCI::write(&info, 0x4, cmd, 2);

        struct nvmectrl &controller = this->controllers[this->ctrlcount++];
        NLib::memset(&controller, 0, sizeof(struct nvmectrl));
        NLib::memset(controller.pending, 0, sizeof(controller.pending));
        controller.num = this->ctrlcount - 1;

        controller.info = info;
        controller.pcibar = bar; // Reference to the actual PCI bar.

        uint64_t caps = read64(&controller.pcibar, REGCAP);
        NLib::memcpy(&controller.caps, &caps, sizeof(struct nvmecaps)); // Struct-ify capabilities.

        uint32_t csts = read32(&controller.pcibar, REGCSTS);
        NLib::memcpy(&controller.csts, &csts, sizeof(struct nvmecsts)); // Struct-ify status.

        if (controller.csts.ready) { // Controller is already ready! We should reset it to bring it into a known state.
            write32(&controller.pcibar, REGCC, 0); // Reset config. Flips the enable bit to reset.

            for (size_t i = 0; i < 1000000; i++) {
                csts = read32(&controller.pcibar, REGCSTS);
                NLib::memcpy(&controller.csts, &csts, sizeof(struct nvmecsts));

                if (!controller.csts.ready) {
                    break; // We have finally reached a successful disabling of the controller.
                }
            }

            if (controller.csts.ready) { // Did we reach here because we timed out waiting?
                NUtil::printf("[dev/nvme]: Failed to initialise driver, could not reset controller.\n");
                PCI::unmapbar(bar);
                return;
            }
        }

        if (createqueue(&controller.asq, QUEUESIZE, 0, 0, false) != 0) {
            NUtil::printf("[dev/nvme]: Failed to initialise driver, could not create admin submission queue.\n");
            PCI::unmapbar(bar);
            return;
        }

        if (createqueue(&controller.acq, QUEUESIZE, 0, 0, true) != 0) {
            NUtil::printf("[dev/nvme]: Failed to initialise driver, could not create admin completion queue.\n");
            dmafree(controller.asq.entries, QUEUESIZE * sizeof(struct nvmesqe));
            PCI::unmapbar(bar);
            return;
        }

        // Define our queue sizes:
        controller.aqa.asqs = QUEUESIZE - 1;
        controller.aqa.acqs = QUEUESIZE - 1;
        write32(&controller.pcibar, REGAQA, *((uint32_t *)&controller.aqa));

        // Pass DMA addresses to controller.
        write64(&controller.pcibar, REGASQ, controller.asq.dmaaddr);
        write64(&controller.pcibar, REGACQ, controller.acq.dmaaddr);

        controller.cc.en = 0;
        controller.cc.css = CSINVM;
        controller.cc.mps = 0; // 4096 pages.
        controller.cc.ams = 0; // Round-robin arbitration.
        controller.cc.shn = 0;
        controller.cc.iosqes = 6; // 64-bytes per submission queue entry.
        controller.cc.iocqes = 4; // 16-bytes per completion queue entry.
        write32(&controller.pcibar, REGCC, *((uint32_t *)&controller.cc));

        controller.cc.en = 1; // Enable controller.
        write32(&controller.pcibar, REGCC, *((uint32_t *)&controller.cc));

        for (size_t i = 0; i < 1000000; i++) {
            csts = read32(&controller.pcibar, REGCSTS);
            NLib::memcpy(&controller.csts, &csts, sizeof(struct nvmecsts));

            if (controller.csts.ready) {
                break; // We have finally reached a successful enabling of the controller.
            }
        }

        if (!controller.csts.ready) { // Did we reach here because we timed out waiting?
            NUtil::printf("[dev/nvme]: Failed to initialise driver, could not enable controller.\n");
            dmafree(controller.asq.entries, QUEUESIZE * sizeof(struct nvmesqe));
            dmafree(controller.acq.entries, QUEUESIZE * sizeof(struct nvmecqe));
            PCI::unmapbar(bar);
            return;
        }

        NUtil::printf("[dev/nvme]: Successfully enabled controller.\n");

        struct nvmeid *id = (struct nvmeid *)dmaalloc(sizeof(struct nvmeid));
        if (!id) {
            NUtil::printf("[dev/nvme]: Failed to initialise driver, could not allocate PRP for Identify command.\n");
            dmafree(controller.asq.entries, QUEUESIZE * sizeof(struct nvmesqe));
            dmafree(controller.acq.entries, QUEUESIZE * sizeof(struct nvmecqe));
            PCI::unmapbar(bar);
            return;
        }

        struct nvmesqe idcmd = { };
        NLib::memset(&idcmd, 0, sizeof(struct nvmesqe));

        idcmd.nsid = 0;
        idcmd.op = ADMINIDENTIFY;

        idcmd.fuse = 0;
        idcmd.psdt = 0; // Use PRP.
        idcmd.cid = controller.asq.nextcid++;

        idcmd.prp1 = NArch::VMM::virt2phys(&NArch::VMM::kspace, (uintptr_t)id);
        idcmd.cdw10 = 0x01; // Identify controller.

        submitadmin(&controller, &idcmd);

        if (waitadmin(&controller) != 0) {
            NUtil::printf("[dev/nvme]: Failed to identify controller (admin identify failed).\n");
            dmafree(controller.asq.entries, QUEUESIZE * sizeof(struct nvmesqe));
            dmafree(controller.acq.entries, QUEUESIZE * sizeof(struct nvmecqe));
            dmafree(id, sizeof(struct nvmeid));
            PCI::unmapbar(bar);
            return;
        }

        controller.id = id;

        uint32_t *nsids = (uint32_t *)dmaalloc(PAGESIZE);
        if (!nsids) {
            dmafree(controller.asq.entries, QUEUESIZE * sizeof(struct nvmesqe));
            dmafree(controller.acq.entries, QUEUESIZE * sizeof(struct nvmecqe));
            dmafree(controller.id, sizeof(struct nvmeid));
            PCI::unmapbar(bar);
            return;
        }

        struct nvmesqe nsidscmd = { };
        NLib::memset(&nsidscmd, 0, sizeof(struct nvmesqe));

        nsidscmd.nsid = 0;
        nsidscmd.op = ADMINIDENTIFY;

        nsidscmd.cid = controller.asq.nextcid++;

        nsidscmd.prp1 = NArch::VMM::virt2phys(&NArch::VMM::kspace, (uintptr_t)nsids);
        nsidscmd.cdw10 = 0x02; // Identify namespace ID list.

        submitadmin(&controller, &nsidscmd);
        if (waitadmin(&controller) != 0) {
            NUtil::printf("[dev/nvme]: Failed to fetch namespace ID list.\n");
            dmafree(nsids, PAGESIZE);
            dmafree(controller.asq.entries, QUEUESIZE * sizeof(struct nvmesqe));
            dmafree(controller.acq.entries, QUEUESIZE * sizeof(struct nvmecqe));
            dmafree(controller.id, sizeof(struct nvmeid));
            PCI::unmapbar(bar);
            return;
        }

        for (size_t i = 0; i < id->nn; i++) {
            if (nsids[i]) {
                NUtil::printf("[dev/nvme]: Discovered namespace %u with ID %u.\n", i, nsids[i]);
                controller.nscount++;
            }
        }

        NArch::CPU::get()->currthread->disablemigrate();

        // Allocate vectors for each namespace's I/O completion queue, plus one for the admin queue.
        PCI::enablevectors(&info, controller.nscount + 1, controller.qvecs);

        NArch::CPU::get()->currthread->enablemigrate();

        for (size_t i = 0; i < id->nn; i++) {
            if (nsids[i]) { // Namespace ID list will let us know if there is an actual namespace here, or just the capacity for one.
                struct nvmens *ns = &controller.namespaces[i];

                ns->nsid = nsids[i];
                ns->nsnum = i;
                initnamespace(&controller, ns);
            }
        }

        dmafree(nsids, PAGESIZE); // We no longer need these.
        controller.initialised = true;
        NUtil::printf("[dev/nvme]: Successfully initialised NVMe controller with %u namespaces.\n", controller.nscount);
    }

    static struct reginfo info = {
        .name = "nvme",
        .type = reginfo::PCI,
        .match = {
            .pci = {
                .pciclass       = 0x01, // Mass storage controller.
                .pcisubclass    = 0x08, // Non-volatile memory controller.
                .pciprogif      = 0x02, // NVMe.
                .flags          = PCI_MATCHCLASS | PCI_MATCHSUBCLASS | PCI_MATCHPROGIF,
                .vendor         = 0,
                .devcount       = 0,
                .devices        = { }
            }
        }
    };

    REGDRIVER(NVMEDriver, &info);
}
