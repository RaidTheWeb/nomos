#ifdef __x86_64__
#include <arch/x86_64/apic.hpp>
#include <arch/x86_64/cpu.hpp>
#include <arch/x86_64/e9.hpp>
#include <arch/x86_64/tsc.hpp>
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
#include <std/stdatomic.h>
#include <dev/block.hpp>

namespace NDev {
    using namespace NFS;

    // Allocate DMA-capable memory.
    static void *dmaalloc(size_t size) {
        void *ptr = NArch::hhdmoff(NArch::PMM::alloc(size, NArch::PMM::FLAGS_DEVICE));
        if (ptr) {
            NLib::memset(ptr, 0, size);
        }
        return ptr;
    }

    // Free DMA-capable memory.
    static void dmafree(void *ptr, size_t size) {
        if (ptr) {
            NArch::PMM::free(NArch::hhdmsub(ptr), size);
        }
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
                for (size_t q = 0; q < ctrl->nscount; q++) {
                    if (ctrl->iosq[q + 1].entries) {
                        dmafree(ctrl->iosq[q + 1].entries, ctrl->iosq[q + 1].size * sizeof(struct nvmesqe));
                    }
                    if (ctrl->iocq[q + 1].entries) {
                        dmafree(ctrl->iocq[q + 1].entries, ctrl->iocq[q + 1].size * sizeof(struct nvmecqe));
                    }
                }

                // Free identification structure.
                dmafree(ctrl->id, PAGESIZE);
            }
            PCI::unmapbar(ctrl->pcibar);
        }
    }

    // Create a queue (submission or completion).
    static int createqueue(struct nvmequeue *queue, uint32_t size, uint32_t id, uint16_t cqvec, bool iscq) {
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

        queue->dmaaddr = NArch::VMM::virt2phys(&NArch::VMM::kspace, (uintptr_t)queue->entries);
        return 0;
    }

    // Poll for completion of an admin command (used only during controller initialisation).
    static int polladmin(struct nvmectrl *ctrl, uint64_t timeoutus) {
        uint64_t start = NArch::TSC::query();
        uint64_t hz = NArch::TSC::hz;
        uint64_t deadline = start + (timeoutus * hz) / 1000000;

        for (;;) {
            volatile struct nvmecqe *cqe = &((struct nvmecqe *)ctrl->acq.entries)[ctrl->acq.head];

            if (cqe->p == ctrl->acq.phase) {
                // Ensure we read all fields after seeing the phase bit.
                asm volatile("lfence" ::: "memory");

                uint16_t status = cqe->sc;

                // Consume the CQE.
                ctrl->acq.head++;
                if (ctrl->acq.head >= ctrl->acq.size) {
                    ctrl->acq.head = 0;
                    ctrl->acq.phase = !ctrl->acq.phase;
                }

                write32(&ctrl->pcibar, COMPQUEUEDB(0, ctrl->caps.stride), ctrl->acq.head);

                return (status != 0) ? -1 : 0;
            }

            if (NArch::TSC::query() > deadline) {
                return -1; // Timeout.
            }

            asm volatile("pause");
        }
    }

    // Submit commands to the admin queue.
    static int submitadmin(struct nvmectrl *ctrl, struct nvmesqe *cmd) {
        NLib::ScopeSpinlock lock(&ctrl->asq.qlock);

        uint16_t tail = ctrl->asq.tail;
        struct nvmesqe *next = &((struct nvmesqe *)ctrl->asq.entries)[tail];

        NLib::memcpy(next, cmd, sizeof(struct nvmesqe));

#ifdef __x86_64__
        asm volatile("sfence" ::: "memory");
#endif

        tail = (tail + 1) % ctrl->asq.size;
        ctrl->asq.tail = tail;

        write32(&ctrl->pcibar, SUBQUEUEDB(0, ctrl->caps.stride), tail);
        return 0;
    }

    // Create an I/O completion queue.
    static int createiocqueue(struct nvmectrl *ctrl, uint16_t id, uint32_t size, uint16_t msixidx, uint8_t cpuvec) {
        if (createqueue(&ctrl->iocq[id], size, id, cpuvec, true) != 0) {
            return -1;
        }

        struct nvmesqe ciocmd = { };
        NLib::memset(&ciocmd, 0, sizeof(struct nvmesqe));

        ciocmd.op = ADMINCREATECQ;
        ciocmd.prp1 = ctrl->iocq[id].dmaaddr;
        ciocmd.cid = ctrl->asq.nextcid++;

        ciocmd.cdw10 = (id & 0xffff) | ((size - 1) << 16);
        ciocmd.cdw11 = (msixidx << 16) | (1 << 1) | (1 << 0); // MSI-X index, interrupts enabled, physically contiguous.

        submitadmin(ctrl, &ciocmd);

        if (polladmin(ctrl, 5000000) != 0) { // 5 second timeout.
            dmafree(ctrl->iocq[id].entries, size * sizeof(struct nvmecqe));
            ctrl->iocq[id].entries = NULL;
            return -1;
        }
        return 0;
    }

    // Create an I/O submission queue.
    static int createiosqueue(struct nvmectrl *ctrl, uint16_t id, uint32_t size, uint16_t cqid) {
        if (createqueue(&ctrl->iosq[id], size, id, 0, false) != 0) {
            return -1;
        }

        struct nvmesqe ciocmd = { };
        NLib::memset(&ciocmd, 0, sizeof(struct nvmesqe));

        ciocmd.op = ADMINCREATESQ;
        ciocmd.prp1 = ctrl->iosq[id].dmaaddr;
        ciocmd.cid = ctrl->asq.nextcid++;

        ciocmd.cdw10 = (id & 0xffff) | ((size - 1) << 16);
        ciocmd.cdw11 = (cqid << 16) | (1 << 0); // Physically contiguous.

        submitadmin(ctrl, &ciocmd);

        if (polladmin(ctrl, 5000000) != 0) { // 5 second timeout.
            dmafree(ctrl->iosq[id].entries, size * sizeof(struct nvmesqe));
            ctrl->iosq[id].entries = NULL;
            return -1;
        }
        return 0;
    }

    // Create a PRP list for transfers larger than two pages.
    static uintptr_t createprplist(void *buffer, size_t size) {
        uintptr_t start = (uintptr_t)buffer;
        uintptr_t end = start + size;
        uintptr_t firstpage = NLib::aligndown(start, PAGESIZE);
        uintptr_t lastpage = NLib::alignup(end, PAGESIZE);

        size_t numpages = (lastpage - firstpage) / PAGESIZE;

        if (numpages <= 2) {
            return 0; // No PRP list needed.
        }

        // PRP list contains entries for pages 2 through N (first page is in prp1).
        size_t listentries = numpages - 1;
        const size_t entriesperpage = PAGESIZE / sizeof(uint64_t);
        size_t numlistpages = (listentries + entriesperpage - 1) / entriesperpage;

        uintptr_t listsphys = (uintptr_t)NArch::PMM::alloc(numlistpages * PAGESIZE);
        if (!listsphys) {
            return 0;
        }

        struct nvmeprplist *base = (struct nvmeprplist *)NArch::hhdmoff((void *)listsphys);
        NLib::memset(base, 0, numlistpages * PAGESIZE);

        size_t currentidx = 0;
        struct nvmeprplist *curr = base;

        for (size_t i = 1; i < numpages; i++) {
            uintptr_t virt = firstpage + (i * PAGESIZE);
            uintptr_t phys = NArch::VMM::virt2phys(&NArch::VMM::kspace, virt);

            curr->entries[currentidx++] = phys;

            if (currentidx >= entriesperpage && (i + 1) < numpages) {
                // Need to chain to next list page.
                currentidx = 0;
                curr = (struct nvmeprplist *)((uintptr_t)curr + PAGESIZE);
            }
        }

        return listsphys;
    }

    static void freeprplist(uintptr_t listphys, void *buffer, size_t size) {
        if (!listphys) {
            return;
        }

        uintptr_t start = (uintptr_t)buffer;
        uintptr_t end = start + size;
        uintptr_t firstpage = NLib::aligndown(start, PAGESIZE);
        uintptr_t lastpage = NLib::alignup(end, PAGESIZE);

        size_t numpages = (lastpage - firstpage) / PAGESIZE;
        if (numpages <= 2) {
            return;
        }

        size_t listentries = numpages - 1;
        const size_t entriesperpage = PAGESIZE / sizeof(uint64_t);
        size_t numlistpages = (listentries + entriesperpage - 1) / entriesperpage;

        NArch::PMM::free((void *)listphys, numlistpages * PAGESIZE);
    }

    // Prepare PRPs for a command.
    static int setupprps(struct nvmesqe *cmd, void *buffer, size_t size) {
        if (size == 0) {
            cmd->prp1 = 0;
            cmd->prp2 = 0;
            return -1;
        }

        uint64_t bufferphys = NArch::VMM::virt2phys(&NArch::VMM::kspace, (uintptr_t)buffer);

        if (size <= PAGESIZE) {
            cmd->prp1 = bufferphys;
            cmd->prp2 = 0;
        } else if (size <= (2 * PAGESIZE)) {
            cmd->prp1 = bufferphys;
            uintptr_t secondpagevirt = NLib::aligndown((uintptr_t)buffer, PAGESIZE) + PAGESIZE;
            cmd->prp2 = NArch::VMM::virt2phys(&NArch::VMM::kspace, secondpagevirt);
        } else {
            cmd->prp1 = bufferphys;

            uintptr_t listphys = createprplist(buffer, size);
            if (!listphys) {
                return -1;
            }

            cmd->prp2 = listphys;
        }

        return 0;
    }

    // Allocate a pending slot for I/O tracking.
    static int allocpending(struct nvmectrl *ctrl, uint16_t qid, uint16_t *outcid, struct nvmepending **outpending) {
        struct nvmequeue *sq = &ctrl->iosq[qid];
        size_t baseidx = qid * QUEUESIZE;

        // Atomically load the next CID hint.
        uint16_t startnextcid = __atomic_load_n(&sq->nextcid, memory_order_acquire);

        // Try to find an available slot.
        for (uint16_t i = 0; i < QUEUESIZE; i++) {
            uint16_t slot = (startnextcid + i) % QUEUESIZE;
            struct nvmepending *pending = &ctrl->pending[baseidx + slot];

            bool expected = false;
            if (__atomic_compare_exchange_n(&pending->inuse, &expected, true, false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
                __atomic_store_n(&pending->done, false, memory_order_release);
                __atomic_store_n(&pending->status, 0, memory_order_release);
                pending->submittsc = 0; // Will be set at submission time.

                // Atomically update the next CID hint (best-effort, races are tolerable).
                __atomic_store_n(&sq->nextcid, (slot + 1) % QUEUESIZE, memory_order_release);
                *outcid = slot;
                *outpending = pending;
                return 0;
            }
        }

        return -1; // No slots available.
    }

    // I/O timeout in microseconds (30 seconds).
    static constexpr uint64_t IOTIMEOUTUS = 30000000;

    // Wait for I/O completion with timeout.
    static int waitio(struct nvmepending *pending) {
        uint64_t hz = NArch::TSC::hz;
        uint64_t submittsc = __atomic_load_n(&pending->submittsc, memory_order_acquire);
        uint64_t deadline = submittsc + (IOTIMEOUTUS * hz) / 1000000;

        // Wait loop with timeout check.
        while (!__atomic_load_n(&pending->done, memory_order_acquire)) {
            // Check for timeout.
            uint64_t now = NArch::TSC::query();
            if (now > deadline) {
                NUtil::printf("[dev/nvme]: I/O request timed out after %lu us.\n", IOTIMEOUTUS);
                // Mark as no longer in use so completion handler ignores late arrival.
                __atomic_store_n(&pending->inuse, false, memory_order_release);
                return -1;
            }

            pending->wq.wait();
        }

        int status = __atomic_load_n(&pending->status, memory_order_acquire);
        __atomic_store_n(&pending->inuse, false, memory_order_release);
        return status ? -1 : 0;
    }

    // I/O completion queue interrupt handler.
    static void iocqhandler(struct NArch::Interrupts::isr *isr, struct NArch::CPU::context *ctx) {
        (void)ctx;

        if (!instance) {
            return;
        }

        uint8_t vec = (uint8_t)(isr->id & 0xff);

        // Search for the controller and queue that owns this vector.
        for (size_t c = 0; c < instance->ctrlcount; c++) {
            struct nvmectrl *ctrl = &instance->controllers[c];

            if (!ctrl->initialised) {
                continue;
            }

            // Check each I/O completion queue.
            for (size_t q = 1; q <= ctrl->nscount; q++) {
                struct nvmequeue *cq = &ctrl->iocq[q];
                struct nvmequeue *sq = &ctrl->iosq[q];

                if (!cq->entries || cq->cqvec != vec) {
                    continue;
                }

                cq->qlock.acquire();

                // Process all available completions.
                while (true) {
                    uint32_t cqhead = cq->head;
                    uint8_t cqphase = cq->phase;
                    volatile struct nvmecqe *cqe = &((struct nvmecqe *)cq->entries)[cqhead];

                    if (cqe->p != cqphase) {
                        break; // No more completions.
                    }

                    // Ensure we see all CQE fields after the phase bit.
                    __atomic_thread_fence(memory_order_acquire);

                    // Update submission queue head from completion (atomically for readers).
                    __atomic_store_n(&sq->head, cqe->sqhead, memory_order_release);

                    // Validate CID before accessing pending slot.
                    uint16_t cid = cqe->cid;
                    if (cid >= QUEUESIZE) {
                        goto advancecq;
                    }

                    {
                        struct nvmepending *pending = &ctrl->pending[q * QUEUESIZE + cid];

                        // Validate that this slot is actually in use before signaling.
                        // This guards against late completions after timeout or device bugs.
                        if (!__atomic_load_n(&pending->inuse, memory_order_acquire)) {
                            // Just skip without waking anyone.
                            goto advancecq;
                        }

                        __atomic_store_n(&pending->status, cqe->sc, memory_order_release);
                        __atomic_store_n(&pending->done, true, memory_order_release);
                        pending->wq.wakeone();
                    }

advancecq:
                    // Advance completion queue head.
                    cqhead++;
                    if (cqhead >= cq->size) {
                        cqhead = 0;
                        cqphase = !cqphase;
                    }
                    cq->head = cqhead;
                    cq->phase = cqphase;

                    write32(&ctrl->pcibar, COMPQUEUEDB(q, ctrl->caps.stride), cqhead);
                }

                cq->qlock.release();
            }
        }
    }

    int NVMEDriver::iorequest(struct nvmectrl *ctrl, uint16_t qid, uint8_t opcode, uint32_t nsid, uint64_t lba, uint16_t sectors, void *buffer, size_t size) {
        struct nvmequeue *sq = &ctrl->iosq[qid];

        // Allocate a pending slot first.
        uint16_t cid;
        struct nvmepending *pending;

        int retries = 0;
        while (allocpending(ctrl, qid, &cid, &pending) != 0) {
            if (retries++ > 100) {
                NUtil::printf("[dev/nvme]: No pending slots available.\n");
                return -1;
            }
            NSched::yield();
        }

        int queueretries = 0;
retry:
        // Lock the submission queue for the submission phase.
        sq->qlock.acquire();

        uint32_t tail = sq->tail;
        uint32_t nexttail = (tail + 1) % sq->size;

        // Check if queue is full using atomic read (head is updated by ISR).
        uint32_t sqhead = __atomic_load_n(&sq->head, memory_order_acquire);
        if (nexttail == sqhead) {
            sq->qlock.release();

            // Keep the same pending slot, just retry submission.
            if (queueretries++ > 1000) {
                NUtil::printf("[dev/nvme]: Queue full after 1000 retries.\n");
                __atomic_store_n(&pending->inuse, false, memory_order_release);
                return -1;
            }
            NSched::yield();
            goto retry;
        }

        struct nvmesqe *cmd = &((struct nvmesqe *)sq->entries)[tail];
        NLib::memset(cmd, 0, sizeof(struct nvmesqe));

        cmd->op = opcode;
        cmd->nsid = nsid;
        cmd->cid = cid;
        cmd->psdt = 0;
        cmd->fuse = 0;

        cmd->cdw10 = (uint32_t)(lba & 0xffffffff);
        cmd->cdw11 = (uint32_t)((lba >> 32) & 0xffffffff);
        cmd->cdw12 = (sectors - 1) & 0xffff;

        if (setupprps(cmd, buffer, size) != 0) {
            sq->qlock.release();
            __atomic_store_n(&pending->inuse, false, __ATOMIC_RELEASE);
            return -1;
        }

        uintptr_t prplistaddr = (size > 2 * PAGESIZE) ? cmd->prp2 : 0;

        // Record submission timestamp for timeout detection before ringing doorbell.
        __atomic_store_n(&pending->submittsc, NArch::TSC::query(), memory_order_release);

#ifdef __x86_64__
        asm volatile("sfence" ::: "memory");
#endif

        sq->tail = nexttail;
        write32(&ctrl->pcibar, SUBQUEUEDB(qid, ctrl->caps.stride), sq->tail);

        sq->qlock.release();

        // Wait for completion.
        int result = waitio(pending);

        // Seed entropy from timestamp.
#ifdef __x86_64__
        uint64_t tsc = NArch::TSC::query();
        NArch::CPU::get()->entropypool->addentropy((uint8_t *)&tsc, sizeof(tsc), 1);
#endif

        if (prplistaddr) {
            freeprplist(prplistaddr, buffer, size);
        }

        return result;
    }

    // Initialise an NVMe namespace.
    void NVMEDriver::initnamespace(struct nvmectrl *ctrl, struct nvmens *ns) {
        ns->id = (struct nvmensid *)dmaalloc(sizeof(struct nvmensid));
        if (!ns->id) {
            NUtil::printf("[dev/nvme]: Failed to allocate namespace identification buffer.\n");
            return;
        }

        struct nvmesqe idcmd = { };
        NLib::memset(&idcmd, 0, sizeof(struct nvmesqe));

        idcmd.nsid = ns->nsid;
        idcmd.op = ADMINIDENTIFY;
        idcmd.cid = ctrl->asq.nextcid++;
        idcmd.prp1 = NArch::VMM::virt2phys(&NArch::VMM::kspace, (uintptr_t)ns->id);
        idcmd.cdw10 = 0x00; // Identify namespace.

        submitadmin(ctrl, &idcmd);

        if (polladmin(ctrl, 5000000) != 0) {
            NUtil::printf("[dev/nvme]: Admin identify namespace failed for ns %u.\n", ns->nsid);
            dmafree(ns->id, sizeof(struct nvmensid));
            ns->id = NULL;
            return;
        }

        int fmt = ns->id->flbasize & 0xf;
        ns->blksize = 1 << ns->id->lbaf[fmt].lbadatasize;
        ns->capacity = ns->id->nscap;

        // Create I/O queues for this namespace.
        uint16_t qid = ns->nsnum + 1;
        uint8_t cpuvec = ctrl->qvecs[qid];  // CPU interrupt vector for this queue.

        // Register interrupt handler with CPU vector.
        NArch::CPU::get()->currthread->disablemigrate();
        NArch::Interrupts::regisr(cpuvec, iocqhandler, true);
        NArch::CPU::get()->currthread->enablemigrate();

        // Create completion queue: qid is the MSI-X table index, cpuvec is for interrupt matching.
        if (createiocqueue(ctrl, qid, QUEUESIZE, qid, cpuvec) != 0) {
            NUtil::printf("[dev/nvme]: Failed to create I/O completion queue for ns %u.\n", ns->nsid);
            dmafree(ns->id, sizeof(struct nvmensid));
            ns->id = NULL;
            return;
        }

        if (createiosqueue(ctrl, qid, QUEUESIZE, qid) != 0) {
            NUtil::printf("[dev/nvme]: Failed to create I/O submission queue for ns %u.\n", ns->nsid);
            dmafree(ctrl->iocq[qid].entries, QUEUESIZE * sizeof(struct nvmecqe));
            ctrl->iocq[qid].entries = NULL;
            dmafree(ns->id, sizeof(struct nvmensid));
            ns->id = NULL;
            return;
        }

        ns->active = true;
        ctrl->activenscount++;
        NUtil::printf("[dev/nvme]: Initialised namespace %u (capacity: %lu blocks, block size: %u).\n",
                      ns->nsid, ns->capacity, ns->blksize);

        // Create block device and device node.
        NVMEBlockDevice *nsblkdev = new NVMEBlockDevice(
            DEVFS::makedev(NSBLKMAJOR, nsblktominor(ctrl->num, ns->nsnum, 0)),
            this, ctrl, ns
        );
        registry->add(nsblkdev);

        struct VFS::stat st = { };
        st.st_mode = (VFS::S_IFBLK | 0644);
        st.st_uid = 0;
        st.st_gid = 0;
        st.st_rdev = DEVFS::makedev(NSBLKMAJOR, nsblktominor(ctrl->num, ns->nsnum, 0));
        st.st_size = ns->capacity * ns->blksize;
        st.st_blksize = ns->blksize;
        st.st_blocks = (ns->capacity * ns->blksize) / 512;

        char namebuf[64];
        NUtil::snprintf(namebuf, sizeof(namebuf), "nvme%un%u", ctrl->num, ns->nsnum + 1);
        DEVFS::registerdevfile(namebuf, st);

        struct parttableinfo *ptinfo = getpartinfo(nsblkdev);
        if (ptinfo) {
            for (size_t i = 0; i < ptinfo->numparts; i++) {
                struct partinfo *part = &ptinfo->partitions[i];

                NUtil::snprintf(namebuf, sizeof(namebuf), "nvme%un%up%lu", ctrl->num, ns->nsnum + 1, i + 1);
                st.st_size = (part->lastlba - part->firstlba + 1) * ns->blksize;
                st.st_blocks = st.st_size / 512;
                st.st_rdev = DEVFS::makedev(NSBLKMAJOR, nsblktominor(ctrl->num, ns->nsnum, i + 1));

                PartitionBlockDevice *partblkdev = new PartitionBlockDevice(
                    DEVFS::makedev(NSBLKMAJOR, nsblktominor(ctrl->num, ns->nsnum, i + 1)),
                    this, nsblkdev, part->firstlba, part->lastlba
                );
                registry->add(partblkdev);

                DEVFS::registerdevfile(namebuf, st);
            }
        }
    }

    void NVMEDriver::probe(struct devinfo info) {
        NUtil::printf("[dev/nvme]: Discovered NVMe controller: %04x:%04x.\n",
                      info.info.pci.vendor, info.info.pci.device);

        struct PCI::bar bar = PCI::getbar(&info, 0);

        if (!bar.mmio) {
            NUtil::printf("[dev/nvme]: Controller does not support MMIO.\n");
            PCI::unmapbar(bar);
            return;
        }

        // Enable bus mastering and MMIO.
        uint16_t cmd = PCI::read(&info, 0x4, 2);
        cmd |= (1 << 2) | (1 << 1);
        PCI::write(&info, 0x4, cmd, 2);

        struct nvmectrl *ctrl = &this->controllers[this->ctrlcount];
        NLib::memset(ctrl, 0, sizeof(struct nvmectrl));
        ctrl->num = this->ctrlcount;
        ctrl->info = info;
        ctrl->pcibar = bar;

        // Read capabilities.
        uint64_t caps = read64(&ctrl->pcibar, REGCAP);
        NLib::memcpy(&ctrl->caps, &caps, sizeof(struct nvmecaps));

        // Check if controller is ready and reset if needed.
        uint32_t csts = read32(&ctrl->pcibar, REGCSTS);
        NLib::memcpy(&ctrl->csts, &csts, sizeof(struct nvmecsts));

        if (ctrl->csts.ready) {
            write32(&ctrl->pcibar, REGCC, 0);

            uint64_t timeout = ctrl->caps.to * 500000; // Timeout in microseconds.
            uint64_t start = NArch::TSC::query();
            uint64_t hz = NArch::TSC::hz;
            uint64_t deadline = start + (timeout * hz) / 1000000;

            while (NArch::TSC::query() < deadline) {
                csts = read32(&ctrl->pcibar, REGCSTS);
                NLib::memcpy(&ctrl->csts, &csts, sizeof(struct nvmecsts));
                if (!ctrl->csts.ready) {
                    break;
                }
                asm volatile("pause");
            }

            if (ctrl->csts.ready) {
                NUtil::printf("[dev/nvme]: Failed to reset controller.\n");
                PCI::unmapbar(bar);
                return;
            }
        }

        // Create admin queues.
        if (createqueue(&ctrl->asq, QUEUESIZE, 0, 0, false) != 0) {
            NUtil::printf("[dev/nvme]: Failed to create admin submission queue.\n");
            PCI::unmapbar(bar);
            return;
        }

        if (createqueue(&ctrl->acq, QUEUESIZE, 0, 0, true) != 0) {
            NUtil::printf("[dev/nvme]: Failed to create admin completion queue.\n");
            dmafree(ctrl->asq.entries, QUEUESIZE * sizeof(struct nvmesqe));
            PCI::unmapbar(bar);
            return;
        }

        // Configure admin queue attributes.
        ctrl->aqa.asqs = QUEUESIZE - 1;
        ctrl->aqa.acqs = QUEUESIZE - 1;
        write32(&ctrl->pcibar, REGAQA, *((uint32_t *)&ctrl->aqa));

        // Set admin queue base addresses.
        write64(&ctrl->pcibar, REGASQ, ctrl->asq.dmaaddr);
        write64(&ctrl->pcibar, REGACQ, ctrl->acq.dmaaddr);

        // Configure and enable controller.
        ctrl->cc.en = 0;
        ctrl->cc.css = CSINVM;
        ctrl->cc.mps = 0; // 4096 byte pages.
        ctrl->cc.ams = 0; // Round-robin arbitration.
        ctrl->cc.shn = 0;
        ctrl->cc.iosqes = 6; // 64 bytes per SQE.
        ctrl->cc.iocqes = 4; // 16 bytes per CQE.
        write32(&ctrl->pcibar, REGCC, *((uint32_t *)&ctrl->cc));

        ctrl->cc.en = 1;
        write32(&ctrl->pcibar, REGCC, *((uint32_t *)&ctrl->cc));

        // Wait for controller ready.
        uint64_t timeout = ctrl->caps.to * 500000;
        uint64_t start = NArch::TSC::query();
        uint64_t hz = NArch::TSC::hz;
        uint64_t deadline = start + (timeout * hz) / 1000000;

        while (NArch::TSC::query() < deadline) {
            csts = read32(&ctrl->pcibar, REGCSTS);
            NLib::memcpy(&ctrl->csts, &csts, sizeof(struct nvmecsts));
            if (ctrl->csts.ready) {
                break;
            }
            asm volatile("pause");
        }

        if (!ctrl->csts.ready) {
            NUtil::printf("[dev/nvme]: Controller failed to become ready.\n");
            dmafree(ctrl->asq.entries, QUEUESIZE * sizeof(struct nvmesqe));
            dmafree(ctrl->acq.entries, QUEUESIZE * sizeof(struct nvmecqe));
            PCI::unmapbar(bar);
            return;
        }

        NUtil::printf("[dev/nvme]: Controller enabled successfully.\n");

        // Identify controller.
        struct nvmeid *id = (struct nvmeid *)dmaalloc(sizeof(struct nvmeid));
        if (!id) {
            NUtil::printf("[dev/nvme]: Failed to allocate controller identification buffer.\n");
            dmafree(ctrl->asq.entries, QUEUESIZE * sizeof(struct nvmesqe));
            dmafree(ctrl->acq.entries, QUEUESIZE * sizeof(struct nvmecqe));
            PCI::unmapbar(bar);
            return;
        }

        struct nvmesqe idcmd = { };
        NLib::memset(&idcmd, 0, sizeof(struct nvmesqe));

        idcmd.nsid = 0;
        idcmd.op = ADMINIDENTIFY;
        idcmd.cid = ctrl->asq.nextcid++;
        idcmd.prp1 = NArch::VMM::virt2phys(&NArch::VMM::kspace, (uintptr_t)id);
        idcmd.cdw10 = 0x01; // Identify controller.

        submitadmin(ctrl, &idcmd);

        if (polladmin(ctrl, 5000000) != 0) {
            NUtil::printf("[dev/nvme]: Failed to identify controller.\n");
            dmafree(id, sizeof(struct nvmeid));
            dmafree(ctrl->asq.entries, QUEUESIZE * sizeof(struct nvmesqe));
            dmafree(ctrl->acq.entries, QUEUESIZE * sizeof(struct nvmecqe));
            PCI::unmapbar(bar);
            return;
        }

        ctrl->id = id;

        // Get namespace ID list.
        uint32_t *nsids = (uint32_t *)dmaalloc(PAGESIZE);
        if (!nsids) {
            NUtil::printf("[dev/nvme]: Failed to allocate namespace ID list buffer.\n");
            dmafree(ctrl->id, sizeof(struct nvmeid));
            dmafree(ctrl->asq.entries, QUEUESIZE * sizeof(struct nvmesqe));
            dmafree(ctrl->acq.entries, QUEUESIZE * sizeof(struct nvmecqe));
            PCI::unmapbar(bar);
            return;
        }

        struct nvmesqe nsidscmd = { };
        NLib::memset(&nsidscmd, 0, sizeof(struct nvmesqe));

        nsidscmd.nsid = 0;
        nsidscmd.op = ADMINIDENTIFY;
        nsidscmd.cid = ctrl->asq.nextcid++;
        nsidscmd.prp1 = NArch::VMM::virt2phys(&NArch::VMM::kspace, (uintptr_t)nsids);
        nsidscmd.cdw10 = 0x02; // Identify namespace ID list.

        submitadmin(ctrl, &nsidscmd);

        if (polladmin(ctrl, 5000000) != 0) {
            NUtil::printf("[dev/nvme]: Failed to get namespace ID list.\n");
            dmafree(nsids, PAGESIZE);
            dmafree(ctrl->id, sizeof(struct nvmeid));
            dmafree(ctrl->asq.entries, QUEUESIZE * sizeof(struct nvmesqe));
            dmafree(ctrl->acq.entries, QUEUESIZE * sizeof(struct nvmecqe));
            PCI::unmapbar(bar);
            return;
        }

        // Count active namespaces.
        ctrl->nscount = 0;
        for (size_t i = 0; i < id->nn && i < MAXNS; i++) {
            if (nsids[i]) {
                ctrl->nscount++;
            }
        }

        NUtil::printf("[dev/nvme]: Controller has %u namespace(s).\n", ctrl->nscount);

        // Allocate MSI/MSI-X vectors.
        NArch::CPU::get()->currthread->disablemigrate();
        PCI::enablevectors(&info, ctrl->nscount + 1, ctrl->qvecs);
        NArch::CPU::get()->currthread->enablemigrate();

        // Mark controller as initialised before creating namespaces so interrupts work.
        ctrl->initialised = true;
        this->ctrlcount++;

        // Initialise each namespace.
        size_t nsnum = 0;
        for (size_t i = 0; i < id->nn && i < MAXNS; i++) {
            if (nsids[i]) {
                struct nvmens *ns = &ctrl->namespaces[nsnum];
                ns->nsid = nsids[i];
                ns->nsnum = nsnum;
                initnamespace(ctrl, ns);
                nsnum++;
            }
        }

        dmafree(nsids, PAGESIZE);

        NUtil::printf("[dev/nvme]: Controller initialisation complete (%u active namespace(s)).\n",
                      ctrl->activenscount);
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
