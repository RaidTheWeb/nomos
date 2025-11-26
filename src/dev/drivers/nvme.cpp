#ifdef __x86_64__
#include <arch/x86_64/apic.hpp>
#include <arch/x86_64/cpu.hpp>
#include <arch/x86_64/vmm.hpp>
#endif

#include <dev/dev.hpp>
#include <dev/pci.hpp>

#include <lib/align.hpp>
#include <sched/event.hpp>

namespace NDev {
    using namespace NFS;

    static constexpr uint16_t REGCAP = 0x0000;
    static constexpr uint16_t REGVS = 0x0008;
    static constexpr uint16_t REGINTMS = 0x000c;
    static constexpr uint16_t REGINTMC = 0x0010;
    static constexpr uint16_t REGCC = 0x0014;
    static constexpr uint16_t REGCSTS = 0x001c;
    static constexpr uint16_t REGNSSR = 0x0020;
    static constexpr uint16_t REGAQA = 0x0024;
    static constexpr uint16_t REGASQ = 0x0028;
    static constexpr uint16_t REGACQ = 0x0030;
    static constexpr uint16_t REGCMBLOC = 0x0038;
    static constexpr uint16_t REGCMBSIZE = 0x003c;

    // Tail doorbell of submission queue.
    #define SUBQUEUEDB(ID, STRIDE) (0x1000 + (2 * (ID)) * (4 << (STRIDE)))
    // Head doorbell of completion queue.
    #define COMPQUEUEDB(ID, STRIDE) (0x1000 + (2 * (ID) + 1) * (4 << (STRIDE)))

    struct nvmecaps {
        uint64_t mqes   : 16;
        uint64_t cqr    : 1;    // Contiguous queues required.
        uint64_t ams    : 2;    // Arbitration mechanism is supported.
        uint64_t rsvd0  : 5;
        uint64_t to     : 8;    // Timeout.

        uint64_t stride : 4;    // Stride used when calculating doorbell offsets.
        uint64_t nssrs  : 1;    // Subsystem reset supported.
        uint64_t css    : 8;    // Command sets are supported.
        uint64_t rsvd1  : 3;
        uint64_t mpsmin : 4;    // Minimum memory page size.
        uint64_t mpsmax : 4;    // Maximum memory page size.
        uint64_t pmrs   : 1;    // Persistent memory region is supported.
        uint64_t cmbs   : 1;    // Controller memory buffer is supported.
        uint64_t rsvd2  : 6;
    } __attribute__((packed));

    static constexpr uint8_t CSINVM = 0x00;
    static constexpr uint8_t CSIKV = 0x01;
    static constexpr uint8_t CSIZNS = 0x02;

    struct nvmecc { // Controller command.
        uint32_t en     : 1;    // Controller enable.
        uint32_t rsvd1  : 3;
        uint32_t css    : 3;    // I/O command set.
        uint32_t mps    : 4;    // Memory page size.
        uint32_t ams    : 3;    // Arbitration shutdown mechanism selected.
        uint32_t shn    : 2;    // Shutdown notification.
        uint32_t iosqes : 4;    // Submission queue entry size (I/O).
        uint32_t iocqes : 4;    // Completion queue entry size (I/O).
        uint32_t rsvd2  : 8;
    } __attribute__((packed));

    struct nvmecsts { // Controller status.
        uint32_t ready  : 1;    // Is the controller ready yet?
        uint32_t cfs    : 1;    // Fatal status.
        uint32_t shst   : 2;    // Shutdown status.
        uint32_t nssro  : 1;    // Subsystem reset occurred.
        uint32_t pp     : 1;    // Processing paused.
        uint32_t rsvd0  : 26;
    } __attribute__((packed));

    struct nvmeaqa { // Admin queue attributes.
        uint32_t asqs   : 16;   // Submission queue size.
        uint32_t acqs   : 16;   // Completion queue size.
    } __attribute__((packed));

    static constexpr uint8_t ADMINDELETESQ = 0x00;
    static constexpr uint8_t ADMINCREATESQ = 0x01;
    static constexpr uint8_t ADMINGETLOGPAGE = 0x02;
    static constexpr uint8_t ADMINDELETECQ = 0x04;
    static constexpr uint8_t ADMINCREATECQ = 0x05;
    static constexpr uint8_t ADMINIDENTIFY = 0x06;

    static constexpr uint8_t IOWRITE = 0x01;
    static constexpr uint8_t IOREAD = 0x02;

    struct nvmesqe { // Submission queue entry.
        uint8_t op;             // Opcode.
        uint8_t fuse    : 2;    // Fused operation.
        uint8_t rsvd0   : 4;
        uint8_t psdt    : 2;    // PRP or SGL?
        uint16_t cid;           // Command ID.
        uint32_t nsid;          // Namespace ID.
        uint64_t rsvd1;
        uint64_t mptr;          // Metadata.
        union {
            struct {
                uint64_t prp1;
                uint64_t prp2;
            };
            struct {
                uint64_t addr;
                uint32_t length;
                uint8_t rsvd0[3];
                uint8_t type;
            } sgl;
        };
        // Command Dwords:

        uint32_t cdw10;
        uint32_t cdw11;
        uint32_t cdw12;
        uint32_t cdw13;
        uint32_t cdw14;
        uint32_t cdw15;
    } __attribute__((packed));

    struct nvmecqe { // Completion queue entry.
        uint32_t dw0;               // Command-specific dword (return result or similar, it depends).
        uint32_t rsvd0;
        uint16_t sqhead;            // Head of submission queue this came from.
        uint16_t sqid;              // ID of submission queue this came from.
        uint16_t cid;               // Command ID.

        // Status:
        uint16_t p       : 1;        // Command phase.
        uint16_t sc      : 8;        // Command status code.
        uint16_t sct     : 3;        // Command status code type.
        uint16_t rsvd1   : 2;
        uint16_t m       : 1;        // More?
        uint16_t dnr     : 1;        // Do-Not-Retry.
    } __attribute__((packed));

    struct nvmeid { // Controller identification command result.
        uint16_t vendor;            // Vendor.
        uint16_t ssvendor;          // Subsystem vendor.
        uint8_t serialnumber[20];   // Serial number (ASCII, not NUL-terminated).
        uint8_t modelnumber[40];    // Model number (ASCII, not NUL-terminated).
        uint8_t fwrev[8];           // Firmware revision (ASCII, not NUL-terminated).
        uint8_t rab;                // Recommended arbitration burst.
        uint8_t ieee[3];            // IEEE OUI identifier.
        uint8_t cmic;               // CMI and NSS caps.
        uint8_t mdts;               // Maximum data transfer size.
        uint16_t cntlid;            // Controller ID.
        uint32_t version;           // Controller version.
        uint32_t rtd3r;             // RTD3 resume latency.
        uint32_t rtd3e;             // RTD3 entry latency.
        uint32_t oaes;              // Optional async events supported.
        uint32_t ctrattr;           // Controller attributes.
        uint8_t rsvd0[12];
        uint8_t fguid[16];          // FGUID.
        uint8_t rsvd1[128];
        uint16_t oacs;              // Optional admin command support.
        uint8_t acl;                // Abort command list.
        uint8_t aerl;               // Async event request limit.
        uint8_t fwupdates;          // Firmware updates.
        uint8_t logpageattr;        // Log page attributes.
        uint8_t elpe;               // Error log page entries.
        uint8_t npss;               // Number of power states (for PSD).
        uint8_t avscc;              // Admin vendor-specific command configs.
        uint8_t apsta;              // Autonomous power state attributes.
        uint16_t wctemp;            // Warming temperature threshold.
        uint16_t cctemp;            // Critical temperature threshold.
        uint16_t mtfa;              // Maximum time for firmware to activate.
        uint32_t hmpsize;           // Preferred size to be used for host buffer.
        uint32_t hmmsize;           // Minimum size to be used for host buffer.
        uint64_t tnvmcap[2];        // Total NVM capacity (128-bit; two 64-bit values).
        uint64_t unvmcap[2];        // Unallocated NVM capacity (128-bit).
        uint32_t rpmbs;             // RPMB support.
        uint16_t edstt;             // Extended device self-test time.
        uint8_t dsto;               // Self-test options.
        uint8_t fwug;               // Firmware update granuality.
        uint16_t kas;               // Keep-alive support.
        uint16_t hosttattr;         // Host thermal management attributes.
        uint16_t mitmtemp;          // Minimum thermal management temperature.
        uint16_t mxtmtemp;          // Maximum thermal management temperature.
        uint32_t sanicap;           // Sanitisation capabilities.
        uint8_t rsvd2[180];
        uint8_t sqes;               // Submission queue entry size.
        uint8_t cqes;               // Completion queue entry size.
        uint16_t rsvd3;
        uint32_t nn;                // Number of namespaces controlled by this controller.
        uint16_t oncs;              // Optional NVM command support.
        uint16_t fuses;             // Fused operation support.
        uint8_t fna;                // Format NVM attributes.
        uint8_t vwc;                // Volatile write cache.
        uint16_t awun;              // Atomic write unit normal.
        uint16_t awupf;             // Atomic write unit failure.
        uint8_t nvscc;              // Vendor-specific command configs for NVM.
        uint8_t rsvd4;
        uint16_t acwu;              // Atomic compare+write unit.
        uint16_t rsvd5;
        uint32_t sgls;              // SGL support.
        uint32_t rsvd6[178];
        uint8_t subnqn[256];        // Subsystem NVMe qualified name.
        uint8_t rsvd7[768];
        uint8_t psd[1024];          // Power state descriptors.
    } __attribute__((packed));

    struct nvmensid { // Namespace identification command result.
        uint64_t nssize;            // Namespace LBA size.
        uint64_t nscap;             // Namespace capacity.
        uint64_t nsutilisation;     // Namespace utilisation.
        uint8_t nsfeatures;         // Namespace features.
        uint8_t nlbaf;              // Number of LBA formats.
        uint8_t flbasize;           // Size of a formatted LBA.
        uint8_t metacaps;           // Metadata capabilities.
        uint8_t dpc;                // Data protection capabilities.
        uint8_t dps;                // Data protection type settings.
        uint8_t nsmic;              // NMI and NSS caps.
        uint8_t rsvcap;             // Reservation capabilities.
        uint8_t fpi;                // Format progress indicator.
        uint8_t dlfeat;             // Deallocate features.
        uint16_t nawun;             // NS atomic write normal.
        uint16_t nawupf;            // NS atomic write power fail.
        uint16_t nacwu;             // NS atomic compare+write unit.
        uint16_t nabsn;             // NS atomic boundary size normal.
        uint16_t nabo;              // NS atomic boundary offset.
        uint16_t nabspf;            // NS atomic boundary size power fail.
        uint16_t noiob;             // NS optimal I/O boundary.
        uint64_t nvmcap[2];         // NVM capacity.
        uint8_t rsvd0[40];
        uint8_t nguid[16];          // NS GUID.
        uint8_t eui64[8];           // EUI-64.
        struct {
            uint16_t ms;            // Metadata size.
            uint8_t lbadatasize;    // LBA data size.
            uint8_t rp      : 2;    // Relative performance.
            uint8_t rsvd0   : 6;
        } lbaf[16];                 // LBA formats.
        uint8_t rsvd1[192];
        uint8_t vs[3712];           // Vendor-specific NS attributes fill the rest of the page.
    } __attribute__((packed));

    struct nvmedsmr { // DSM range.
        uint64_t startlba;          // Starting LBA.
        uint32_t nlblocks;          // Number of logical blocks.
        uint16_t rsvd0;
        uint16_t cid;               // Command ID.
        uint32_t rsvd1;
    } __attribute__((packed));

    struct nvmequeue {
        uint32_t head;
        uint32_t tail;
        uint32_t size;
        uint32_t id;
        uint16_t cqvec;
        uint8_t phase;
        void *entries;
        uintptr_t dmaaddr;

        uint16_t nextcid; // Next command ID for this queue. Only use for submission queues.
    };

    struct nvmens {
        uint32_t nsid; // Namespace ID (Given by the controller).
        uint32_t nsnum; // Namespace number (0-based index).
        struct nvmensid *id;
        uint64_t capacity;
        uint32_t blksize;
        bool active;
        bool formatted;
        char guid[37];
    };

    static constexpr size_t MAXQUEUES = 64;
    static constexpr size_t MAXCTRL = 16;
    static constexpr size_t MAXNS = 256;
    static constexpr size_t PAGESIZE = 4096;
    static constexpr size_t QUEUESIZE = 1024;

    struct nvmeprplist {
        uint64_t entries[PAGESIZE / sizeof(uint64_t)];
    };

    // Struct for pending operations.
    struct nvmepending {
        NSched::WaitQueue wq; // Wait queue for this pending operation.
        bool done; // Is the operation done? Atomic.
        int status;
        uint8_t inuse; // Are we using this slot? Atomic.
    };

    struct nvmectrl {
        struct PCI::bar pcibar;
        struct nvmecaps caps;
        struct nvmecc cc;
        struct nvmecsts csts;
        struct nvmeaqa aqa;

        struct nvmequeue asq;
        struct nvmequeue acq;
        struct nvmequeue iosq[MAXQUEUES];
        struct nvmequeue iocq[MAXQUEUES];

        struct nvmeid *id; // Reference to an identification struct for immediate access.

        struct nvmens namespaces[MAXNS];
        uint8_t qvecs[MAXNS + 1]; // Vectors used for each namespace's I/O completion queue.
        uint32_t nscount;
        uint32_t activenscount;

        struct devinfo info;

        bool initialised;

        struct nvmepending pending[MAXQUEUES * QUEUESIZE];

        // XXX: Per-controller locks.
    };

    static inline uint64_t read64(struct PCI::bar *bar, uint64_t reg) {
        return *((volatile uint64_t *)(bar->base + reg));
    }

    static inline uint32_t read32(struct PCI::bar *bar, uint64_t reg) {
        return *((volatile uint32_t *)(bar->base + reg));
    }

    static inline uint16_t read16(struct PCI::bar *bar, uint64_t reg) {
        return *((volatile uint16_t *)(bar->base + reg));
    }

    static inline uint8_t read8(struct PCI::bar *bar, uint64_t reg) {
        return *((volatile uint8_t *)(bar->base + reg));
    }

    static inline void write64(struct PCI::bar *bar, uint64_t reg, uint64_t val) {
        *((volatile uint64_t *)(bar->base + reg)) = val;
    }

    static inline void write32(struct PCI::bar *bar, uint64_t reg, uint32_t val) {
        *((volatile uint32_t *)(bar->base + reg)) = val;
    }

    static inline void write16(struct PCI::bar *bar, uint64_t reg, uint16_t val) {
        *((volatile uint16_t *)(bar->base + reg)) = val;
    }

    static inline void write8(struct PCI::bar *bar, uint64_t reg, uint8_t val) {
        *((volatile uint8_t *)(bar->base + reg)) = val;
    }

    // Allocate DMA-capable memory.
    static void *dmaalloc(size_t size) {
        return NArch::hhdmoff(NArch::PMM::alloc(size));
    }

    // Free DMA-capable memory.
    static void dmafree(void *ptr, size_t size) {
        NArch::PMM::free(NArch::hhdmsub(ptr), size);
    }

    class NVMEDriver;

    static NVMEDriver *instance;

    class NVMEDriver : public DevDriver {
        private:
            struct nvmectrl controllers[MAXCTRL];
            size_t ctrlcount = 0;
        public:
            NVMEDriver(void) {
                instance = this;
            }

            ~NVMEDriver() {
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

                if (this->createqueue(&ctrl->iosq[id], size, id, 0, false) != 0) {
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

                if (this->createqueue(&ctrl->iocq[id], size, id, vec, true) != 0) {
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

            int iorequest(struct nvmectrl *ctrl, uint16_t id, uint8_t opcode, uint32_t nsid, uint64_t lba, uint16_t sectors, void *buffer, size_t size) {
                struct nvmequeue *sq = &ctrl->iosq[id];
                struct nvmequeue *cq = &ctrl->iocq[id];

                uint16_t cid = sq->nextcid++;

                struct nvmepending *pending;
                if (preparewait(ctrl, id, cid, &pending) != 0) {
                    return -1;
                }

                uint32_t tail = sq->tail;
                uint32_t nexttail = (tail + 1) % sq->size;

                // Simple full-queue check
                if (nexttail == sq->head) {
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
                    return -1;
                }

            #ifdef __x86_64__
                asm volatile ("sfence" : : : "memory");
            #endif

                sq->tail = nexttail;
                write32(&ctrl->pcibar, SUBQUEUEDB(id, ctrl->caps.stride), sq->tail);

                // Wait for completion on CQ (extracted to helper for IRQ transition)
                if (waitirq(pending) != 0) {
                    return -1;
                }

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
                        // consume CQE and report error
                        ctrl->acq.head++;
                        if (ctrl->acq.head >= ctrl->acq.size) {
                            ctrl->acq.head = 0;
                            ctrl->acq.phase = !ctrl->acq.phase; // Flip phase whenever we wrap around.
                        }

                        write32(&ctrl->pcibar, COMPQUEUEDB(0, ctrl->caps.stride), ctrl->acq.head); // Write to doorbell.
                        return -1;
                    }

                    // consume successful CQE
                    ctrl->acq.head++;
                    if (ctrl->acq.head >= ctrl->acq.size) {
                        ctrl->acq.head = 0;
                        ctrl->acq.phase = !ctrl->acq.phase;
                    }

                    write32(&ctrl->pcibar, COMPQUEUEDB(0, ctrl->caps.stride), ctrl->acq.head); // Write to doorbell.

                    return 0;
                }
            }

            // Sleep calling thread until command is complete (used for I/O commands).
            static int waitirq(struct nvmepending *pending) {
                waitevent(&pending->wq, __atomic_load_n(&pending->done, memory_order_acquire) == true);
                int status = pending->status;
                __atomic_store_n(&pending->inuse, false, memory_order_release); // After this, we can no longer guarantee the pending struct is valid.
                return status ? -1 : 0; // Non-zero status indicates error.
            }

            // Waits for completion of an I/O command.
            static int waitio(struct nvmectrl *ctrl, struct nvmequeue *cq, uint16_t id) {
                for (;;) {
                    volatile struct nvmecqe *cqe = &((struct nvmecqe *)cq->entries)[cq->head];
                    uint16_t phase = cqe->p;

                    if (phase != cq->phase) {
                        asm volatile ("pause");
                        continue;
                    }

                    // Ensure we see the other fields after seeing the phase bit
                    asm volatile ("" : : : "memory");

                    uint16_t status = cqe->sc;
                    if (status != 0) {
                        // consume CQE and report error
                        cq->head++;
                        if (cq->head >= cq->size) {
                            cq->head = 0;
                            cq->phase = !cq->phase;
                        }
                        write32(&ctrl->pcibar, COMPQUEUEDB(id, ctrl->caps.stride), cq->head);
                        return -1;
                    }

                    break;
                }

                // consume successful CQE
                cq->head++;
                if (cq->head >= cq->size) {
                    cq->head = 0;
                    cq->phase = !cq->phase;
                }

                write32(&ctrl->pcibar, COMPQUEUEDB(id, ctrl->caps.stride), cq->head);
                return 0;
            }

            static void ioqueue(struct NArch::Interrupts::isr *isr, struct NArch::CPU::context *ctx) {
                NUtil::printf("NVMe interrupt received!\n");
                uint8_t vec = (uint8_t)(isr->id & 0xff);

                // Find which controller this interrupt belongs to.
                for (size_t i = 0; i < instance->ctrlcount; i++) {
                    struct nvmectrl *ctrl = &instance->controllers[i];
                    for (size_t j = 0; j < ctrl->nscount; j++) {
                        struct nvmens *ns = &ctrl->namespaces[j];
                        if (ctrl->qvecs[ns->nsnum + 1] == vec) {
                            NUtil::printf("Interrupt belongs to controller %u, namespace %u.\n", i, ns->nsid);

                            while (true) {
                                volatile struct nvmecqe *cqe = &((struct nvmecqe *)ctrl->iocq[ns->nsnum + 1].entries)[ctrl->iocq[ns->nsnum + 1].head];
                                uint16_t phase = cqe->p;

                                if (phase != ctrl->iocq[ns->nsnum + 1].phase) {
                                    break; // No more completions.
                                }

                                // Ensure we see the other fields after seeing the phase bit
                                asm volatile ("" : : : "memory");

                                uint16_t cid = cqe->cid;
                                struct nvmepending *pending = &ctrl->pending[(ns->nsnum + 1) * QUEUESIZE + (cid % QUEUESIZE)];
                                pending->status = cqe->sc;
                                __atomic_store_n(&pending->done, true, memory_order_release);
                                pending->wq.wake();

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
            void initnamespace(struct nvmectrl *ctrl, struct nvmens *ns) {
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

                // Read first byte from namespace and print it (test read).
                uint8_t testbuf[512] = { 0 };
                if (iorequest(ctrl, ns->nsnum + 1, IOREAD, ns->nsid, 0, 1, testbuf, 512) != 0) {
                    NUtil::printf("[dev/nvme]: Test read from namespace %u failed.\n", ns->nsid);
                } else {
                    NUtil::printf("[dev/nvme]: Test read from namespace %u succeeded, first byte: 0x%02x\n", ns->nsid, testbuf[0]);
                }
            }

            void probe(struct devinfo info) override {
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

                if (this->createqueue(&controller.asq, QUEUESIZE, 0, 0, false) != 0) {
                    NUtil::printf("[dev/nvme]: Failed to initialise driver, could not create admin submission queue.\n");
                    PCI::unmapbar(bar);
                    return;
                }

                if (this->createqueue(&controller.acq, QUEUESIZE, 0, 0, true) != 0) {
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
    };

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
