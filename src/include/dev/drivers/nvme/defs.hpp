#ifndef _DEV__DRIVERS__NVME__STRUCTS_HPP
#define _DEV__DRIVERS__NVME__STRUCTS_HPP

#include <dev/dev.hpp>
#include <dev/pci.hpp>

#include <sched/event.hpp>
#include <stddef.h>
#include <stdint.h>

namespace NDev {
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

        NArch::Spinlock qlock; // Lock for this queue.

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
        uint32_t num; // Controller number.

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
}

#endif