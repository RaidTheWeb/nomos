#include <dev/dev.hpp>
#include <dev/pci.hpp>

namespace NDev {
    using namespace NFS;

    struct nvmebar {
        uint64_t caps; // Controler capabilities.
        uint32_t version;       // Controller version.
        uint32_t intms;         // Interrupt mask set.
        uint32_t intmc;         // Interrupt mask clear.
        uint32_t conf;          // Controller config.
        uint32_t rsvd0;
        uint32_t status;        // Controller status.
        uint32_t rsvd1;
        uint32_t aqa;           // Admin queue attributes.
        uint32_t asq;           // Admin submission queue.
        uint32_t acq;           // Admin completion queue.
    } __attribute__((packed));

    // Tail doorbell of submission queue.
    #define SUBQUEUEDB(ID, STRIDE) (0x1000 + (2 * (ID)) * (STRIDE))
    // Head doorbell of completion queue.
    #define COMPQUEUEDB(ID, STRIDE) (0x1000 + (2 * (ID) + 1) * (STRIDE))

    struct nvmecaps {
        uint16_t maxqueueentries;
        uint8_t cqr     : 1;    // Contiguous queues required.
        uint8_t ams     : 2;    // Arbitration mechanism is supported.
        uint8_t rsvd0   : 5;
        uint8_t to;             // Timeout.
        uint8_t stride;         // Stride used when calculating doorbell offsets.
        uint8_t nssrs   : 1;    // Subsystem reset supported.
        uint8_t css     : 7;    // Command sets are supported.
        uint8_t rsvd1   : 3;
        uint8_t mpsmin  : 4;    // Minimum memory page size.
        uint8_t mpsmax  : 4;    // Maximum memory page size.
        uint8_t pmrs    : 1;    // Persistent memory region is supported.
        uint8_t cmbs    : 1;    // Controller memory buffer is supported.
        uint8_t rsvd2   : 6;
    } __attribute__((packed));

    struct nvmecc { // Controller command.
        uint8_t rsvd0   : 1;
        uint8_t en      : 1;    // Controller enable.
        uint8_t rsvd1   : 2;
        uint8_t css     : 3;    // I/O command set.
        uint8_t mps     : 4;    // Memory page size.
        uint8_t ams     : 3;    // Arbitration shutdown mechanism selected.
        uint8_t shn     : 2;    // Shutdown notification.
        uint8_t iosqes  : 4;    // Submission queue entry size (I/O).
        uint8_t iocqes  : 4;    // Completion queue entry size (I/O).
        uint8_t rsvd2;
    } __attribute__((packed));

    struct nvmecsts { // Controller status.
        uint8_t ready   : 1;    // Is the controller ready yet?
        uint8_t cfs     : 1;    // Fatal status.
        uint8_t shst    : 2;    // Shutdown status.
        uint8_t nssro   : 1;    // Subsystem reset occurred.
        uint8_t pp      : 1;    // Processing paused.
        uint32_t rsvd0  : 26;
    } __attribute__((packed));

    struct nvmeaqa { // Admin queue attributes.
        uint16_t asqs;          // Submission queue size.
        uint16_t rsvd0;
        uint16_t acqs;          // Completion queue size.
        uint16_t rsvd1;
    } __attribute__((packed));

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
            uint64_t prp1;
            struct {
                uint64_t addr;
                uint32_t len;
                uint32_t key;
            } sgl1;
        };
        union {
            uint64_t prp2;
            struct {
                uint64_t addr;
                uint32_t len;
                uint32_t key;
            } sgl2;
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
        uint8_t p       : 1;        // Command phase.
        uint8_t sc      : 8;        // Command status code.
        uint8_t sct     : 3;        // Command status code type.
        uint8_t rsvd1   : 2;
        uint8_t m       : 1;        // More?
        uint8_t dnr     : 1;        // Do-Not-Retry
    } __attribute__((packed));

    struct nvmeid { // Controller identification command result.
        uint16_t vendor;            // Vendor.
        uint16_t ssvendor;          // Subsystem vendor.
        char serialnumber[20];      // Serial number.
        char modelnumber[40];       // Model number.
        char fwrev[8];              // Firmware revision.
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
        uint32_t rsvd0[12];
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
        uint8_t tnvmcap[16];        // Total NVM capacity.
        uint8_t unvmcap[16];        // Unallocated NVM capacity.
        uint32_t rpmbs;             // RPMB support.
        uint16_t edstt;             // Extended device self-test time.
        uint8_t dsto;               // Self-test options.
        uint8_t fwug;               // Firmware update granuality.
        uint16_t kas;               // Keep-alive support.
        uint16_t hosttattr;         // Host thermal management attributes.
        uint16_t mitmtemp;          // Minimum thermal management temperature.
        uint16_t mxtmtemp;          // Maximum thermal management temperature.
        uint32_t sanicap;           // Sanitisation capabilities.
        uint32_t rsvd2[180];
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
        uint64_t nssize;            // Namespace size.
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

    class NVMEDriver : public DevDriver {
        private:
        public:
            NVMEDriver(void) {
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

                struct nvmebar *nvmbar = (struct nvmebar *)bar.base;

                NUtil::printf("Controller is version %x.\n", nvmbar->version);
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
