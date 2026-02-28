#ifndef _DEV__DRIVERS__ATA__DEFS_HPP
#define _DEV__DRIVERS__ATA__DEFS_HPP

#include <dev/dev.hpp>
#include <dev/pci.hpp>

#include <sched/event.hpp>
#include <sched/workqueue.hpp>
#include <stddef.h>
#include <stdint.h>

namespace NDev {

    // BAR5 registers.

    static constexpr uint32_t REGCAP = 0x00; // Host capability.
    static constexpr uint32_t REGGHCR = 0x04; // Global host control
    static constexpr uint32_t REGIS = 0x08; // Interrupt status.
    static constexpr uint32_t REGPI = 0x0c; // Ports implemented.
    static constexpr uint32_t REGVS = 0x10; // Version.
    static constexpr uint32_t REGCAP2 = 0x24; // Host capability 2.

    // Port registers.

    static constexpr uint32_t PORTREGCLB = 0x00; // Command list base address.
    static constexpr uint32_t PORTREGCLBU = 0x04; // Upper 32 bits of CLB.
    static constexpr uint32_t PORTREGBFB = 0x08; // FIS base address.
    static constexpr uint32_t PORTREGBFBU = 0x0c; // Upper 32 bits of BFB.
    static constexpr uint32_t PORTREGIS = 0x10; // Interrupt status.
    static constexpr uint32_t PORTREGIE = 0x14; // Interrupt enable.
    static constexpr uint32_t PORTREGCMD = 0x18; // Command and status.
    static constexpr uint32_t PORTREGTFD = 0x20; // Task file data.
    static constexpr uint32_t PORTREGSIG = 0x24; // Signature.
    static constexpr uint32_t PORTREGSSTS = 0x28; // SATA status (SCR0).
    static constexpr uint32_t PORTREGSCTL = 0x2c; // SATA control (SCR2).
    static constexpr uint32_t PORTREGSERR = 0x30; // SATA error (SCR1).
    static constexpr uint32_t PORTREGSACT = 0x34; // SATA active (SCR3).
    static constexpr uint32_t PORTREGCI = 0x38; // Command issue.


    #define PORTREG(portnum, reg) (0x100 + (portnum) * 0x80 + (reg)) // Port registers start at offset 0x100, and each port's registers are spaced 0x80 apart.


    static constexpr uint32_t AHCIGHC_AE = (1 << 31); // AHCI Enable/Disable.
    static constexpr uint32_t AHCIGHC_IE = (1 << 1); // Global interrupt enable.
    static constexpr uint32_t AHCIGHC_HR = (1 << 0); // HBA reset.

    static constexpr uint32_t AHCICAP_S64 = (1 << 31); // Supports 64-bit addressing.
    static constexpr uint32_t AHCICAP_NCQ = (1 << 30); // Supports NCQ.
    static constexpr uint32_t AHCICAP_NCS = (0x1f << 8); // Number of command slotsiiiii.
    static constexpr uint32_t AHCICAP_NCSS = 8;

    static constexpr uint32_t AHCIPCMD_ST = (1 << 0); // Start.
    static constexpr uint32_t AHCIPCMD_FRE = (1 << 4); // FIS receive enable.
    static constexpr uint32_t AHCIPCMD_FR = (1 << 14); // FIS receive running.
    static constexpr uint32_t AHCIPCMD_CR = (1 << 15); // Command list running.

    static constexpr uint32_t AHCIPIS_DHRS = (1 << 0); // Device to host register FIS interrupt.
    static constexpr uint32_t AHCIPIS_PSS = (1 << 1); // PIO setup FIS interrupt.
    static constexpr uint32_t AHCIPIS_DSS = (1 << 2); // DMA setup FIS interrupt.
    static constexpr uint32_t AHCIPIS_SDBS = (1 << 3); // Set device bits FIS interrupt (needed for NCQ).
    static constexpr uint32_t AHCIPIS_TFES = (1 << 30); // Task file error status (an error occurred during command processing).

    static constexpr uint32_t AHCITFD_SRBSY = (1 << 7);
    static constexpr uint32_t AHCITFD_SRDRQ = (1 << 3);
    static constexpr uint32_t AHCITFD_SERR = (1 << 0);

    // ATA command codes.

    static constexpr uint8_t ATACMD_READDMAEXT = 0x25;
    static constexpr uint8_t ATACMD_WRITEDMAEXT = 0x35;
    static constexpr uint8_t ATACMD_PACKET = 0xa0; // ATAPI PACKET (SCSI commands).
    static constexpr uint8_t ATACMD_IDENTIFYPACKET = 0xa1;
    static constexpr uint8_t ATACMD_FLUSHCACHE = 0xea;
    static constexpr uint8_t ATACMD_IDENTIFY = 0xec;
    static constexpr uint8_t ATACMD_SETFEATURES = 0xef;

    // SCSI command codes for ATAPI devices (sent via ATACMD_PACKET).

    static constexpr uint8_t SCSICMD_TESTUNITREADY = 0x00;
    static constexpr uint8_t SCSICMD_INQUIRY = 0x12;
    static constexpr uint8_t SCSICMD_READCAPACITY = 0x25;
    static constexpr uint8_t SCSICMD_READ10 = 0x28;
    static constexpr uint8_t SCSICMD_WRITE10 = 0x2a;

    static constexpr uint8_t FISTYPE_H2D = 0x27; // Host to device FIS.

    static constexpr uint8_t FISDEVLBA = (1 << 6); // If this bit is set in a FIS, the LBA fields are valid.


    static constexpr size_t MAXSLOTS = 32; // Maximum number of command slots, as per AHCI spec.
    static constexpr size_t MAXPORTS = 32;
    static constexpr size_t MAXCTRLS = 8;

    static constexpr size_t PRDTMAX = 64; // Maximum number of PRD entries in a command table to accommodate scatter-gather for multi-page DMA transfers.

    struct ahciprdte {
        uint32_t dba; // Data base address (lower 32 bits).
        uint32_t dbau; // Data base address (upper 32 bits).
        uint32_t rsvd0;
        uint32_t dbc : 22; // Byte count.
        uint32_t rsvd1 : 9;
        uint32_t i : 1; // Interrupt on completion.
    } __attribute__((packed));

    struct ahcicmdtable {
        uint8_t cfis[64]; // Command FIS.
        uint8_t acmd[16]; // ATAPI command, if this is an ATAPI command.
        uint8_t rsvd[48];
        struct ahciprdte prdt[PRDTMAX];
    } __attribute__((packed));

    // AHCI command header.
    struct ahcicmdhdr {
        uint16_t cfl : 5; // Command length.
        uint16_t a : 1; // Is ATAPI?
        uint16_t w : 1; // Is this host-to-device?
        uint16_t p : 1; // Prefetchable?
        uint16_t r : 1; // Reset.
        uint16_t b : 1; // BIST.
        uint16_t c : 1; // Clear busy upon R_OK.
        uint16_t rsvd0 : 1;
        uint16_t pmp : 4; // Port multiplier port.
        uint16_t prdtl; // PRDT length (in entries).
        volatile uint32_t prdbc; // PRD byte count transferred.
        uint32_t ctba; // Command table descriptor base address lower.
        uint32_t ctbau; // Command table descriptor base address upper.
        uint32_t rsvd1[4];
    } __attribute__((packed));

    // Host to device FIS structure.
    struct atah2d {
        uint8_t type;
        uint8_t pmport : 4;
        uint8_t rsvd0 : 3;
        uint8_t c : 1; // Command bit (0 for data FIS, 1 for command FIS).
        uint8_t cmd;
        uint8_t featurel;

        uint8_t lba0;
        uint8_t lba1;
        uint8_t lba2;
        uint8_t device;

        uint8_t lba3;
        uint8_t lba4;
        uint8_t lba5;
        uint8_t featureh;

        uint16_t count;
        uint8_t icc;
        uint8_t control;

        uint8_t rsvd1[4];
    } __attribute__((packed));

    struct ataid {
        uint16_t cfg;
        uint16_t rsvd0[9];
        uint8_t serial[20];
        uint16_t rsvd1[3];
        uint8_t fwrev[8];
        uint8_t model[40];
        uint16_t rsvd2[29];
        uint16_t capabilities;
        uint16_t rsvd3[9];
        uint16_t fieldvalid;
        uint16_t rsvd4[5];
        uint16_t multisect;
        uint32_t lba28sectors;
        uint16_t rsvd5[2];
        uint16_t dmaword;
        uint16_t rsvd6[5];
        uint16_t majver;
        uint16_t minver;
        uint16_t cmdset1;
        uint16_t cmdset2;
        uint16_t rsvd7[4];
        uint16_t udma;
        uint16_t rsvd8[11];
        uint64_t lba48sectors;
        uint16_t rsvd9[2];
        uint16_t secsize;
        uint16_t rsvd10[10];
        uint32_t logsecsize;
        uint16_t rsvd11[129];
    } __attribute__((packed));


    static constexpr uint16_t ATAID_LBA48 = (1 << 10); // If this bit is set in the identify data, the device supports 48-bit LBA and the sector count and LBA fields are interpreted differently.
    static constexpr uint16_t ATAID_LBA = (1 << 9); // If this bit is set in the identify data, the device supports LBA (as opposed to CHS) addressing.


    class BlockDevice; // Forward declaration for device tracking.

    struct ahciport; // Forward declaration; ahcipending needs a backpointer.

    struct ahcipending {
        NSched::WaitQueue wq; // Wait queue for this pending operation.

        volatile bool done; // Is the operation done? Accessed atomically.
        volatile int status; // Status code. Written by ISR, read after done=true.
        volatile bool inuse; // Are we using this slot? Accessed atomically.
        volatile bool issued; // Has the command been issued to hardware? Set after CI write, cleared by ISR after processing.
        volatile uint64_t submittsc; // TSC timestamp when submitted, for timeout detection.

        struct ahciport *port = NULL; // Backpointer to owning port (set by allocslot). Used by timeout paths to coordinate with ISR via portlock.

        void (*callback)(struct ahcipending *) = NULL; // Optional callback function for async completions.
        void *udata = NULL; // User data pointer for the callback.

        struct NSched::work work; // Work item for async completions.
        struct bioreq *bio = NULL; // Associated block I/O request, if any.
    };

    struct ahciport {
        enum type {
            NONE,
            ATA,
            ATAPI
        };

        enum type type;

        bool initialised;
        uint8_t num;

        // DMA buffers.
        uintptr_t clphys; // Command list.
        uintptr_t fbphys; // FIS receive buffer.
        uintptr_t ctphys; // Command tables.

        // Mapped DMA.
        struct ahcicmdhdr *cmdlist; // Command list.
        struct ahcicmdtable *cmdtables; // Command tables.

        char model[41];
        uint64_t numsectors;
        uint32_t sectorsize;

        NArch::IRQSpinlock portlock;
        NSched::WaitQueue slotavailwq; // Signalled when a command slot becomes free.

        struct ahcipending pendings[MAXSLOTS]; // One pending slot per command slot.

        // Device tracking for teardown.
        static constexpr size_t MAXPARTS = 16;
        BlockDevice *blkdev;
        char devname[32];
        BlockDevice *partdevs[MAXPARTS];
        char partnames[MAXPARTS][32];
        size_t numparts;
    };


    struct ahcictrl {
        struct devinfo info;
        struct PCI::bar pcibar;

        uint32_t portimpl;
        uint32_t nslots;
        bool supports64bit;

        struct ahciport ports[MAXPORTS];
        size_t portcount;

        volatile bool initialised;
        uint32_t num; // Controller number.

        volatile bool dead;
        uint8_t vec;
    };

    static inline uint64_t read64(struct PCI::bar *bar, uint32_t reg) {
        return *((volatile uint64_t *)(bar->base + reg));
    }

    static inline void write64(struct PCI::bar *bar, uint32_t reg, uint64_t val) {
        *((volatile uint64_t *)(bar->base + reg)) = val;
    }

    static inline uint32_t read32(struct PCI::bar *bar, uint32_t reg) {
        return *((volatile uint32_t *)(bar->base + reg));
    }

    static inline void write32(struct PCI::bar *bar, uint32_t reg, uint32_t val) {
        *((volatile uint32_t *)(bar->base + reg)) = val;
    }

}

#endif