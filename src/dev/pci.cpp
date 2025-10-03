
#ifdef __x86_64__
#include <arch/x86_64/acpi.hpp>
#include <arch/x86_64/apic.hpp>
#include <arch/x86_64/cpu.hpp>
#include <arch/x86_64/vmm.hpp>
#endif

#include <dev/dev.hpp>
#include <dev/pci.hpp>

namespace NDev {

    namespace PCI {
        struct mcfgrange {
            uintptr_t base; // Base for any operation.

            uint16_t seg;

            uint8_t start; // Start of range.
            uint8_t end; // End of range.
        };

        NLib::SingleList<struct mcfgrange> ranges;

        bool usemcfg = false;

        void scanbus(uint8_t bus);

        void scanfunc(uint8_t bus, uint8_t slot, uint8_t func) {
            struct devinfo dev = { };
            dev.type = devinfo::PCI;
            dev.info.pci.seg = 0;
            dev.info.pci.bus = bus;
            dev.info.pci.slot = slot;
            dev.info.pci.func = func;

            uint32_t devvendor = read(&dev, 0, 4); // Register 0.

            dev.info.pci.device = (devvendor >> 16) & 0xffff;
            dev.info.pci.vendor = devvendor & 0xffff;


            uint32_t info = read(&dev, 0x8, 4); // Register 2.

            dev.info.pci.pcirev = info & 0xff;
            dev.info.pci.pciprogif = (info >> 8) & 0xff;
            dev.info.pci.pcisubclass = (info >> 16) & 0xff;
            dev.info.pci.pciclass = (info >> 24) & 0xff;

            if (dev.info.pci.pciclass == 6 && dev.info.pci.pcisubclass == 4) { // PCI-PCI Bridge.
                uint32_t reg6 = read(&dev, 0x18, 4); // Register 6, contains secondary bus number.
                scanbus((reg6 >> 8) & 0xff); // Scan this entire bus as well.
            }

            NUtil::printf("[dev/pci]: Discovered PCI device %04x:%04x\n", dev.info.pci.vendor, dev.info.pci.device);

            uint16_t status = read(&dev, 0x6, 2);

            if (status & (1 << 4)) { // Has a capabilities list.
                uint8_t ptr = read(&dev, 0x34, 1); // Offset of capabilities list within PCI struct.
                while (ptr) {
                    uint8_t cap = read(&dev, ptr, 1); // Read in a capability.

                    if (cap == 0x05) { // MSI.
                        dev.info.pci.msisupport = true;
                        dev.info.pci.msioff = ptr;
                        break;
                    } else if (cap == 0x10) { // PCIe.
                        dev.info.pci.pciesupport = true;
                        dev.info.pci.pcieoff = ptr;
                        break;
                    } else if (cap == 0x11) { // MSI-X.
                        dev.info.pci.msixsupport = true;
                        dev.info.pci.msixoff = ptr;
                        break;
                    }

                    ptr = read(&dev, ptr + 1, 1);
                }

            }

            for (struct regentry *entry = (NDev::regentry *)__drivers_start; (uintptr_t)entry < (uintptr_t)__drivers_end; entry++) {
                if (entry->magic == NDev::MAGIC && entry->info->type == reginfo::PCI) {

                    uint8_t flags = entry->info->match.pci.flags;

                    if (flags & PCI_MATCHDEVICE) {
                        if (entry->info->match.pci.vendor != dev.info.pci.vendor) {
                            continue;
                        }

                        bool match = false;
                        for (size_t i = 0; i < entry->info->match.pci.devcount; i++) {
                            uint16_t device = entry->info->match.pci.devices[i];
                            if (dev.info.pci.device == device) {
                                match = true;
                            }
                        }

                        if (!match) {
                            continue;
                        }

                        entry->instance->probe(dev);
                    } else if (flags & PCI_MATCHVENDOR) {
                        if (entry->info->match.pci.vendor != dev.info.pci.vendor) {
                            continue;
                        }

                        entry->instance->probe(dev);
                    } else {
                        if ((flags & PCI_MATCHCLASS) && (entry->info->match.pci.pciclass != dev.info.pci.pciclass)) {
                            continue;
                        }

                        if ((flags & PCI_MATCHSUBCLASS) && (entry->info->match.pci.pcisubclass != dev.info.pci.pcisubclass)) {
                            continue;
                        }

                        if ((flags & PCI_MATCHPROGIF) && (entry->info->match.pci.pciprogif != dev.info.pci.pciprogif)) {
                            continue;
                        }

                        entry->instance->probe(dev);
                    }

                }
            }
        }

        void scanslot(uint8_t bus, uint8_t slot) {
            uint8_t func = 0;

            struct devinfo dev = {  };
            dev.type = devinfo::PCI;
            dev.info.pci.seg = 0;
            dev.info.pci.bus = bus;
            dev.info.pci.slot = slot;
            dev.info.pci.func = func;

            uint16_t vendor = read(&dev, 0, 2);
            if (vendor == 0xffff) {
                return; // No device in this slot.
            }

            scanfunc(bus, slot, func);

            if (read(&dev, 0xc, 4) & 0x800000) { // Multifunction.

                for (size_t i = 1; i < 8; i++) {
                    dev.info.pci.func = i;
                    if (read(&dev, 0, 2) != 0xffff) {
                        scanfunc(bus, slot, i);
                    }
                }
            }
        }

        void scanbus(uint8_t bus) {
            for (size_t i = 0; i < 32; i++) { // For every device slot:
                scanslot(bus, i);
            }
        }

        void scanroot(void) {
            struct devinfo root = { };
            root.type = devinfo::PCI;
            root.info.pci.seg = 0;
            root.info.pci.bus = 0;
            root.info.pci.slot = 0;
            root.info.pci.func = 0;

            if (!(read(&root, 0xc, 4) & 0x800000)) { // Single bus only.
                scanbus(0);
            } else {
                for (size_t i = 0; i < 8; i++) { // Scan all other buses.
                    root.info.pci.func = i;

                    if (read(&root, 0, 2) == 0xffff) { // Vendor ID full of 0xffff signifies end.
                        break;
                    }

                    scanbus(i);
                }
            }
        }

        void unmapbar(struct bar bar) {
            if (bar.mmio) { // Only unmap MMIO BARs.
                NLib::ScopeSpinlock guard(&NArch::VMM::kspace.lock);
                NArch::VMM::_unmaprange(&NArch::VMM::kspace, bar.base, bar.len);
                NArch::VMM::kspace.vmaspace->free((void *)bar.base, bar.len);
            }
        }

        void maskvector(struct devinfo *dev, uint8_t idx) {
            if (dev->info.pci.msixsupport) {
                uint32_t bir = read(dev, dev->info.pci.msixoff + MSIXTABLE, 4);

                uint8_t idx = bir & 0x7;
                uint32_t off = bir & ~0x7;

                struct PCI::bar bar = getbar(dev, idx); // MSI-X info is contained within the specified BAR.

                struct msixentry *table = (struct msixentry *)(bar.base + off);
                table[idx].vc |= (1 << 0); // Flip mask bit to mask.

                asm volatile("sfence" : : : "memory"); // Barrier to ensure write.
                unmapbar(bar);
            } else if (dev->info.pci.msisupport) {
                uint16_t ctrl = read(dev, dev->info.pci.msioff + MSICTRLREG, 2);

                if (!(ctrl & MSICTRLMASK)) {
                    NUtil::printf("[dev/pci]: Device does not support MSI masking.\n");
                    return;
                }

                uint32_t bits = read(dev, dev->info.pci.msioff + MSIMASKREG, 4);
                bits |= (1 << idx); // Flip bit to mask.
                write(dev, dev->info.pci.msioff + MSIMASKREG, bits, 4);
            }

            // XXX: Legacy IRQ support.
        }

        void unmaskvector(struct devinfo *dev, uint8_t idx) {
            if (dev->info.pci.msixsupport) {
                uint32_t bir = read(dev, dev->info.pci.msixoff + MSIXTABLE, 4);

                uint8_t idx = bir & 0x7;
                uint32_t off = bir & ~0x7;

                struct PCI::bar bar = getbar(dev, idx); // MSI-X info is contained within the specified BAR.

                struct msixentry *table = (struct msixentry *)(bar.base + off);
                table[idx].vc &= ~(1 << 0); // Flip mask bit to unmask.

                asm volatile("sfence" : : : "memory"); // Barrier to ensure write.
                unmapbar(bar);
            } else if (dev->info.pci.msisupport) {
                uint16_t ctrl = read(dev, dev->info.pci.msioff + MSICTRLREG, 2);

                if (!(ctrl & MSICTRLMASK)) {
                    NUtil::printf("[dev/pci]: Device does not support MSI masking.\n");
                    return;
                }

                uint32_t bits = read(dev, dev->info.pci.msioff + MSIMASKREG, 4);
                bits &= ~(1 << idx); // Flip bit to unmask.
                write(dev, dev->info.pci.msioff + MSIMASKREG, bits, 4);
            }

            // XXX: Legacy IRQ support.
        }

        int enablevectors(struct devinfo *dev, uint8_t count, uint8_t *vectors) {
            if (dev->info.pci.msixsupport) { // Prioritise MSI-X.
                uint16_t msixctrl = read(dev, dev->info.pci.msixoff + MSIXCTRLREG, 2);

                if (msixctrl & MSIXCTRLEN) {
                    // Disable controller if it's already enabled.
                    write(dev, dev->info.pci.msixoff + MSIXCTRLREG, msixctrl & ~MSIXCTRLEN, 2);
                }

                uint16_t size = (msixctrl & MSIXTABLESIZEMASK) + 1;

                if (count == 0 || count > size) {
                    NUtil::printf("[dev/pci]: Device does not support the requested number of MSI-X vectors.\n");
                    return -1;
                }

                uint32_t bir = read(dev, dev->info.pci.msixoff + MSIXTABLE, 4);

                uint8_t idx = bir & 0x7;
                uint32_t off = bir & ~0x7;
                NUtil::printf("Table is on BAR%u at %p.\n", idx, off);

                struct PCI::bar bar = getbar(dev, idx); // MSI-X info is contained within the specified BAR.

                struct msixentry *table = (struct msixentry *)(bar.base + off);

                for (size_t i = 0; i < count; i++) {
                    vectors[i] = NArch::Interrupts::allocvec();

                    table[i].addrlo = NArch::APIC::lapicphy | (NArch::CPU::get()->lapicid << 12);
                    table[i].addrhi = (NArch::APIC::lapicphy >> 32) & 0xffffffff;
                    table[i].data = vectors[i]; // Specify the vector.
                    table[i].vc = 0; // Begin unmasked.
                    NUtil::printf("[dev/pci]: Sending MSI-X IRQ %u to %u at %p.\n", i, vectors[i], table[i].addrlo);
                }


                asm volatile("sfence" : : : "memory"); // Barrier to ensure commit.

                msixctrl &= ~MSIXCTRLFUNCMASK;
                msixctrl |= MSIXCTRLEN; // Enable controller.
                write(dev, dev->info.pci.msixoff + MSIXCTRLREG, msixctrl, 2);

                unmapbar(bar);

                NUtil::printf("[dev/pci]: MSI-X enabled with vectors %u to %u.\n", vectors[0], vectors[0] + count - 1);
                return 0;
            } else if (dev->info.pci.msisupport) {
                uint16_t msictrl = read(dev, dev->info.pci.msioff + MSICTRLREG, 2);

                uint8_t mmc = (msictrl & MSIMMMASK) >> MSIMMSHIFT;
                uint8_t maxvec = 1 << mmc;

                if (count > maxvec) {
                    NUtil::printf("[dev/pci]: Device does not support the requested number of MSI vectors.\n");
                    return -1;
                }

                for (size_t i = 0; i < count; i++) {
                    vectors[i] = NArch::Interrupts::allocvec();
                }

                uint8_t mmeval = 0;
                switch (count) {
                    case 1:
                        mmeval = 0;
                        break;
                    case 2:
                        mmeval = 1;
                        break;
                    case 4:
                        mmeval = 2;
                        break;
                    case 8:
                        mmeval = 3;
                        break;
                    case 16:
                        mmeval = 4;
                        break;
                    case 32:
                        mmeval = 5;
                        break;
                    default:
                        return -1;
                }

                msictrl &= ~MSICTRLEN; // Disable controller.
                write(dev, dev->info.pci.msioff + MSICTRLREG, msictrl, 2);

                union {
                    struct {
                        uint32_t rsvd0 : 2;
                        uint32_t mode : 1;
                        uint32_t hint : 1;
                        uint32_t rsvd1 : 8;
                        uint32_t dest : 8;
                        uint32_t addr : 12;
                    };
                    uint32_t raw;
                } msiaddr;
                msiaddr.addr = NArch::APIC::lapicphy;
                msiaddr.dest = 0; // Target CPU0.
                msiaddr.hint = 0;
                msiaddr.mode = 0;

                write(dev, dev->info.pci.msioff + MSIADDRLOREG, msiaddr.raw, 4);
                if (msictrl & MSICTRL64) { // If we support 64-bit, shove the higher half of the LAPIC address here.
                    write(dev, dev->info.pci.msioff + MSIADDRHIREG, (NArch::APIC::lapicphy >> 32) & 0xffffffff, 4);
                }

                uint16_t data = vectors[0];
                write(dev, dev->info.pci.msioff + MSIDATAREG, data, 2); // Write base vector.

                msictrl &= ~MSIMMMASK;
                msictrl |= (mmeval << MSIMMSHIFT); // Overwrite with new MME value.
                msictrl |= MSICTRLEN; // Reenable controller.
                write(dev, dev->info.pci.msioff + MSICTRLREG, msictrl, 2);
                NUtil::printf("[dev/pci]: MSI enabled with vectors %u to %u.\n", vectors[0], vectors[0] + count - 1);
                return 0;
            }

            return -1; // XXX: Legacy IRQ support.
        }

        struct bar getbar(struct devinfo *dev, uint8_t idx) {
            struct bar bar = { };
            bar.base = 0;
            bar.len = 0;
            bar.mmio = false;

            if (idx > 5) { // Invalid BAR#.
                return bar;
            }

            uint16_t baroff = 0x10 + idx * sizeof(uint32_t); // Acquire offset for desired BAR.

            uint32_t baselo = read(dev, baroff, 4);

            // Acquire size by writing ~0 to the register, then reading.
            write(dev, baroff, ~0, 4);
            uint32_t sizelo = read(dev, baroff, 4);

            write(dev, baroff, baselo, 4); // Write original value of base to register (restore).

            if (!(baselo & (1 << 0))) { // If the first bit is zero, this is an MMIO bar.
                bar.mmio = true;

                int type = (baselo >> 1) & 0x3;

                bar.base = baselo & 0xfffffff0;
                if (type == 2) { // Type 2 is 64-bit, this means we should combine with the next BAR.
                    uint32_t basehi = read(dev, baroff + 4, 4);
                    bar.base |= ((uint64_t)basehi << 32);
                }


                bar.len = ~(sizelo & ~0b1111) + 1;
                NArch::VMM::kspace.lock.acquire();
                uintptr_t virt = (uintptr_t)NArch::VMM::kspace.vmaspace->alloc(bar.len, NMem::Virt::VIRT_RW | NMem::Virt::VIRT_NX);
                assert(NArch::VMM::_maprange(
                    &NArch::VMM::kspace, virt, bar.base,
                    NArch::VMM::PRESENT | NArch::VMM::NOEXEC | NArch::VMM::WRITEABLE, bar.len)
                , "Failed to map PCI MMIO space.\n");
                NArch::VMM::kspace.lock.release();

                bar.base = virt; // Update BAR with virtual mapped address.
            } else { // First bit is one, this is an I/O bar.
                bar.base = baselo & ~0b11; // Remove first two bits (marker and reserved).
                bar.len = ~(sizelo & ~0b11) + 1; // And add one, for actual size.
            }

            return bar;
        }


        void init(void) {
#ifdef __x86_64__
            if (NArch::ACPI::mcfg.initialised) {

                NUtil::printf("[dev/pci]: Using MCFG for PCI device probing.\n");

                struct acpi_mcfg_allocation *alloc = (struct acpi_mcfg_allocation *)NArch::ACPI::mcfg.start;
                while (alloc < (struct acpi_mcfg_allocation *)NArch::ACPI::mcfg.end) {
                    NUtil::printf("[dev/pci]: Discovered ECAM space at %p for bus range %d-%d.\n", alloc->address, alloc->start_bus, alloc->end_bus);


                    NArch::VMM::kspace.lock.acquire();
                    uintptr_t virt = (uintptr_t)NArch::VMM::kspace.vmaspace->alloc(4096 * 8 * 32 * (alloc->end_bus - alloc->start_bus + 1), NMem::Virt::VIRT_RW | NMem::Virt::VIRT_NX);
                    assert(NArch::VMM::_maprange(&NArch::VMM::kspace, virt, alloc->address, NArch::VMM::PRESENT | NArch::VMM::NOEXEC | NArch::VMM::WRITEABLE, 4096 * 8 * 32 * (alloc->end_bus - alloc->start_bus + 1)), "Failed to map PCI MMIO space.\n");
                    NArch::VMM::kspace.lock.release();

                    ranges.push((struct mcfgrange) {
                        .base = virt,
                        .seg = alloc->segment,
                        .start = alloc->start_bus,
                        .end = alloc->end_bus
                    });

                    alloc = (struct acpi_mcfg_allocation *)((uintptr_t)alloc + sizeof(struct acpi_mcfg_allocation));
                }

                usemcfg = true;
            }
#endif

            scanroot();
        }

        uint32_t read(struct devinfo *dev, uint32_t off, int size) {
            assert(dev->type == devinfo::PCI, "Attempting to perform PCI read on non-PCI device.\n");

            if (usemcfg) {
                NLib::SingleList<struct mcfgrange>::Iterator it = ranges.begin();

                while (it.valid()) {
                    struct mcfgrange *range = it.get();

                    if (
                        range->seg == dev->info.pci.seg &&
                        range->start <= dev->info.pci.bus &&
                        range->end >= dev->info.pci.bus
                    ) { // This is the correct MCFG range for the device.
                        uintptr_t virt = (((dev->info.pci.bus - range->start) << 20) | (dev->info.pci.slot << 15) | (dev->info.pci.func << 12)) + range->base + off;

                        switch (size) {
                            case 1:
                                return *(uint8_t *)virt;
                            case 2:
                                return *(uint16_t *)virt;
                            case 4:
                                return *(uint32_t *)virt;
                        }

                        return 0;
                    }

                    it.next();
                }
            }
            return 0;
        }

        void write(struct devinfo *dev, uint32_t off, uint32_t val, int size) {
            assert(dev->type == devinfo::PCI, "Attempting to perform PCI write on non-PCI device.\n");
            if (usemcfg) {
                NLib::SingleList<struct mcfgrange>::Iterator it = ranges.begin();

                while (it.valid()) {
                    struct mcfgrange *range = it.get();

                    if (
                        range->seg == dev->info.pci.seg &&
                        range->start <= dev->info.pci.bus &&
                        range->end >= dev->info.pci.bus
                    ) { // This is the correct MCFG range for the device.
                        uintptr_t virt = (((dev->info.pci.bus - range->start) << 20) | (dev->info.pci.slot << 15) | (dev->info.pci.func << 12)) + range->base + off;

                        switch (size) {
                            case 1:
                                *(uint8_t *)virt = val;
                            case 2:
                                *(uint16_t *)virt = val;
                            case 4:
                                *(uint32_t *)virt = val;
                        }

                        return;
                    }

                    it.next();
                }
            }
        }
    }
}
