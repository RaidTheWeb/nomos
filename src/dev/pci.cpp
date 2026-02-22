
#ifdef __x86_64__
#include <arch/x86_64/acpi.hpp>
#include <arch/x86_64/apic.hpp>
#include <arch/x86_64/cpu.hpp>
#include <arch/x86_64/smp.hpp>
#include <arch/x86_64/vmm.hpp>
#include <arch/x86_64/io.hpp>
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

        bool usemcfg = false; // Set to true if MCFG table is present. XXX: Does not currently support alternative means of discovery.

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

            NUtil::printf("[dev/pci]: Discovered PCI device %04x:%04x.\n", dev.info.pci.vendor, dev.info.pci.device);

            uint16_t status = read(&dev, 0x6, 2);

            if (status & (1 << 4)) { // Has a capabilities list.
                uint8_t ptr = read(&dev, 0x34, 1); // Offset of capabilities list within PCI struct.
                while (ptr) {
                    uint8_t cap = read(&dev, ptr, 1); // Read in a capability.

                    if (cap == 0x05) { // MSI.
                        dev.info.pci.msisupport = true;
                        dev.info.pci.msioff = ptr;
                    }
                    if (cap == 0x10) { // PCIe.
                        dev.info.pci.pciesupport = true;
                        dev.info.pci.pcieoff = ptr;
                    }
                    if (cap == 0x11) { // MSI-X.
                        dev.info.pci.msixsupport = true;
                        dev.info.pci.msixoff = ptr;
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
                {
                    NLib::ScopeIRQSpinlock guard(&NArch::VMM::kspace.lock);
                    NArch::VMM::_unmaprange(&NArch::VMM::kspace, bar.base, bar.len, false);
                    NArch::VMM::kspace.vmaspace->free((void *)bar.base, bar.len);
                }
                NArch::VMM::doshootdown(NArch::VMM::SHOOTDOWN_RANGE, bar.base, bar.base + bar.len);
            }
        }

        void maskvector(struct devinfo *dev, uint8_t idx) {
            if (dev->info.pci.msixsupport) {
                uint32_t bir = read(dev, dev->info.pci.msixoff + MSIXTABLE, 4);

                uint8_t bar_idx = bir & 0x7;
                uint32_t off = bir & ~0x7;

                struct PCI::bar bar = getbar(dev, bar_idx); // MSI-X info is contained within the specified BAR.

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

                uint8_t maskoff = (ctrl & MSICTRL64) ? MSIMASKREG64 : MSIMASKREG32;
                uint32_t bits = read(dev, dev->info.pci.msioff + maskoff, 4);
                bits |= (1 << idx); // Flip bit to mask.
                write(dev, dev->info.pci.msioff + maskoff, bits, 4);
            }

            // XXX: Legacy IRQ support.
        }

        void unmaskvector(struct devinfo *dev, uint8_t idx) {
            if (dev->info.pci.msixsupport) {
                uint32_t bir = read(dev, dev->info.pci.msixoff + MSIXTABLE, 4);

                uint8_t table_idx = bir & 0x7;
                uint32_t off = bir & ~0x7;

                struct PCI::bar bar = getbar(dev, table_idx); // MSI-X info is contained within the specified BAR.

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

                uint8_t maskoff = (ctrl & MSICTRL64) ? MSIMASKREG64 : MSIMASKREG32;
                uint32_t bits = read(dev, dev->info.pci.msioff + maskoff, 4);
                bits &= ~(1 << idx); // Flip bit to unmask.
                write(dev, dev->info.pci.msioff + maskoff, bits, 4);
            }

            // XXX: Legacy IRQ support.
        }

        // Internal round-robin CPU selector for automatic IRQ distribution.
        static int nextirqcpu(void) {
            static volatile size_t rr = 0;
            return (int)(__atomic_fetch_add(&rr, 1, __ATOMIC_RELAXED) % NArch::SMP::awakecpus);
        }

        int enablevectors(struct devinfo *dev, uint8_t count, uint8_t *vectors, void (*handler)(struct NArch::Interrupts::isr *, struct NArch::CPU::context *), bool eoi) {
            // Disable migration for the duration to keep CPU::get() stable across the function.
            NArch::CPU::get()->currthread->disablemigrate();

            if (count > 32) {
                NUtil::printf("[dev/pci]: Requested vector count %u exceeds limit of 32.\n", count);
                NArch::CPU::get()->currthread->enablemigrate();
                return -1;
            }

            int result = -1;

            if (dev->info.pci.msixsupport) { // Prioritise MSI-X.
                uint16_t msixctrl = read(dev, dev->info.pci.msixoff + MSIXCTRLREG, 2);

                if (msixctrl & MSIXCTRLEN) {
                    // Disable controller if it's already enabled.
                    write(dev, dev->info.pci.msixoff + MSIXCTRLREG, msixctrl & ~MSIXCTRLEN, 2);
                }

                uint16_t size = (msixctrl & MSIXTABLESIZEMASK) + 1;

                if (count == 0 || count > size) {
                    NUtil::printf("[dev/pci]: Device does not support the requested number of MSI-X vectors.\n");
                    NArch::CPU::get()->currthread->enablemigrate();
                    return -1;
                }

                uint32_t bir = read(dev, dev->info.pci.msixoff + MSIXTABLE, 4);

                uint8_t idx = bir & 0x7;
                uint32_t off = bir & ~0x7;

                struct PCI::bar bar = getbar(dev, idx); // MSI-X info is contained within the specified BAR.

                struct msixentry *table = (struct msixentry *)(bar.base + off);

                for (size_t i = 0; i < count; i++) {
                    int cpuidx = nextirqcpu();
                    struct NArch::CPU::cpulocal *target = NArch::SMP::cpulist[cpuidx];

                    vectors[i] = NArch::Interrupts::allocvecon(target);
                    dev->info.pci.irqcpus[i] = (uint8_t)cpuidx;

                    // Register ISR handler atomically with vector allocation if provided.
                    if (handler) {
                        NArch::Interrupts::regisron(target, vectors[i], handler, eoi);
                    }

                    table[i].addrlo = NArch::APIC::lapicphy | (target->lapicid << 12);
                    table[i].addrhi = (NArch::APIC::lapicphy >> 32) & 0xffffffff;
                    table[i].data = vectors[i]; // Specify the vector.
                    table[i].vc = 0; // Begin unmasked.
                    NUtil::printf("[dev/pci]: MSI-X IRQ %u -> vec %u on CPU %u.\n", i, vectors[i], target->lapicid);
                }


                asm volatile("sfence" : : : "memory"); // Barrier to ensure commit.

                msixctrl &= ~MSIXCTRLFUNCMASK;
                msixctrl |= MSIXCTRLEN; // Enable controller.
                write(dev, dev->info.pci.msixoff + MSIXCTRLREG, msixctrl, 2);

                unmapbar(bar);

                NUtil::printf("[dev/pci]: MSI-X enabled with %u vector(s).\n", count);
                result = 0;
            } else if (dev->info.pci.msisupport) {
                // MSI: all vectors share one address register, so they must target a single CPU.
                int msicpuidx = nextirqcpu();
                struct NArch::CPU::cpulocal *msitarget = NArch::SMP::cpulist[msicpuidx];

                uint16_t msictrl = read(dev, dev->info.pci.msioff + MSICTRLREG, 2);

                uint8_t mmc = (msictrl & MSIMMMASK) >> MSIMMSHIFT;
                uint8_t maxvec = 1 << mmc;

                if (count > maxvec) {
                    NUtil::printf("[dev/pci]: Device does not support the requested number of MSI vectors.\n");
                    NArch::CPU::get()->currthread->enablemigrate();
                    return -1;
                }

                for (size_t i = 0; i < count; i++) {
                    vectors[i] = NArch::Interrupts::allocvecon(msitarget);
                    dev->info.pci.irqcpus[i] = (uint8_t)msicpuidx;

                    // Register ISR handler atomically with vector allocation if provided.
                    if (handler) {
                        NArch::Interrupts::regisron(msitarget, vectors[i], handler, eoi);
                    }
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
                        NArch::CPU::get()->currthread->enablemigrate();
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
                msiaddr.raw = 0;
                msiaddr.addr = NArch::APIC::lapicphy >> 20; // 0xFEE00000 -> 0xFEE.
                msiaddr.dest = msitarget->lapicid;
                msiaddr.hint = 0;
                msiaddr.mode = 0;

                write(dev, dev->info.pci.msioff + MSIADDRLOREG, msiaddr.raw, 4);
                if (msictrl & MSICTRL64) { // If we support 64-bit, shove the higher half of the LAPIC address here.
                    write(dev, dev->info.pci.msioff + MSIADDRHIREG, (NArch::APIC::lapicphy >> 32) & 0xffffffff, 4);
                }

                uint8_t dataoff = (msictrl & MSICTRL64) ? MSIDATAREG64 : MSIDATAREG32;
                uint16_t data = vectors[0];
                write(dev, dev->info.pci.msioff + dataoff, data, 2); // Write base vector.

                msictrl &= ~MSIMMMASK;
                msictrl |= (mmeval << MSIMMSHIFT); // Overwrite with new MME value.
                msictrl |= MSICTRLEN; // Reenable controller.
                write(dev, dev->info.pci.msioff + MSICTRLREG, msictrl, 2);
                NUtil::printf("[dev/pci]: MSI enabled with %u vector(s) on CPU %u.\n", count, msitarget->lapicid);
                result = 0;
            }

            NArch::CPU::get()->currthread->enablemigrate();

            if (result == 0) {
                dev->info.pci.irqcount = count;
            }

            if (result != 0) {
                NUtil::printf("[dev/pci]: No MSI/MSI-X support on device. Legacy IRQ not yet implemented.\n");
            }

            return result;
        }

        void disablevectors(struct devinfo *dev, uint8_t count, uint8_t *vectors) {
            if (dev->info.pci.msixsupport) {
                // Mask all vectors first.
                uint16_t msixctrl = read(dev, dev->info.pci.msixoff + MSIXCTRLREG, 2);
                msixctrl |= MSIXCTRLFUNCMASK; // Function-level mask.
                write(dev, dev->info.pci.msixoff + MSIXCTRLREG, msixctrl, 2);
            } else if (dev->info.pci.msisupport) {
                // Disable MSI controller.
                uint16_t msictrl = read(dev, dev->info.pci.msioff + MSICTRLREG, 2);
                msictrl &= ~MSICTRLEN;
                write(dev, dev->info.pci.msioff + MSICTRLREG, msictrl, 2);
            }

            // Ensure in-flight interrupts have drained before freeing vectors.
            asm volatile("mfence" : : : "memory");

            // Free all allocated vectors using the stored CPU assignments.
            NArch::CPU::get()->currthread->disablemigrate();
            for (size_t i = 0; i < count; i++) {
                if (vectors[i] != 0) {
                    struct NArch::CPU::cpulocal *target = NArch::SMP::cpulist[dev->info.pci.irqcpus[i]];
                    NArch::Interrupts::freevecon(target, vectors[i]);
                }
            }
            dev->info.pci.irqcount = 0;
            NArch::CPU::get()->currthread->enablemigrate();
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

            // Determine whether this is MMIO or IO, and whether it's a 64-bit BAR.
            bool is_mmio = !(baselo & 0x1);
            int type = (baselo >> 1) & 0x3; // for MMIO: 0=32-bit, 2=64-bit

            uint64_t bar_size = 0;
            uint32_t size_lo = 0;
            uint32_t size_hi = 0;

            if (is_mmio && type == 2) {
                // 64-bit MMIO BAR: save original high dword, probe size by writing all-ones to both dwords
                uint32_t basehi = read(dev, baroff + 4, 4);

                // Write all-ones to both low and high parts to probe size
                write(dev, baroff, ~0u, 4);
                write(dev, baroff + 4, ~0u, 4);

                size_lo = read(dev, baroff, 4);
                size_hi = read(dev, baroff + 4, 4);

                // Restore original base values
                write(dev, baroff, baselo, 4);
                write(dev, baroff + 4, basehi, 4);

                uint64_t combined = ((uint64_t)size_hi << 32) | (uint64_t)size_lo;
                bar_size = (~(combined & ~0xFULL)) + 1; // mask lower type bits then invert

                bar.mmio = true;
                // Construct the 64-bit base from saved parts
                bar.base = (baselo & 0xfffffff0) | ((uint64_t)basehi << 32);
            } else {
                // 32-bit MMIO or IO BARs
                // Acquire size by writing ~0 to the register, then reading.
                write(dev, baroff, ~0u, 4);
                size_lo = read(dev, baroff, 4);

                write(dev, baroff, baselo, 4); // Restore original value

                if (is_mmio) {
                    bar.mmio = true;
                    bar.base = baselo & 0xfffffff0;
                    bar_size = (~(size_lo & ~0xFu)) + 1;
                } else {
                    // IO BAR
                    bar.base = baselo & ~0x3u;
                    bar_size = (~(size_lo & ~0x3u)) + 1;
                }
            }

            // If MMIO, map the physical BAR into kernel virtual space and return virtual base.
            if (bar.mmio) {
                size_t len = (size_t)bar_size;
                uintptr_t virt;
                {
                    NLib::ScopeIRQSpinlock guard(&NArch::VMM::kspace.lock);
                    virt = (uintptr_t)NArch::VMM::kspace.vmaspace->alloc(len, NMem::Virt::VIRT_RW | NMem::Virt::VIRT_NX);
                    assert(NArch::VMM::_maprange(&NArch::VMM::kspace, virt, bar.base, NArch::VMM::PRESENT | NArch::VMM::NOEXEC | NArch::VMM::WRITEABLE | NArch::VMM::DISABLECACHE, len, false), "Failed to map PCI MMIO space.\n");
                }
                // Deferred shootdown after releasing lock.
                NArch::VMM::doshootdown(NArch::VMM::SHOOTDOWN_RANGE, virt, virt + len);

                bar.len = len;
                bar.base = virt; // Update BAR with virtual mapped address.
            } else {
                bar.len = (size_t)bar_size;
            }

            return bar;
        }


        void init(void) {
#ifdef __x86_64__
            if (NArch::ACPI::mcfg.initialised) {

                NUtil::printf("[dev/pci]: Using MCFG for PCI device probing.\n");

                struct acpi_mcfg_allocation *alloc = (struct acpi_mcfg_allocation *)NArch::ACPI::mcfg.start;
                while (alloc < (struct acpi_mcfg_allocation *)NArch::ACPI::mcfg.end) {


                    size_t maplen = 4096 * 8 * 32 * (alloc->end_bus - alloc->start_bus + 1);
                    uintptr_t virt;
                    {
                        NLib::ScopeIRQSpinlock guard(&NArch::VMM::kspace.lock);
                        virt = (uintptr_t)NArch::VMM::kspace.vmaspace->alloc(maplen, NMem::Virt::VIRT_RW | NMem::Virt::VIRT_NX);
                        assert(NArch::VMM::_maprange(&NArch::VMM::kspace, virt, alloc->address, NArch::VMM::PRESENT | NArch::VMM::NOEXEC | NArch::VMM::WRITEABLE | NArch::VMM::DISABLECACHE, maplen, false), "Failed to map PCI MMIO space.\n");
                    }
                    NUtil::printf("[dev/pci]: Discovered ECAM space at %p for bus range %d-%d.\n", alloc->address, alloc->start_bus, alloc->end_bus);
                    // Deferred shootdown after releasing lock.
                    NArch::VMM::doshootdown(NArch::VMM::SHOOTDOWN_RANGE, virt, virt + maplen);

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
            // Fall back to legacy PCI config access through I/O ports (0xCF8/0xCFC)
            {
                uint32_t addr = 0x80000000u |
                    ((uint32_t)dev->info.pci.bus << 16) |
                    ((uint32_t)dev->info.pci.slot << 11) |
                    ((uint32_t)dev->info.pci.func << 8) |
                    (off & 0xfc);

                NArch::outl(0xcf8, addr);

                uint16_t port = 0xcfc + (off & 0x3);
                switch (size) {
                    case 1:
                        return NArch::inb(port);
                    case 2:
                        return NArch::inw(port);
                    case 4:
                        return NArch::inl(port);
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
                                break;
                            case 2:
                                *(uint16_t *)virt = val;
                                break;
                            case 4:
                                *(uint32_t *)virt = val;
                                break;
                        }

                        return;
                    }

                    it.next();
                }
            }
            // Legacy PCI config access via IO ports
            {
                uint32_t addr = 0x80000000u |
                    ((uint32_t)dev->info.pci.bus << 16) |
                    ((uint32_t)dev->info.pci.slot << 11) |
                    ((uint32_t)dev->info.pci.func << 8) |
                    (off & 0xfc);

                NArch::outl(0xcf8, addr);

                uint16_t port = 0xcfc + (off & 0x3);
                switch (size) {
                    case 1:
                        NArch::outb(port, (uint8_t)val);
                        break;
                    case 2:
                        NArch::outw(port, (uint16_t)val);
                        break;
                    case 4:
                        NArch::outl(port, (uint32_t)val);
                        break;
                }
            }
        }
    }
}
