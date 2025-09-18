
#ifdef __x86_64__
#include <arch/x86_64/acpi.hpp>
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
