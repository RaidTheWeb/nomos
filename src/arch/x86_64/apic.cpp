#include <arch/x86_64/acpi.hpp>
#include <arch/x86_64/apic.hpp>
#include <arch/x86_64/cpu.hpp>
#include <arch/x86_64/interrupts.hpp>
#include <arch/x86_64/io.hpp>
#include <arch/x86_64/tsc.hpp>
#include <arch/x86_64/vmm.hpp>
#include <lib/assert.hpp>
#include <mm/slab.hpp>

namespace NArch {
    namespace APIC {
        IoApic *ioapics = NULL;
        size_t numioapic;
        uintptr_t lapicaddr = 0;
        uintptr_t lapicphy = 0;

        void sendipi(uint8_t cpu, uint8_t vec, uint8_t delivery, uint8_t mode, uint8_t dest) {
            writelapic(LAPICICRHI, (uint32_t)cpu << 24); // Load in the target CPU.

            // Write out specifics for the IPI.
            // Assert IPI, edge triggered.
            writelapic(LAPICICRLO, vec | (delivery << 8) | (mode << 11) | (1 << 14) | (0 << 15) | (dest << 18));

            // Wait for idle.
            while (readlapic(LAPICICRLO) & (1 << 12)) {
                asm volatile("pause" : : : "memory");
            }
        }

        void setirq(uint8_t irq, uint8_t vec, bool mask, uint8_t proc) {
            size_t i = 0;
            struct acpi_madt_interrupt_source_override *entry = (struct acpi_madt_interrupt_source_override *)ACPI::getentry(&ACPI::madt, ACPI_MADT_ENTRY_TYPE_INTERRUPT_SOURCE_OVERRIDE, 0);

            // Intel IOAPIC Datasheet:
            uint8_t polarity = 0b01; // Active low (0b00 is active high).
            uint8_t trigger = 0b00; // Edge triggered (0b01 is level triggered).
            while (entry != NULL) { // As long as there are entries to find:

                if (entry->source == irq) { // If this override maps for the IRQ we're trying to set.
                    NUtil::printf("[arch/x86_64/apic]: IRQ%lu provides an interrupt source override.\n", irq);
                    polarity = entry->flags & IoApic::INTSOPOLARITY ? // Check against the second bit in the flag (second bit of the offset for this flag).
                        1 : // 0b11 is active low.
                        0; // 0b01 is Should be active high.
                    trigger = entry->flags & IoApic::INTSOTRIGGER ? // Check against fourth bit in the flag (second bit of the offset for this flag).
                        1 : // 0b11 is level triggered.
                        0; // 0b01 is edge triggered.
                    irq = entry->gsi; // Overwrite the IRQ with GSI.
                    break;
                }

                // Get next entry.
                entry = (struct acpi_madt_interrupt_source_override *)ACPI::getentry(&ACPI::madt, ACPI_MADT_ENTRY_TYPE_INTERRUPT_SOURCE_OVERRIDE, ++i);
            }

            // Work with whatever we know:

            // Iterate over the IOAPICs to find one that can handle the GSI we're using (or just normal IRQ).
            IoApic *ioapic = NULL;
            for (size_t i = 0; i < numioapic; i++) {
                // Contains the GSI/IRQ we're looking for.
                if (ioapics[i].gsibase <= irq && ioapics[i].gsitop > irq) {
                    ioapic = &ioapics[i]; // This one will do.
                }
            }

            assertarg(ioapic, "No suitable IOAPIC found for GSI %lu", irq);

            irq = irq - ioapic->gsibase; // GSI -> IRQ# translation.

            // Write redirect with fixed delivery mode, and physical destination mode.
            // proc is expected to include the mapping ACPI ID mappings for each interrupt.
            ioapic->writeredirect(irq, vec, 0, 0, polarity, trigger, mask, proc);
        }

        void eoi(void) {
            // Acknowledge the end of interrupt (is done through LAPIC, as the IOAPIC is sending the interrupt to us).
            writelapic(LAPICEOI, 0);
        }

        static void nmi(struct Interrupts::isr *isr, struct CPU::context *ctx) {
            (void)isr;
            (void)ctx;

            assert(false, "NMI Triggered.\n");
        }

        void lapictimerinit(void) {

            writelapic(LAPICDCR, 0b1011); // Divide by 1.
            writelapic(LAPICICR, 0xffffffff); // Start at theoretical maximum, immediately starts the timer countdown.

            // Wait 50000us. The idea here is that we can approximate how many ticks the LAPIC timer will tick when it runs for this time, and then we can calculate how much it SHOULD run, in the future.
            uint64_t start = TSC::query();

            uint64_t ttl = (50000 * TSC::hz) / 1000000; // Wait 50ms (arbitrary calibration delay).

            uint64_t target = start + ttl;

            while (TSC::query() < target) {
                asm volatile("pause");
            }

            uint64_t ticks = (0xffffffff - readlapic(LAPICCCR)); // How many LAPIC timer ticks elapsed?

            uint64_t perus = ticks / 50000; // Difference between initial count, and current is how long it's taken. Divide by 50000us to convert from ticks to microseconds.

            writelapic(LAPICICR, 0); // Reset initial count (disable timer).

            CPU::get()->lapicfreq = perus * 1000000;
        }

        void lapicstop(void) {
            writelapic(LAPICLVTT, 1 << 16); // Mask timer interrupt.
            writelapic(LAPICICR, 0); // Stop timer.
        }

        void lapiconeshot(uint64_t us, uint8_t vec) {
            bool intstate = CPU::get()->setint(false);
            lapicstop(); // Stop current timer (if any).

            uint64_t ticks = us * (CPU::get()->lapicfreq / 1000000); // Calculate number of ticks to wait for.

            writelapic(LAPICLVTT, vec);
            writelapic(LAPICDCR, 0b1011); // Divide by 1.
            writelapic(LAPICICR, ticks); // Start countdown. When this reaches zero, it'll trigger the interrupt passed in as `vec`.


            CPU::get()->setint(intstate); // Restore.
        }

        static void spurious(struct Interrupts::isr *isr, struct CPU::context *ctx) {
            (void)isr;
            (void)ctx;

            // Runaway IRQ:
            assert(false, "Spurious Triggered.\n");
        }

        void lapicinit(void) {
            // Mask entire local vector table.
            writelapic(LAPICLVTTS, 1 << 16);
            writelapic(LAPICLVTPMC, 1 << 16);
            writelapic(LAPICLVTINT0, 1 << 16);
            writelapic(LAPICLVTINT1, 1 << 16);
            writelapic(LAPICLVTERR, 1 << 16);
            writelapic(LAPICLVTT, 1 << 16);

            // Enable interrupt on the LAPIC.
            writelapic(LAPICSIV, readlapic(LAPICSIV) | 0x1ff);

            Interrupts::regisr(0xff, spurious, false);

            // ACPI processor UID.
            size_t cpuid = readlapic(LAPICID) >> 24; // Read processor ID from LAPIC.

            // Create an ISR to handle the NMI.
            struct Interrupts::isr *isr = Interrupts::regisr(Interrupts::allocvec(), nmi, false);

            size_t i = 0;
            struct acpi_madt_lapic_nmi *entry = (struct acpi_madt_lapic_nmi *)ACPI::getentry(&ACPI::madt, ACPI_MADT_ENTRY_TYPE_LAPIC_NMI, 0);
            while (entry != NULL) {

                // ACPI tables request that one of the LINT# registers be configured to handle NMIs.

                // If this entry specifies this APIC processor ID, or for all APICs.
                if (entry->uid == cpuid || entry->uid == 0xff) {
                    // Configure the relevant LINT

                    // Find the relevant LAPIC register.
                    uint32_t reg = 0;
                    switch (entry->lint) {
                        case 0:
                            reg = LAPICLVTINT0;
                            break;
                        case 1:
                            reg = LAPICLVTINT1;
                            break;
                    }

                    // Allocated Vector | NMI Delivery Mode | Flags (polarity and trigger mode).
                    writelapic(reg, (isr->id & 0xff) | (0b100 << 8) | (entry->flags << 12));
                }

                entry = (struct acpi_madt_lapic_nmi *)ACPI::getentry(&ACPI::madt, ACPI_MADT_ENTRY_TYPE_LAPIC_NMI, ++i);
            }

            lapictimerinit();
        }

        void setup(void) {

            numioapic = ACPI::countentries(&ACPI::madt, ACPI_MADT_ENTRY_TYPE_IOAPIC);

            // Address where LAPIC registers are mapped into memory (since this is per-processor, it'll end up being mapped for the current unit).
            lapicaddr = CPU::rdmsr(CPU::MSRAPICBASE) & 0xfffff000; // Read in LAPIC base address.
            NUtil::printf("[arch/x86_64/apic]: 32-bit LAPIC address: %p.\n", lapicaddr);

            // Obtain address override (if it exists).
            struct acpi_madt_lapic_address_override *addroverride = (struct acpi_madt_lapic_address_override *)ACPI::getentry(&ACPI::madt, ACPI_MADT_ENTRY_TYPE_LAPIC_ADDRESS_OVERRIDE, 0);
            if (addroverride != NULL) {
                lapicaddr = addroverride->address; // If the ACPI tables specify an override for the base address, we should use it instead.
                NUtil::printf("[arch/x86_64/apic]: 64-bit LAPIC address override: %p.\n", lapicaddr);
            }

            lapicphy = lapicaddr;

            // Memory map whatever address we're going to be using, or else it won't let us!
            uintptr_t virt = (uintptr_t)VMM::kspace.vmaspace->alloc(PAGESIZE, NMem::Virt::VIRT_NX | NMem::Virt::VIRT_RW);
            assert(VMM::mappage(&VMM::kspace, virt, lapicaddr, VMM::PRESENT | VMM::WRITEABLE | VMM::NOEXEC), "Failed to memory map LAPIC base address.\n");
            lapicaddr = virt;

            ioapics = new IoApic[numioapic];
            assert(ioapics, "Failed to allocate memory for IOAPIC list.\n");

            for (size_t i = 0; i < numioapic; i++) {
                struct acpi_madt_ioapic *ioapic = (struct acpi_madt_ioapic *)ACPI::getentry(&ACPI::madt, ACPI_MADT_ENTRY_TYPE_IOAPIC, i);

                ioapics[i].addr = (void *)(uintptr_t)ioapic->address;
                uintptr_t virt = (uintptr_t)VMM::kspace.vmaspace->alloc(PAGESIZE, NMem::Virt::VIRT_NX | NMem::Virt::VIRT_RW);
                assert(VMM::mappage(&VMM::kspace,
                    virt, (uintptr_t)ioapics[i].addr,
                    VMM::PRESENT | VMM::WRITEABLE | VMM::NOEXEC
                ), "Failed to memory map IOAPIC base address.\n");
                ioapics[i].addr = (void *)virt;

                ioapics[i].gsibase = ioapic->gsi_base;
                ioapics[i].gsitop = ioapic->gsi_base + ((ioapics[i].read(IoApic::IOAPICVER) >> 16) & 0xff) + 1;

                ioapics[i].maskall(); // Mask the entire redirection table.
                NUtil::printf("[arch/x86_64/apic]: Masked redirection table in IOAPIC %lu.\n", ioapic->id);
            }

            NUtil::printf("[arch/x86_64/apic]: APIC initialised.\n");
        }
    }
}
