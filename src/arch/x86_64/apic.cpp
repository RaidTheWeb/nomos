#include <arch/x86_64/acpi.hpp>
#include <arch/x86_64/apic.hpp>
#include <arch/x86_64/cpu.hpp>
#include <arch/x86_64/interrupts.hpp>
#include <arch/x86_64/io.hpp>
#include <arch/x86_64/vmm.hpp>
#include <lib/assert.hpp>
#include <mm/slab.hpp>

namespace NArch {
    namespace APIC {
        IoApic *ioapics = NULL;
        static size_t numioapic;
        uintptr_t lapicaddr = 0;

        void setirq(uint8_t irq, uint8_t vec, bool mask, uint8_t proc) {
            size_t i = 0;
            struct acpi_madt_interrupt_source_override *entry = (struct acpi_madt_interrupt_source_override *)ACPI::getentry(&ACPI::madt, ACPI_MADT_ENTRY_TYPE_INTERRUPT_SOURCE_OVERRIDE, 0);

            // Intel IOAPIC Datasheet:
            uint8_t polarity = 0b01; // Active low (0b00 is active high).
            uint8_t trigger = 0b00; // Edge triggered (0b01 is level triggered).
            while (entry != NULL) { // As long as there are entries to find:

                if (entry->source == irq) { // If this override maps for the IRQ we're trying to set.
                    NUtil::printf("[apic]: IRQ%lu provides an interrupt source override.\n", irq);
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

        void lapicinit(void) {
            // Mask entire local vector table.
            writelapic(LAPICLVTTS, 1 << 16);
            writelapic(LAPICLVTPMC, 1 << 16);
            writelapic(LAPICLVTINT0, 1 << 16);
            writelapic(LAPICLVTINT1, 1 << 16);
            writelapic(LAPICLVTERR, 1 << 16);
            writelapic(LAPICLVTT, 1 << 16);

            // Enable interrupt on the LAPIC.
            writelapic(LAPICSIV, readlapic(LAPICSIV) | 0x100);

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
                    // XXX: Initialise NMI interrupt handler (in accordance with the datasheet).

                    // Allocated Vector | NMI Delivery Mode | Flags (polarity and trigger mode).
                    writelapic(reg, (isr->id & 0xff) | (0b100 << 8) | entry->flags << 12);
                }

                entry = (struct acpi_madt_lapic_nmi *)ACPI::getentry(&ACPI::madt, ACPI_MADT_ENTRY_TYPE_LAPIC_NMI, ++i);
            }

            NUtil::printf("[apic]: LAPIC initialisation completed on CPU%lu.\n", cpuid);
        }

        void setup(void) {

            numioapic = ACPI::countentries(&ACPI::madt, ACPI_MADT_ENTRY_TYPE_IOAPIC);

            // Address where LAPIC registers are mapped into memory (since this is per-processor, it'll end up being mapped for the current unit).
            lapicaddr = CPU::rdmsr(0x1b) & 0xfffff000; // Read in LAPIC base address.
            NUtil::printf("[acpi]: 32-bit LAPIC address: %p.\n", lapicaddr);

            // Obtain address override (if it exists).
            struct acpi_madt_lapic_address_override *addroverride = (struct acpi_madt_lapic_address_override *)ACPI::getentry(&ACPI::madt, ACPI_MADT_ENTRY_TYPE_LAPIC_ADDRESS_OVERRIDE, 0);
            if (addroverride != NULL) {
                lapicaddr = addroverride->address; // If the ACPI tables specify an override for the base address, we should use it instead.
            }

            // Memory map whatever address we're going to be using, or else it won't let us!
            assert(VMM::mappage(&VMM::kspace, lapicaddr, lapicaddr, VMM::PRESENT | VMM::WRITEABLE | VMM::NOEXEC, false), "Failed to memory map LAPIC base address.\n");

            ioapics = new IoApic[numioapic];
            assert(ioapics, "Failed to allocate memory for IOAPIC list.\n");

            for (size_t i = 0; i < numioapic; i++) {
                struct acpi_madt_ioapic *ioapic = (struct acpi_madt_ioapic *)ACPI::getentry(&ACPI::madt, ACPI_MADT_ENTRY_TYPE_IOAPIC, i);

                ioapics[i].addr = (void *)(uintptr_t)ioapic->address;
                assert(VMM::mappage(&VMM::kspace,
                    (uintptr_t)ioapics[i].addr, (uintptr_t)ioapics[i].addr,
                    VMM::PRESENT | VMM::WRITEABLE | VMM::NOEXEC, false
                ), "Failed to memory map IOAPIC base address.\n");

                ioapics[i].gsibase = ioapic->gsi_base;
                ioapics[i].gsitop = ioapic->gsi_base + ((ioapics[i].read(IoApic::IOAPICVER) >> 16) & 0xff) + 1;

                ioapics[i].maskall(); // Mask the entire redirection table.
                NUtil::printf("[apic]: Masked redirection table in IOAPIC %lu.\n", ioapic->id);
            }

            NUtil::printf("[apic]: APIC initialised.\n");
        }
    }
}
