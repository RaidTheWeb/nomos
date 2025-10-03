#ifndef _ARCH__X86_64__APIC_HPP
#define _ARCH__X86_64__APIC_HPP

#include <arch/x86_64/acpi.hpp>
#include <lib/sync.hpp>
#include <stddef.h>
#include <stdint.h>

namespace NArch {
    namespace APIC {

        static const uint32_t LAPICID       = 0x20; // ID of LAPIC.
        static const uint32_t LAPICVER      = 0x30; // Version of LAPIC.
        static const uint32_t LAPICTPR      = 0x80; // Task Priority Register.
        static const uint32_t LAPICAPR      = 0x90; // Arbitration Priority Register.
        static const uint32_t LAPICPPR      = 0xa0; // Processor Priority Register.
        static const uint32_t LAPICEOI      = 0xb0; // End of Interrupt Register.
        static const uint32_t LAPICRRD      = 0xc0; // Remote Read Register.
        static const uint32_t LAPICLDR      = 0xd0; // Logical Destination Register.
        static const uint32_t LAPICDFR      = 0xe0; // Destination Format Register.
        static const uint32_t LAPICSIV      = 0xf0; // Spurious Interrupt Vector Register.

        static const uint32_t LAPICICRLO    = 0x300; // Interrupt Command Register Low.
        static const uint32_t LAPICICRHI    = 0x310; // Interrupt Command Register High.

        static const uint32_t LAPICLVTT     = 0x320; // LVT Timer Register.
        static const uint32_t LAPICLVTTS    = 0x330; // LVT Thermal Sensor Register.
        static const uint32_t LAPICLVTPMC   = 0x340; // LVT Performance Monitoring Counters Register.
        static const uint32_t LAPICLVTINT0  = 0x350; // LVT LTINT0 Register.
        static const uint32_t LAPICLVTINT1  = 0x360; // LVT LTINT1 Register.
        static const uint32_t LAPICLVTERR   = 0x370; // LVT Error Register.
        static const uint32_t LAPICICR      = 0x380; // Initial Count Register.
        static const uint32_t LAPICCCR      = 0x390; // Current Count Register.
        static const uint32_t LAPICDCR      = 0x3e0; // Divide Configuration Register.

        static const uint32_t IPIFIXED      = 0b000; // Normal IPI delivery mode.
        static const uint32_t IPINMI        = 0b100; // IPI delivery mode, as a non-maskable interrupt.

        static const uint32_t IPIPHYS       = 0; // Physical IPI destination mode.
        static const uint32_t IPILOGI       = 1; // Logical IPI destination mode.

        static const uint32_t IPINONE       = 0b00; // IPI targets noone.
        static const uint32_t IPISELF       = 0b01; // IPI targets the LAPIC it was sent from.
        static const uint32_t IPIALL        = 0b10; // IPI targets all LAPICs (inclusive of sender).
        static const uint32_t IPIOTHER      = 0b11; // IPI targets all LAPICs (excluding the sender).


        class IoApic {
            public:
                static const uint32_t IOAPICID      = 0x00; // RO -> APIC ID (24:27).
                static const uint32_t IOAPICVER     = 0x01; // RO -> APIC Version (0:7) + Highest entry in direction table (16:23).
                static const uint32_t IOAPICARB     = 0x02; // RO -> APIC Bus Arbitration Priority (24:27).


                // 0:7 -> Interrupt vector this IRQ should trigger.
                // 8:10 -> Delivery mode.
                // 11 -> Destination mode.
                // 12 -> Delivery status.
                // 13 -> Pin polarity.
                // 14 -> Remote IRR (edge interrupts).
                // 15 -> Trigger mode.
                // 16 -> Mask status (enabled or not).
                // 56:63 -> Destination Field
                //      Physical Mode is for per-APIC (only for the first 16).
                //      Logical Mode is for a set of processors.
                static const uint32_t IOREDTBLBASE  = 0x10; // RW -> Beginning of IRQ redirection table.
                static const uint32_t IOREDTBLTOP   = 0x3f; // RW -> Final register in IRQ redirection table.


                // Here, we're checking the second bit of the offset, because that's the only thing that changes between the two.
                static const uint32_t INTSOPOLARITY = 0b10; // Within an ACPI interrupt source override, get the polarity for the source override (used in the IOAPIC redirection table).
                static const uint32_t INTSOTRIGGER = 0b1000; // Within an ACPI interrupt source override, get the trigger from the source override (used in the IOAPIC redirection table).


                void *addr;
                uint32_t gsibase;
                uint32_t gsitop;
                Spinlock lock;

                // Read from register.
                uint32_t read(uint32_t reg) {
                    NLib::ScopeSpinlock guard(&this->lock);

                    volatile uint32_t *addr = (volatile uint32_t *)this->addr;
                    *addr = reg & 0xff; // Inform IOREGSEL what register we're working with.
                    return *(addr + 4); // Pull value from IOWIN.
                }

                // Write to register.
                void write(uint32_t reg, uint32_t value) {
                    NLib::ScopeSpinlock guard(&this->lock);

                    volatile uint32_t *addr = (volatile uint32_t *)this->addr;
                    *addr = reg & 0xff; // Inform IOREGSEL what register we're working with.
                    *(addr + 4) = value; // Dump value into IOWIN to write out.
                }

                // Write a redirect into the redirection table.
                void writeredirect(uint8_t i, uint8_t vec, uint8_t delmod, uint8_t destmod, uint8_t polarity, uint8_t trigger, bool mask, uint8_t dfield) {

                    uint32_t entry = vec | (delmod & 0b111) << 8 |
                        (destmod & 0x01) << 11 | (polarity & 0x01) << 13 |
                        (trigger & 0x01) << 15 | (mask & 0x01) << 16;

                    // Entry information goes into first part of the register.
                    this->write(IOREDTBLBASE + (i * 2), entry);

                    // Destination field is dumped afterwards. Only the 8 bits at the end of the register matter (everything else is reserved).
                    this->write((IOREDTBLBASE + 1) + (i * 2), (uint32_t)dfield << 24);
                }

                // Mask all IRQ redirects to disable them.
                void maskall(void) {
                    for (size_t i = 0; i < this->gsitop; i++) {
                        // Mask all redirection table entries.
                        // i - base for GSI -> IRQ# translation.
                        this->writeredirect(i - this->gsibase, 0xfe, 0, 0, 0, 0, true, 0);
                    }
                }
        };

        extern IoApic *ioapics;
        extern uintptr_t lapicaddr;
        extern uintptr_t lapicphy;

        // Read from Local APIC register.
        static inline uint32_t readlapic(uint32_t reg) {
            volatile uint32_t *value = (volatile uint32_t *)(lapicaddr + reg);
            return *value;
        }

        // Write to Local APIC register.
        static inline void writelapic(uint32_t reg, uint32_t value) {
            volatile uint32_t *dest = (volatile uint32_t *)(lapicaddr + reg);
            *dest = value;
        }

        // Acknowledge end of interrupt. MUST be called at the end of redirected IOAPIC IRQ handlers.
        void eoi(void);

        // Trigger oneshot interrupt on timeout.
        void lapiconeshot(uint64_t us, uint8_t vec);
        // Stop any actively running timer.
        void lapicstop(void);
        // Initialise Local APIC.
        void lapicinit(void);

        // Send an inter-processor interrupt to another CPU.
        void sendipi(uint8_t cpu, uint8_t vec, uint8_t delivery, uint8_t mode, uint8_t dest);

        void setirq(uint8_t irq, uint8_t vec, bool mask, uint8_t proc);
        void setup(void);
    }
}

#endif
