#ifndef _DEV__PCI_HPP
#define _DEV__PCI_HPP

#include <dev/dev.hpp>
#include <stdint.h>

#ifdef __x86_64__
#include <arch/x86_64/interrupts.hpp>
#endif

namespace NDev {
    namespace PCI {
        struct bar {
            size_t len;
            uintptr_t base;
            bool mmio;
        };

        static constexpr uint8_t MSICTRLREG = 0x02;
        static constexpr uint8_t MSIADDRLOREG = 0x04;
        static constexpr uint8_t MSIADDRHIREG = 0x08;
        static constexpr uint8_t MSIDATAREG32 = 0x08;
        static constexpr uint8_t MSIDATAREG64 = 0x0c;
        static constexpr uint8_t MSIMASKREG32 = 0x0c;
        static constexpr uint8_t MSIMASKREG64 = 0x10;
        static constexpr uint8_t MSIPENDINGREG32 = 0x10;
        static constexpr uint8_t MSIPENDINGREG64 = 0x14;

        static constexpr uint16_t MSICTRL64 = (1 << 7);
        static constexpr uint16_t MSICTRLMASK = (1 << 8);
        static constexpr uint16_t MSICTRLEN = (1 << 0);
        static constexpr uint16_t MSIMMMASK = 0x0070;
        static constexpr uint16_t MSIMMSHIFT = 4;

        static constexpr uint8_t MSIXCTRLREG = 0x02;
        static constexpr uint8_t MSIXTABLE = 0x04;
        static constexpr uint8_t MSIXPBA = 0x08;

        static constexpr uint16_t MSIXCTRLEN = (1 << 15);
        static constexpr uint16_t MSIXCTRLFUNCMASK = (1 << 14);
        static constexpr uint16_t MSIXTABLESIZEMASK = 0x07ff;

        struct msixentry {
            uint32_t addrlo;
            uint32_t addrhi;
            uint32_t data;
            uint32_t vc; // Vector control.
        } __attribute__((packed));

        void maskvector(struct devinfo *dev, uint8_t idx);
        void unmaskvector(struct devinfo *dev, uint8_t idx)
;
        int enablevectors(struct devinfo *dev, uint8_t count, uint8_t *vectors, void (*handler)(struct NArch::Interrupts::isr *, struct NArch::CPU::context *) = NULL, bool eoi = true);
        void disablevectors(struct devinfo *dev, uint8_t count, uint8_t *vectors);

        uint32_t read(struct devinfo *dev, uint32_t off, int size);
        void write(struct devinfo *dev, uint32_t off, uint32_t val, int size);
        struct bar getbar(struct devinfo *dev, uint8_t idx);
        void unmapbar(struct bar bar);

        void init(void);
    }
}

#endif
