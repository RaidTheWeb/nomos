#ifndef _DEV__DEV_HPP
#define _DEV__DEV_HPP

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

namespace NDev {

    __attribute__((used))
    static const uint32_t MAGIC = 0x419af8b2;

    class Driver {
        public:

    };

    struct reginfo {
        // Type of driver:
        enum type {
            PCI, // Instantiates when PCI device is matched.
            USB, // Instantiates when USB device is matched.
            GENERIC // Always instantiated, it will handle probing and such on its own (used for stuff like PS2 drivers).
        };

        const char *name;
        enum type type; // What type of driver are we registering?

        union {
            struct {
                // PCI generic info, only for *very* general devices.
                uint8_t pciclass;
                uint8_t pcisubclass;
                uint8_t pciprogif;

                uint8_t flags; // When matching for PCI devices, what should we match for?

                uint16_t vendor; // Vendor ID to search for.

                uint32_t devcount; // How many device IDs to try match.
                uint16_t devices[]; // List of device IDs this driver will service.
            } pci;
            struct {
                // USB generic info, for generic devices (eg. storage devices, mice, and keyboards).
                uint8_t usbclass;
                uint8_t usbsubclass;

                uint16_t usbver;
                uint16_t devver; // For matching specific revisions of devices.

                uint8_t flags; // When matching for USB devices, what should we match for?

                uint16_t vendor; // Vendor ID to search for.

                uint32_t productcount; // How many product IDs to try match.
                uint16_t products[]; // List of product IDs this driver will service.
            } usb;
        } match;
    };

    struct regentry {
        uint32_t magic;
        Driver *(*create)(void);
        struct reginfo *info;
    };

    extern "C" struct regentry __drivers_start[];
    extern "C" struct regentry __drivers_end[];

#define REGDRIVER(driver, driverinfo) \
    extern "C" __attribute__((section(".drivers"), used)) struct NDev::regentry driver##_entry = { \
        .magic = MAGIC, \
        .create = []() -> NDev::Driver *{ return new driver(); }, \
        .info = driverinfo \
    }


}

#endif
