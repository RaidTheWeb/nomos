#ifndef _DEV__DEV_HPP
#define _DEV__DEV_HPP

#include <lib/errno.hpp>
#include <lib/list.hpp>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

namespace NDev {

    __attribute__((used))
    static const uint32_t MAGIC = 0x419af8b2;

    class Driver {
        public:

    };

    class BusDriver : public Driver {
        public:
    };

    class DevDriver;

    class Device {
        public:
            DevDriver *driver = NULL;

            uint64_t id;

            Device(uint64_t id, DevDriver *driver) {
                this->id = id;
                this->driver = driver;
            }
    };

    class DeviceRegistry {
        private:
            NLib::KVHashMap<uint64_t, Device *> map;
        public:
            void add(Device *dev) {
                this->map.insert(dev->id, dev);
            }

            Device *get(uint64_t id) {
                Device **dev = this->map.find(id);
                if (dev) {
                    return (*dev);
                }
                return NULL;
            }

            void remove(uint64_t id) {
                this->map.remove(id);
            }

            void remove(Device *dev) {
                this->remove(dev->id);
            }
    };

    extern DeviceRegistry *registry;
    void setup(void);

    // Driver that is represented with on the dev filesystem.
    class DevDriver : public Driver {
        protected:
        public:

            virtual ~DevDriver(void) = default;

            virtual ssize_t read(uint32_t minor, void *buf, size_t count, off_t offset) {
                (void)minor;
                (void)buf;
                (void)count;
                (void)offset;
                return 0;
            }
            virtual ssize_t write(uint32_t minor, const void *buf, size_t count, off_t offset) {
                (void)minor;
                (void)buf;
                (void)count;
                (void)offset;
                return 0;
            }
//            XXX: virtual int poll(uint32_t minor, ...)
            virtual int mmap(uint32_t minor, void *addr, size_t offset, uint64_t flags) {
                (void)minor;
                (void)addr;
                (void)offset;
                (void)flags;
                return -EFAULT;
            }
            virtual int munmap(uint32_t minor, void *addr) {
                (void)minor;
                (void)addr;
                return -EFAULT;
            }
            virtual int isatty(uint32_t minor) {
                (void)minor;
                return -ENOTTY;
            }
            virtual int open(uint32_t minor, int flags) {
                (void)minor;
                (void)flags;
                return 0;
            }
            virtual int close(uint32_t minor) {
                (void)minor;
                return 0;
            }
            virtual int ioctl(uint32_t minor, uint32_t request, uint64_t arg) {
                (void)minor;
                (void)request;
                (void)arg;
                return -EINVAL;
            }
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
    } __attribute__((aligned(16)));

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
