#ifndef _DEV__DEV_HPP
#define _DEV__DEV_HPP

#include <fs/vfs.hpp>
#include <lib/errno.hpp>
#include <lib/list.hpp>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

namespace NDev {

    __attribute__((used))
    static const uint32_t MAGIC = 0x419af8b2;

    struct devinfo {
        enum type {
            PCI,
            USB
        };

        enum type type;

        union {
            struct {
                // PCI generic info, only for *very* general devices.
                uint8_t pciclass;
                uint8_t pcisubclass;
                uint8_t pciprogif;
                uint8_t pcirev;

                uint16_t vendor; // Vendor ID.
                uint16_t device; // Device ID.

                uint8_t seg;
                uint8_t bus;
                uint8_t slot;
                uint8_t func;

                bool msisupport;
                bool msixsupport;
                uint16_t msioff;
                uint16_t msixoff;
                bool pciesupport;
                uint16_t pcieoff;
            } pci;
            struct {
                // USB generic info, for generic devices (eg. storage devices, mice, and keyboards).
                uint8_t usbclass;
                uint8_t usbsubclass;

                uint16_t usbver;
                uint16_t devver; // Specific device revision.

                uint16_t vendor; // Vendor ID.
                uint16_t product; // Product ID.
            } usb;
        } info;
    };

    class Driver {
        public:
            virtual void probe(struct devinfo info) {
                (void)info;
            }
    };

    class BusDriver : public Driver {
        public:
    };

    class DevDriver;

    class Device {
        public:
            DevDriver *driver = NULL;

            uint64_t id;

            NFS::VFS::INode *ifnode = NULL; // Device node for interface. Set automatically during node creation.

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

            virtual ssize_t read(uint64_t dev, void *buf, size_t count, off_t offset, int fdflags) {
                (void)dev;
                (void)buf;
                (void)count;
                (void)offset;
                (void)fdflags;
                return 0;
            }
            virtual ssize_t write(uint64_t dev, const void *buf, size_t count, off_t offset, int fdflags) {
                (void)dev;
                (void)buf;
                (void)count;
                (void)offset;
                (void)fdflags;
                return 0;
            }
//            XXX: virtual int poll(uint32_t minor, ...)
            virtual int mmap(uint64_t dev, void *addr, size_t offset, uint64_t flags, int fdflags) {
                (void)dev;
                (void)addr;
                (void)offset;
                (void)flags;
                (void)fdflags;
                return -EFAULT;
            }
            virtual int munmap(uint64_t dev, void *addr, int fdflags) {
                (void)dev;
                (void)addr;
                (void)fdflags;
                return -EFAULT;
            }
            virtual int open(uint64_t dev, int flags) {
                (void)dev;
                (void)flags;
                return 0;
            }
            virtual int close(uint64_t dev, int fdflags) {
                (void)dev;
                (void)fdflags;
                return 0;
            }
            virtual int ioctl(uint64_t dev, unsigned long request, uint64_t arg) {
                (void)dev;
                (void)request;
                (void)arg;
                return -EINVAL;
            }
            virtual int stat(uint64_t dev, struct NFS::VFS::stat *st) {
                (void)dev;
                (void)st;
                return -123123123; // Tell device node to default to node attributes.
            }

            virtual void probe(struct devinfo info) {
                (void)info;
            }
    };

    enum pciflags {
        PCI_MATCHCLASS      = (1 << 0),
        PCI_MATCHSUBCLASS   = (1 << 1),
        PCI_MATCHPROGIF     = (1 << 2),
        PCI_MATCHVENDOR     = (1 << 3), // Match a specific vendor.
        PCI_MATCHDEVICE     = (1 << 4), // Match a specific vendor+device.
    };

    struct reginfo {
        // Type of driver:
        enum type {
            PCI, // Instantiates when PCI device is matched.
            USB, // Instantiates when USB device is matched.
            GENERIC // Always instantiated, it will handle probing and such on its own (used for stuff like PS2 drivers).
        };

        enum stage { // Incredibly rudimentary way to provide load order. XXX: Implement a proper system for this later.
            STAGE1,
            STAGE2
        };

        const char *name;
        enum type type; // What type of driver are we registering?
        enum stage stage = STAGE1; // When should we load the driver?

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
        Driver *instance = NULL;
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
