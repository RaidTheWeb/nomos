#ifdef __x86_64__
#include <arch/limine/console.hpp>
#include <arch/x86_64/arch.hpp>
#endif

#include <dev/dev.hpp>
#include <dev/drivers/tty.hpp>
#include <fs/devfs.hpp>
#include <mm/ucopy.hpp>
#include <std/stddef.h>

namespace NDev {

    using namespace NFS;

    class ConsoleDriver : public DevDriver {
        private:
            // Syscon simply just aliases a TTY, but provides additional functionality specific to a system "console".
            // TTY that syscon aliases can be determined by command line options.

            static const uint64_t DEVICEID = DEVFS::makedev(5, 1); // /dev/console device id.
            Device *targetdev = NULL;
            uint64_t targetdevnum = 0;
            NSched::Mutex devlock; // Lock for device access.
        public:
            ConsoleDriver(void) {
                registry->add(new Device(DEVICEID, this)); // Register.

                struct VFS::stat st {
                    // Exclusive access by the root user, ONLY.
                    .st_mode = (VFS::S_IRUSR | VFS::S_IWUSR) | VFS::S_IFCHR,
                    .st_uid = 0,
                    .st_gid = 0,
                    .st_rdev = DEVICEID,
                    .st_blksize = 1024
                };

                DEVFS::registerdevfile("console", st);

                const char *target = NArch::cmdline.get("syscon");
                if (!target) {
                    // Well. What now? Default to /dev/tty0?
                    // Technically, redirects don't care about whether the target is a TTY or not, we could just send reads and writes to /dev/null, to disable kernel logging.
                    target = "tty1"; // Default to tty0. XXX: Actually implement VT handling through /dev/tty0.
                }

                // Extract tty number from target, and turn that into a TTY minor number.
                uint32_t minor = 0;
                if (NLib::strncmp(target, "tty", 3) == 0) {
                    minor = NLib::atoi(&target[3]);
                } else if (NLib::strncmp(target, "ttyS", 4) == 0) {
                    minor = 64 + NLib::atoi(&target[4]); // Serial TTYs start at minor 64.
                } else {
                    assert(false, "syscon target is not a valid TTY device.\n");
                }

                this->targetdevnum = DEVFS::makedev(4, minor); // TTY major is 4.
                this->targetdev = registry->get(this->targetdevnum);
                assert(this->targetdev != NULL, "syscon target TTY device not found in registry.\n");
            }

            ssize_t write(uint64_t dev, const void *buf, size_t count, off_t offset, int fdflags) override {
                assert(dev == DEVICEID, "Invalid device given to console driver.\n");
                this->devlock.acquire();

                ssize_t ret = this->targetdev->driver->write(this->targetdevnum, buf, count, offset, fdflags);
                this->devlock.release();
                return ret;
            }

            ssize_t read(uint64_t dev, void *buf, size_t count, off_t offset, int fdflags) override {
                (void)offset;
                assert(dev == DEVICEID, "Invalid device given to console driver.\n");

                this->devlock.acquire();
                ssize_t ret = this->targetdev->driver->read(this->targetdevnum, buf, count, offset, fdflags);
                this->devlock.release();
                return ret;
            }

            int ioctl(uint64_t dev, unsigned long request, uint64_t arg) override {
                assert(dev == DEVICEID, "Invalid device given to console driver.\n");

                this->devlock.acquire();
                int ret = this->targetdev->driver->ioctl(this->targetdevnum, request, arg);
                this->devlock.release();
                return ret;
            }

            int poll(uint64_t dev, short events, short *revents, int fdflags) override {
                assert(dev == DEVICEID, "Invalid device given to console driver.\n");

                this->devlock.acquire();
                int ret = this->targetdev->driver->poll(this->targetdevnum, events, revents, fdflags);
                this->devlock.release();
                return ret;
            }
    };

    static struct reginfo info = {
        .name = "syscon",
        .type = reginfo::GENERIC,
        .stage = reginfo::STAGE2, // Load order after tty.
        .match = { }
    };

    REGDRIVER(ConsoleDriver, &info);

}
