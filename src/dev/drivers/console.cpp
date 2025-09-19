#ifdef __x86_64__
#include <arch/x86_64/arch.hpp>
#endif

#include <dev/dev.hpp>
#include <arch/limine/console.hpp>
#include <dev/drivers/tty.hpp>
#include <fs/devfs.hpp>
#include <mm/ucopy.hpp>

namespace NDev {

    using namespace NFS;

    class ConsoleDriver : public DevDriver {
        private:
            // Syscon simply just aliases a TTY, but provides additional functionality specific to a system "console".
            // TTY that syscon aliases can be determined by command line options.

            static const uint64_t DEVICEID = DEVFS::makedev(5, 1); // /dev/console device id.
            VFS::INode *targetnode = NULL;
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

                assert(VFS::vfs.create("/dev/console", st), "Failed to create device node.\n");

                const char *target = NArch::cmdline.get("syscon");
                if (!target) {
                    // Well. What now? Default to /dev/tty0?
                    // Technically, redirects don't care about whether the target is a TTY or not, we could just send reads and writes to /dev/null, to disable kernel logging.
                    target = "tty1"; // Default to tty0. XXX: Actually implement VT handling through /dev/tty0.
                }
                char path[1024];
                NUtil::snprintf(path, sizeof(path), "/dev/%s", target);
                this->targetnode = VFS::vfs.resolve(path);
                assert(this->targetnode, "Invalid syscon target.");
                this->targetnode->unref();
            }

            ssize_t write(uint64_t dev, const void *buf, size_t count, off_t offset, int fdflags) override {
                assert(dev == DEVICEID, "Invalid device given to console driver.\n");

                this->targetnode->ref();
                ssize_t ret = this->targetnode->write(buf, count, offset, fdflags);
                this->targetnode->unref();
                return ret;
            }

            ssize_t read(uint64_t dev, void *buf, size_t count, off_t offset, int fdflags) override {
                (void)offset;
                assert(dev == DEVICEID, "Invalid device given to console driver.\n");

                this->targetnode->ref();
                ssize_t ret = this->targetnode->read(buf, count, offset, fdflags);
                this->targetnode->unref();
                return ret;
            }

            int ioctl(uint64_t dev, unsigned long request, uint64_t arg) override {
                assert(dev == DEVICEID, "Invalid device given to console driver.\n");

                this->targetnode->ref();
                int ret = this->targetnode->ioctl(request, arg);
                this->targetnode->unref();
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
