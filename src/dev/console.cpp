#include <dev/dev.hpp>
#include <fs/devfs.hpp>
#include <mm/ucopy.hpp>

namespace NDev {

    using namespace NFS;

    class ConsoleDriver : public DevDriver {
        private:
            static const uint64_t DEVICEID = DEVFS::makedev(5, 1); // /dev/console device id.
        public:
            ConsoleDriver(void) {
                registry->add(new Device(DEVICEID, this)); // Register.

                struct VFS::stat st{
                    .st_mode = 0660 | VFS::S_IFCHR,
                    .st_rdev = DEVICEID,
                    .st_blksize = 4096
                };

                VFS::vfs.create("/dev/console", st);



                // st.st_mode = 0664 | VFS::S_IFLNK;
                // st.st_rdev = 0;

                // DEVFS::DevNode *node = (DEVFS::DevNode *)VFS::vfs.create("/dev/stdout", st);
                // node->setsymlink("/dev/console");
            }

            ssize_t write(uint32_t minor, const void *buf, size_t count, off_t offset) override {
                (void)offset;
                assert(minor == 1, "Invalid minor given to console driver.\n");

                char pbuf[1024];
                NLib::memset(pbuf, 0, sizeof(pbuf));

                NUtil::snprintf(pbuf, sizeof(pbuf), "%s", buf);
                NUtil::printf("%s", pbuf);
                return count;
            }
    };

    static struct reginfo info = {
        .name = "syscon",
        .type = reginfo::GENERIC,
        .match = { }
    };

    REGDRIVER(ConsoleDriver, &info);

}
