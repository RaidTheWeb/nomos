#ifdef __x86_64__
#include <arch/x86_64/e9.hpp>
#endif

#include <dev/dev.hpp>
#include <fs/devfs.hpp>
#include <mm/ucopy.hpp>
#include <std/stddef.h>

namespace NDev {
    using namespace NFS;

    class E9Driver : public DevDriver {
        private:
            static const uint32_t MAJOR = 255; // Arbitrary major for E9 debug port.

            static const uint32_t E9MINOR = 0;

        public:
            E9Driver(void) {
                registry->add(new Device(DEVFS::makedev(MAJOR, E9MINOR), this)); // Register device.

                struct VFS::stat st {
                    .st_mode = 0600 | VFS::S_IFCHR,
                    .st_rdev = DEVFS::makedev(MAJOR, E9MINOR),
                    .st_blksize = 1
                };

                DEVFS::registerdevfile("e9", st);
                NArch::E9::enabled = true;
            }

            ssize_t write(uint64_t dev, const void *buf, size_t count, off_t offset, int fdflags) override {
                (void)dev;
                (void)offset;
                (void)fdflags;

                size_t totalwritten = 0;
                const char *cbuf = (const char *)buf;

                char kbuf[256];
                while (totalwritten < count) {
                    size_t chunk = (count - totalwritten > sizeof(kbuf)) ? sizeof(kbuf) : (count - totalwritten);
                    ssize_t ret = NMem::UserCopy::copyfrom(&kbuf, &cbuf[totalwritten], chunk);
                    if (ret < 0) {
                        return ret;
                    }

                    for (size_t i = 0; i < chunk; i++) {
                        NArch::E9::puts(&kbuf[i]);
                    }
                    totalwritten += chunk;
                }
                return (ssize_t)totalwritten;
            }
    };

    static struct reginfo info = {
        .name = "e9",
        .type = reginfo::GENERIC,
        .stage = reginfo::STAGE1
    };
    REGDRIVER(E9Driver, &info);
}