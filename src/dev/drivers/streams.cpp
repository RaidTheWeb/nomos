
#ifdef __x86_64__
#include <arch/x86_64/cpu.hpp>
#endif

#include <dev/dev.hpp>
#include <dev/input/input.hpp>
#include <fs/devfs.hpp>
#include <mm/ucopy.hpp>
#include <sched/sched.hpp>
#include <std/stddef.h>
#include <sys/clock.hpp>
#include <sys/random.hpp>

namespace NDev {

    using namespace NFS;

    class StreamDriver : public DevDriver {
        private:
            static const uint32_t MAJOR = 1; // "Memory devices". This driver doesn't implement all of them, only a few.

            // Stream device minor device IDs:
            static const uint32_t NULLMINOR = 3;
            static const uint32_t ZEROMINOR = 5;
            static const uint32_t FULLMINOR = 7;
            static const uint32_t RANDOMMINOR = 8;
            static const uint32_t URANDOMMINOR = 9;

            // None of the devices have any state, so there's no need for locking mechanisms.
        public:
            StreamDriver(void) {
                registry->add(new Device(DEVFS::makedev(MAJOR, NULLMINOR), this));
                registry->add(new Device(DEVFS::makedev(MAJOR, ZEROMINOR), this)); // Register device.
                registry->add(new Device(DEVFS::makedev(MAJOR, FULLMINOR), this));
                registry->add(new Device(DEVFS::makedev(MAJOR, RANDOMMINOR), this));
                registry->add(new Device(DEVFS::makedev(MAJOR, URANDOMMINOR), this));

                // Initial stat struct. All of the streams are the same, so we can just change the device to reflect a different stream.
                struct VFS::stat st {
                    .st_mode = 0666 | VFS::S_IFCHR,
                    .st_rdev = DEVFS::makedev(MAJOR, NULLMINOR),
                    .st_blksize = 4096
                };

                DEVFS::registerdevfile("null", st);

                st.st_rdev = DEVFS::makedev(MAJOR, ZEROMINOR);
                DEVFS::registerdevfile("zero", st);

                st.st_rdev = DEVFS::makedev(MAJOR, FULLMINOR);
                DEVFS::registerdevfile("full", st);

                st.st_rdev = DEVFS::makedev(MAJOR, RANDOMMINOR);
                DEVFS::registerdevfile("random", st);

                st.st_rdev = DEVFS::makedev(MAJOR, URANDOMMINOR);
                DEVFS::registerdevfile("urandom", st);
            }

            ssize_t read(uint64_t dev, void *buf, size_t count, off_t offset, int fdflags) override {
                (void)offset;
                (void)fdflags;
                uint32_t minor = DEVFS::minor(dev);

                switch (minor) {
                    case NULLMINOR: {
                        return 0; // Immediate EOF. You cannot read from /dev/null.
                    }
                    case ZEROMINOR:
                    case FULLMINOR: { // Both of these provide zeroes on read.
                        NLib::memset(buf, 0, count); // Reading device simply wants us to fill the buffer with zeroes.
                        return count;
                    }
                    case RANDOMMINOR: // /dev/random uses blocking and limited by entropy.
                    case URANDOMMINOR: { // /dev/urandom is non-blocking and not limited by entropy.
                        bool blocking = (minor == RANDOMMINOR); // /dev/random is blocking, /dev/urandom is non-blocking.
                        bool randomsource = (minor == RANDOMMINOR); // /dev/random limits by available entropy.

                        if (!NMem::UserCopy::valid(buf, count)) {
                            return -EFAULT;
                        }

                        NSys::Random::EntropyPool *pool = NArch::CPU::get()->entropypool;
                        ssize_t ret = pool->getrandom((uint8_t *)buf, count, blocking, randomsource);
                        return ret; // Return actual bytes read (may be less than count for /dev/random).
                    }

                    default:
                        return -EBADF;
                }
            }

            ssize_t write(uint64_t dev, const void *buf, size_t count, off_t offset, int fdflags) override {
                (void)buf;
                (void)offset;
                (void)fdflags;
                uint64_t minor = DEVFS::minor(dev);

                if (minor == FULLMINOR) {
                    return -ENOSPC; // /dev/full should return ENOSPC error on write. Because it's "full".
                }

                // None of these stream devices are "writable", but will tell the user that everything went well, regardless.
                return count;
            }
    };

    static struct reginfo info = {
        .name = "streams",
        .type = reginfo::GENERIC,
        .match = { }
    };

    REGDRIVER(StreamDriver, &info);
}
