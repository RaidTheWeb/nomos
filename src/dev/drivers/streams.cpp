#include <dev/dev.hpp>
#include <dev/input/input.hpp>
#include <fs/devfs.hpp>
#include <mm/ucopy.hpp>
#include <sched/sched.hpp>
#include <std/stddef.h>
#include <sys/clock.hpp>

namespace NDev {

    using namespace NFS;

    static struct Input::eventhandler handler;
    static uint64_t entropy = 0;

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

                VFS::INode *devnode;
                VFS::vfs->create("/dev/null", &devnode, st);
                devnode->unref();

                st.st_rdev = DEVFS::makedev(MAJOR, ZEROMINOR);
                VFS::vfs->create("/dev/zero", &devnode, st);
                devnode->unref();

                st.st_rdev = DEVFS::makedev(MAJOR, FULLMINOR);
                VFS::vfs->create("/dev/full", &devnode, st);
                devnode->unref();

                st.st_rdev = DEVFS::makedev(MAJOR, RANDOMMINOR);
                VFS::vfs->create("/dev/random", &devnode, st);
                devnode->unref();

                st.st_rdev = DEVFS::makedev(MAJOR, URANDOMMINOR);
                VFS::vfs->create("/dev/urandom", &devnode, st);
                devnode->unref();

                handler.connect = NULL;
                handler.disconnect = NULL;
                handler.evsubscription = Input::event::KEY; // XXX: As we get new events, they should be crammed into entropy.
                handler.event = event;
                Input::registerhandler(&handler);
            }

            static void event(uint64_t tmstmp, uint16_t type, uint16_t code, int32_t value) {
                (void)type;
                (void)code;
                (void)value;
                // XXX: This is abysmal.

                entropy ^= tmstmp;
                struct NSys::Clock::timespec ts;
                NSys::Clock::getclock(NSys::Clock::CLOCK_MONOTONIC)->gettime(&ts);
                entropy ^= ts.tv_nsec;
                entropy ^= (entropy << 5) | (entropy >> 7);
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
                    case RANDOMMINOR: // XXX: /dev/random is supposed to use an "entropy pool". How fancy.
                    case URANDOMMINOR: {
                        uint8_t *cbuf = (uint8_t *)buf;
                        for (size_t i = 0; i < count; i++) {
                            // XXX: By no means even remotely secure.
                            // It's just a random number seeded by input events, and that's all I need it to be.
                            entropy ^= (entropy << 13);
                            entropy ^= (entropy >> 7);
                            entropy ^= (entropy << 17);
                            cbuf[i] = (uint8_t)(entropy & 0xff);
                        }
                        return count;
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
