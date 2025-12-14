#ifndef _FS__DEVFS_HPP
#define _FS__DEVFS_HPP

#include <dev/dev.hpp>
#include <fs/vfs.hpp>
#include <lib/errno.hpp>

namespace NFS {
    namespace DEVFS {
        // Bitmasks for quickly extracting major and minor from encoding.
        static const uint64_t MAJORHI = 0xffffffff00000000;
        static const uint64_t MAJORLO = 0x000000000000ff00;
        static const uint64_t MINORHI = 0x00000000ffff0000;
        static const uint64_t MINORLO = 0x00000000000000ff;
        static const int64_t NOSTAT = -123123123; // Specific error code to indicate that the driver could not provide stat info, so the device node should use its own.

        // Pack 32-bit major and minor device ids into 64-bit device number.
        static constexpr uint64_t makedev(uint32_t major, uint32_t minor) {
            return ((uint64_t)(major & 0xffffffff) << 32) |
                    ((uint64_t)(minor & 0xffff) << 16) |
                    ((uint64_t)(major & 0xff00) << 8) |
                    (minor & 0xff);
        }

        // Extract major from device number.
        static inline uint32_t major(uint64_t dev) {
            return (uint32_t)((dev & MAJORHI) >> 32) |
                    (uint32_t)((dev & MAJORLO) >> 8);
        }

        // Extract minor from device number.
        static inline uint32_t minor(uint64_t dev) {
            return (uint32_t)((dev & MINORHI) >> 16) |
                    (uint32_t)(dev & MINORLO);
        }

        class DevNode : public VFS::INode {
            private:
                const char *symlinktarget = NULL;
                NDev::Device *device = NULL;
                NLib::HashMap<DevNode *> children;
            public:
                DevNode(VFS::IFileSystem *fs, const char *name, struct VFS::stat attr) : VFS::INode(fs, name, attr) { }
                ~DevNode(void) {
                    delete this->name;
                    if (this->symlinktarget) {
                        delete this->symlinktarget;
                    }

                    NLib::HashMap<DevNode *>::Iterator it = this->children.begin();

                    while (it.valid()) {
                        delete *it.value();
                        it.next();
                    }
                }

                void setsymlink(const char *target) {
                    this->symlinktarget = NLib::strdup(target);
                }

                void setdev(NDev::Device *dev) {
                    this->device = dev;
                }

                ssize_t read(void *buf, size_t count, off_t offset, int fdflags) override;
                ssize_t write(const void *buf, size_t count, off_t offset, int fdflags) override;
                ssize_t readdir(void *buf, size_t count, off_t offset) override;
                ssize_t readlink(char *buf, size_t bufsiz) override;
                int open(int flags) override;
                int close(int fdflags) override;
                int poll(short events, short *revents, int fdflags) override;
                int mmap(void *addr, size_t count, size_t offset, uint64_t flags, int fdflags) override;
                int munmap(void *addr, int fdflags) override;
                int ioctl(unsigned long request, uint64_t arg) override;
                int stat(struct VFS::stat *st) override;
                VFS::INode *lookup(const char *name) override;
                bool add(VFS::INode *node) override;
                bool remove(const char *name) override;
                VFS::INode *resolvesymlink(void) override;
                bool empty(void) override {
                    NLib::ScopeSpinlock guard(&this->metalock);
                    return this->children.size() == 0;
                }
        };

        class DevFileSystem : public VFS::IFileSystem {
            private:
                uint64_t nextinode = 1;
            public:
                DevFileSystem(VFS::VFS *vfs) {
                    this->vfs = vfs;
                    struct VFS::stat attr {
                        .st_mode = 0755 | VFS::S_IFDIR,
                    };
                    this->root = new DevNode(this, "", attr);
                }

                int mount(const char *path, VFS::INode *mntnode) override;
                int sync(void) override;
                int umount(void) override;
                ssize_t create(const char *name, VFS::INode **nodeout, struct VFS::stat attr) override;
                int unlink(const char *path) override;
        };
    }
}
#endif
