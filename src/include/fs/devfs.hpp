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

        class DevFileSystem;

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

                NLib::HashMap<DevNode *> &getchildren(void) {
                    return this->children;
                }

                ssize_t read(void *buf, size_t count, off_t offset, int fdflags) override;
                ssize_t write(const void *buf, size_t count, off_t offset, int fdflags) override;
                ssize_t readdir(void *buf, size_t count, off_t offset) override;
                ssize_t readlink(char *buf, size_t bufsiz) override;
                int open(int flags) override;
                int close(int fdflags) override;
                int poll(short events, short *revents, int fdflags) override;
                int mmap(void *addr, size_t count, size_t offset, uint64_t flags, int fdflags) override;
                int munmap(void *addr, size_t count, size_t offset, int fdflags) override;
                int ioctl(unsigned long request, uint64_t arg) override;
                int stat(struct VFS::stat *st) override;
                VFS::INode *lookup(const char *name) override;
                bool add(VFS::INode *node) override;
                bool remove(const char *name) override;
                VFS::INode *resolvesymlink(void) override;
                bool empty(void) override {
                    NLib::ScopeIRQSpinlock guard(&this->metalock);
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

                ~DevFileSystem(void);

                static VFS::IFileSystem *instance(VFS::VFS *vfs) {
                    return new DevFileSystem(vfs);
                }

                int mount(const char *src, const char *path, VFS::INode *mntnode, uint64_t flags, const void *data) override;
                int sync(void) override;
                int umount(int flags) override;
                ssize_t create(const char *name, VFS::INode **nodeout, struct VFS::stat attr) override;
                int unlink(VFS::INode *node, VFS::INode *parent) override;

                // Create a class directory node directly on this filesystem.
                DevNode *createclassnode(const char *classname);
                // Remove a class directory node from this filesystem.
                void removeclassnode(const char *classname);
                // Create a device file node directly on this filesystem.
                DevNode *createdevnode(const char *name, struct VFS::stat attr, const char *classname);
                // Remove a device file node from this filesystem.
                void removedevnode(const char *name, const char *classname);
        };

        struct regclass {
            const char *name; // Class name (for /dev/<class>/).
        };

        struct regdevfile {
            const char *name; // Device file name (for /dev/<class>/<name>).
            const char *classname; // Device class name, or NULL for generic (root /dev/).
            struct VFS::stat attr; // Attributes for the device node.
        };

        extern NArch::Spinlock devlock;
        extern NLib::DoubleList<struct regclass> registeredclasses;
        extern NLib::DoubleList<struct regdevfile> registered;
        extern NLib::DoubleList<DevFileSystem *> mountedinstances;

        // Register a mounted devfs instance for automatic updates.
        void registerinstance(DevFileSystem *fs);
        // Unregister a devfs instance.
        void unregisterinstance(DevFileSystem *fs);

        // Register a device class (creates /dev/<name>/ directory).
        void registerclass(const char *name);
        // Unregister a device class.
        void unregisterclass(const char *name);

        // Register a device file under a device class. If classname is NULL, registers under /dev/ directly.
        void registerdevfile(const char *name, struct VFS::stat attr, const char *classname = NULL);
        // Unregister a device file.
        void unregisterdevfile(const char *name, const char *classname = NULL);

        // Find a registered class by name. Returns NULL if not found.
        struct regclass *findclass(const char *name);

        // Lookup a device node by name from the first mounted devfs instance.
        DevNode *lookupdevnode(const char *name, const char *classname = NULL);
    }
}
#endif
