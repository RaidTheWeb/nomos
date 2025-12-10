#ifndef __FS__PIPEFS_HPP
#define __FS__PIPEFS_HPP

#include <fs/vfs.hpp>
#include <lib/errno.hpp>
#include <sched/sched.hpp>
#include <std/stddef.h>

namespace NFS {
    namespace PipeFS {
        #define PIPEBUFSIZE (16 * NArch::PAGESIZE)

        class PipeNode : public VFS::INode {
            private:
                NArch::Spinlock datalock;
                NSched::WaitQueue wq;
                NLib::CircularBuffer<uint8_t> databuffer;
                size_t writers = 0;
                size_t readers = 0;
            public:
                PipeNode(VFS::IFileSystem *fs, const char *name, struct VFS::stat attr);

                ~PipeNode(void) {
                    delete this->name;
                }

                int open(int flags) override;
                int close(int fdflags) override;

                ssize_t read(void *buf, size_t count, off_t offset, int fdflags) override;
                ssize_t write(const void *buf, size_t count, off_t offset, int fdflags) override;
                ssize_t readdir(void *buf, size_t count, off_t offset) override {
                    return -ENOTDIR;
                }
                ssize_t readlink(char *buf, size_t bufsiz) override {
                    return -EINVAL;
                }
                VFS::INode *lookup(const char *name) override {
                    (void)name;
                    return NULL;
                }
                bool add(VFS::INode *node) override {
                    (void)node;
                    return false;
                }
                bool remove(const char *name) override {
                    (void)name;
                    return false;
                }
                VFS::INode *resolvesymlink(void) override {
                    return NULL;
                }

                bool empty(void) override {
                    return true;
                }
        };

        class PipeFileSystem : public VFS::IFileSystem {
            public:
                PipeFileSystem(VFS::VFS *vfs) {
                    this->vfs = vfs;
                    struct VFS::stat attr = (struct VFS::stat) {
                        .st_mode = 0666 | VFS::S_IFIFO,
                    };
                    this->root = new PipeNode(this, "", attr);
                }

                int mount(const char *path, VFS::INode *mntnode) override {
                    (void)path;
                    (void)mntnode;
                    return -EINVAL; // Purely virtual filesystem.
                }
                int umount(void) override {
                    return 0;
                }
                int sync(void) override;

                // TODO: FIFO files creating their corresponding PipeNode instances.
                // Maybe when initialising a filesystem, we create PipeNode hardlinks for each FIFO file...
                // This would mean we'd need a specialised "abstracted" hard link purely in the VFS, just for stuff like this.
                VFS::INode *create(const char *name, struct VFS::stat attr) override {
                    if (!VFS::S_ISFIFO(attr.st_mode)) {
                        return NULL; // Only FIFOs supported.
                    }

                    return new PipeNode(this, name, attr);
                }

                int unlink(const char *path) override {
                    return -ENOSYS; // Not supported.
                }
        };

        // Global PipeFS instance.
        extern PipeFileSystem *pipefs;
    }
}

#endif