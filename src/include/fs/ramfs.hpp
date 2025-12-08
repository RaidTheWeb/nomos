#ifndef _FS__RAMFS_HPP
#define _FS__RAMFS_HPP

#include <fs/vfs.hpp>
#include <lib/errno.hpp>
#include <sched/sched.hpp>

namespace NFS {
    namespace RAMFS {
        class RAMNode : public VFS::INode {
            private:
                uint8_t *data = NULL;
                NLib::HashMap<RAMNode *> children;
                NSched::Mutex datalock; // Lock for data access.
            public:

                RAMNode(VFS::IFileSystem *fs, const char *name, struct VFS::stat attr) : VFS::INode(fs, name, attr) { }

                ~RAMNode(void) {
                    delete this->name;

                    if (this->data != NULL) {
                        delete this->data;
                    }
                    // Free children:
                    NLib::HashMap<RAMNode *>::Iterator it = this->children.begin();
                    while (it.valid()) {
                        delete *it.value(); // Free node.
                        it.next();
                    }
                }

                ssize_t read(void *buf, size_t count, off_t offset, int fdflags) override;
                ssize_t write(const void *buf, size_t count, off_t offset, int fdflags) override;
                ssize_t readdir(void *buf, size_t count, off_t offset) override;
                ssize_t readlink(char *buf, size_t bufsiz) override;
                VFS::INode *lookup(const char *name) override;
                bool add(VFS::INode *node) override;
                bool remove(const char *name) override;
                VFS::INode *resolvesymlink(void) override;
        };

        class RAMFileSystem : public VFS::IFileSystem {
            private:
            public:
                RAMFileSystem(VFS::VFS *vfs) {
                    this->vfs = vfs;
                    struct VFS::stat attr = (struct VFS::stat) {
                        .st_mode = 0755 | VFS::S_IFDIR,
                    };
                    this->root = new RAMNode(this, "", attr);
                }

                int mount(const char *path, VFS::INode *mntnode) override;
                int umount(void) override;
                int sync(void) override { return 0; }

                VFS::INode *create(const char *name, struct VFS::stat attr) override;
        };
    }
}


#endif
