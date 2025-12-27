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

                RAMNode(VFS::IFileSystem *fs, const char *name, struct VFS::stat attr);

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
                int truncate(off_t length) override;
                VFS::INode *lookup(const char *name) override;
                bool add(VFS::INode *node) override;
                bool remove(const char *name) override;
                VFS::INode *resolvesymlink(void) override;

                int poll(short events, short *revents, int fdflags) override;

                bool empty(void) override {
                    NLib::ScopeSpinlock guard(&this->metalock);
                    return this->children.size() == 0;
                }
        };

        class RAMFileSystem : public VFS::IFileSystem {
            private:
                uint64_t nextinode = 1;
            public:
                RAMFileSystem(VFS::VFS *vfs) {
                    this->vfs = vfs;
                    struct VFS::stat attr = (struct VFS::stat) {
                        .st_mode = 0755 | VFS::S_IFDIR,
                    };
                    this->root = new RAMNode(this, "", attr);
                }

                static VFS::IFileSystem *instance(VFS::VFS *vfs) {
                    return new RAMFileSystem(vfs);
                }


                int mount(const char *src, const char *path, VFS::INode *mntnode, uint64_t flags, const void *data) override;
                int umount(int flags) override;
                int sync(void) override { return 0; }

                ssize_t create(const char *name, VFS::INode **nodeout, struct VFS::stat attr) override;
                int unlink(VFS::INode *node, VFS::INode *parent) override;
                int rename(VFS::INode *oldparent, VFS::INode *node, VFS::INode *newparent, const char *newname, VFS::INode *target) override;
        };
    }
}


#endif
