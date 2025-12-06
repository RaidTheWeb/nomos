#include <fs/ramfs.hpp>
#include <lib/errno.hpp>

namespace NFS {
    namespace RAMFS {
        ssize_t RAMNode::read(void *buf, size_t count, off_t offset, int fdflags) {
            (void)fdflags;
            assert(buf, "Reading into invalid buffer.\n");
            assert(count, "Invalid count.\n");

            this->datalock.acquire();

            if (offset >= this->attr.st_size) {
                this->datalock.release();
                return 0;
            }
            if ((off_t)(offset + count) > this->attr.st_size) {
                count = this->attr.st_size - offset;
            }

            NLib::memcpy(buf, this->data + offset, count);
            this->datalock.release();
            return count;
        }

        ssize_t RAMNode::write(const void *buf, size_t count, off_t offset, int fdflags) {
            (void)fdflags;
            this->datalock.acquire();

            if ((off_t)(offset + count) > this->attr.st_size) {
                this->attr.st_size = offset + count;
                this->attr.st_blocks = (this->attr.st_size + this->attr.st_blksize - 1) / this->attr.st_blksize;

                this->data = (uint8_t *)NMem::allocator.realloc(this->data, this->attr.st_size);
                assert(this->data, "Failed to grow file data.\n");
            }

            NLib::memcpy(this->data + offset, (void *)buf, count);
            this->datalock.release();
            return count;
        }

        ssize_t RAMNode::readdir(void *buf, size_t count, off_t offset) {
            NLib::ScopeSpinlock guard(&this->metalock);

            if (!VFS::S_ISDIR(this->attr.st_mode)) {
                return -ENOTDIR;
            }

            size_t bytesread = 0;
            size_t curroffset = 0;
            NLib::HashMap<RAMNode *>::Iterator it = this->children.begin();

            while (it.valid()) {
                RAMNode *child = *it.value();
                size_t reclen = sizeof(struct VFS::dirent);
                if (curroffset >= (size_t)offset) {
                    if (bytesread + reclen > count) {
                        break; // No more space.
                    }

                    struct VFS::dirent *dentry = (struct VFS::dirent *)((uint8_t *)buf + bytesread);
                    dentry->d_ino = child->attr.st_ino;
                    dentry->d_off = bytesread + reclen;
                    dentry->d_reclen = (uint16_t)reclen;
                    dentry->d_type = (child->attr.st_mode & VFS::S_IFMT) >> 12; // File type is stored in the high bits of st_mode.
                    NLib::memset(dentry->d_name, 0, sizeof(dentry->d_name));
                    NLib::strncpy(dentry->d_name, (char *)child->getname(), sizeof(dentry->d_name) - 1);

                    bytesread += reclen;
                }
                curroffset += reclen;
                it.next();
            }

            return bytesread;
        }

        VFS::INode *RAMNode::resolvesymlink(void) {
            this->datalock.acquire();

            if (!VFS::S_ISLNK(this->attr.st_mode)) {
                return NULL; // Non-symbolic links cannot resolve to node.
            }

            if (!this->attr.st_size) {
                return NULL; // Resolving empty symbolic link.
            }

            VFS::VFS *vfs = this->fs->getvfs();

            // Attempt to resolve the node our data points to. Uses normal resolution function, but it doesn't attempt to resolve symbolic links (we don't want any crazy recursion).
            VFS::INode *node = vfs->resolve((const char *)this->data, this, false);
            this->datalock.release();
            return node;
        }

        VFS::INode *RAMNode::lookup(const char *name) {
            NLib::ScopeSpinlock guard(&this->metalock);

            if (!VFS::S_ISDIR(this->attr.st_mode)) {
                return NULL; // Non-directories possess no children.
            }

            RAMNode **node = this->children.find(name);
            if (node) {
                (*node)->ref();
                return (*node);
            }

            return NULL;
        }

        bool RAMNode::add(VFS::INode *node) {
            NLib::ScopeSpinlock guard(&this->metalock);

            if (!VFS::S_ISDIR(this->attr.st_mode)) {
                return false; // Non-directories possess no children.
            }

            RAMNode *rnode = (RAMNode *)node;

            node->setparent(this); // Ensure the node knows we're its parent.
            this->children.insert(rnode->name, rnode);
            return true;
        }

        bool RAMNode::remove(const char *name) {
            NLib::ScopeSpinlock guard(&this->metalock);

            if (!VFS::S_ISDIR(this->attr.st_mode)) {
                return false; // Non-directories possess no children.
            }

            return this->children.remove(name);
        }

        int RAMFileSystem::mount(const char *path, VFS::INode *mntnode) {
            (void)path;

            NLib::ScopeSpinlock guard(&this->spin);

            if (this->mounted) {
                return -EINVAL;
            }

            // Set the parent of the root node to the mountpoint node.
            if (mntnode) {
                this->root->setparent(mntnode);
            }

            this->mounted = true;
            return 0;
        }

        int RAMFileSystem::umount(void) {
            NLib::ScopeSpinlock guard(&this->spin);

            if (!this->mounted) {
                return -EINVAL; // Unmounted.
            }

            delete this->root; // Delete root node. Its destructor will get rid of every child node in the hierarchy.
            this->root = NULL;
            return 0;
        }

        VFS::INode *RAMFileSystem::create(const char *name, struct VFS::stat attr) {
            attr.st_blksize = 512;
            return new RAMNode(this, name, attr);
        }
    }
}
