#include <fs/ramfs.hpp>
#include <lib/errno.hpp>

namespace NFS {
    namespace RAMFS {
        ssize_t RAMNode::read(void *buf, size_t count, off_t offset) {
            assert(buf, "Reading into invalid buffer.\n");
            assert(count, "Invalid count.\n");

            NLib::ScopeSpinlock guard(&this->spin);

            if (offset >= this->attr.st_size) {
                return 0;
            }
            if ((off_t)(offset + count) > this->attr.st_size) {
                count = this->attr.st_size - offset;
            }

            NLib::memcpy(buf, this->data + offset, count);
            return count;
        }

        ssize_t RAMNode::write(const void *buf, size_t count, off_t offset) {
            NLib::ScopeSpinlock guard(&this->spin);

            if ((off_t)(offset + count) > this->attr.st_size) {
                this->attr.st_size = offset + count;
                this->attr.st_blocks = (this->attr.st_size + this->attr.st_blksize - 1) / this->attr.st_blksize;

                this->data = (uint8_t *)NMem::allocator.realloc(this->data, this->attr.st_size);
                assert(this->data, "Failed to grow file data.\n");
            }

            NLib::memcpy(this->data + offset, (void *)buf, count);
            return count;
        }

        VFS::INode *RAMNode::resolvesymlink(void) {
            NLib::ScopeSpinlock guard(&this->spin);

            if (!VFS::S_ISLNK(this->attr.st_mode)) {
                return NULL; // Non-symbolic links cannot resolve to node.
            }

            if (!this->attr.st_size) {
                return NULL; // Resolving empty symbolic link.
            }

            VFS::VFS *vfs = this->fs->getvfs();

            // Attempt to resolve the node our data points to. Uses normal resolution function, but it doesn't attempt to resolve symbolic links (we don't want any crazy recursion).
            return vfs->resolve((const char *)this->data, this, false);
        }

        VFS::INode *RAMNode::lookup(const char *name) {
            NLib::ScopeSpinlock guard(&this->spin);

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
            NLib::ScopeSpinlock guard(&this->spin);

            if (!VFS::S_ISDIR(this->attr.st_mode)) {
                return false; // Non-directories possess no children.
            }

            RAMNode *rnode = (RAMNode *)node;

            node->setparent(this); // Ensure the node knows we're its parent.
            this->children.insert(rnode->name, rnode);
            return true;
        }

        bool RAMNode::remove(const char *name) {
            NLib::ScopeSpinlock guard(&this->spin);

            if (!VFS::S_ISDIR(this->attr.st_mode)) {
                return false; // Non-directories possess no children.
            }

            return this->children.remove(name);
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
