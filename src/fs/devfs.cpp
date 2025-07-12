#include <fs/devfs.hpp>

namespace NFS {
    namespace DEVFS {

        ssize_t DevNode::read(void *buf, size_t count, off_t offset) {
            NLib::ScopeSpinlock guard(&this->spin);

            if (!this->device) {
                return -ENODEV;
            }

            return this->device->driver->read(minor(this->attr.st_rdev), buf, count, offset);
        }

        ssize_t DevNode::write(const void *buf, size_t count, off_t offset) {
            NLib::ScopeSpinlock guard(&this->spin);

            if (!this->device) {
                return -ENODEV;
            }

            return this->device->driver->write(minor(this->attr.st_rdev), buf, count, offset);
        }

        int DevNode::open(int flags) {
            NLib::ScopeSpinlock guard(&this->spin);

            if (!this->device) {
                return -ENODEV;
            }

            return this->device->driver->open(minor(this->attr.st_rdev), flags);
        }

        int DevNode::close(void) {
            NLib::ScopeSpinlock guard(&this->spin);

            if (!this->device) {
                return -ENODEV;
            }

            return this->device->driver->close(minor(this->attr.st_rdev));
        }

        int DevNode::mmap(void *addr, size_t offset, uint64_t flags) {
            NLib::ScopeSpinlock guard(&this->spin);

            if (!this->device) {
                return -ENODEV;
            }

            return this->device->driver->mmap(minor(this->attr.st_rdev), addr, offset, flags);
        }

        int DevNode::munmap(void *addr) {
            NLib::ScopeSpinlock guard(&this->spin);

            if (!this->device) {
                return -ENODEV;
            }

            return this->device->driver->munmap(minor(this->attr.st_rdev), addr);
        }

        int DevNode::isatty(void) {
            NLib::ScopeSpinlock guard(&this->spin);

            if (!this->device) {
                return -ENODEV;
            }

            return this->device->driver->isatty(minor(this->attr.st_rdev));
        }

        int DevNode::ioctl(uint32_t request, uint64_t arg) {
            NLib::ScopeSpinlock guard(&this->spin);

            if (!this->device) {
                return -ENODEV;
            }

            return this->device->driver->ioctl(minor(this->attr.st_dev), request, arg);
        }

        VFS::INode *DevNode::resolvesymlink(void) {
            NLib::ScopeSpinlock guard(&this->spin);

            if (!VFS::S_ISLNK(this->attr.st_mode)) {
                return NULL;
            }

            if (!this->symlinktarget) {
                return NULL;
            }
            VFS::VFS *vfs = this->fs->getvfs();
            NUtil::printf("Resolve %s.\n", this->symlinktarget);
            return vfs->resolve(this->symlinktarget, this, false);
        }

        VFS::INode *DevNode::lookup(const char *name) {
            NLib::ScopeSpinlock guard(&this->spin);

            if (!VFS::S_ISDIR(this->attr.st_mode)) {
                return NULL;
            }

            DevNode **node = this->children.find(name);
            if (node) {
                (*node)->ref();
                return (*node);
            }

            return NULL;
        }

        bool DevNode::add(VFS::INode *node) {
            NLib::ScopeSpinlock guard(&this->spin);

            if (!VFS::S_ISDIR(this->attr.st_mode)) {
                return false;
            }

            DevNode *dnode = (DevNode *)node;

            node->setparent(this);
            this->children.insert(dnode->name, dnode);
            return true;
        }

        bool DevNode::remove(const char *name) {
            NLib::ScopeSpinlock guard(&this->spin);

            if (!VFS::S_ISDIR(this->attr.st_mode)) {
                return false;
            }

            return this->children.remove(name);
        }


        int DevFileSystem::mount(const char *path) {
            (void)path;

            NLib::ScopeSpinlock guard(&this->spin);

            if (this->mounted) {
                return -EINVAL;
            }

            this->mounted = true;
            return 0;
        }

        int DevFileSystem::umount(void) {
            NLib::ScopeSpinlock guard(&this->spin);

            if (!this->mounted) {
                return -EINVAL;
            }

            delete this->root;

            this->root = NULL;
            return 0;
        }

        int DevFileSystem::sync(void) {
            return 0;
        }

        VFS::INode *DevFileSystem::create(const char *name, struct VFS::stat attr) {
            DevNode *dnode = new DevNode(this, name, attr);
            NDev::Device *dev = NDev::registry->get(attr.st_rdev);
            if (dev) {
                dnode->setdev(dev);
            } else {
                delete dnode; // Invalid node.
                return NULL;
            }
            return dnode;
        }
    }
}
