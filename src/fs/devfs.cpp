#include <fs/devfs.hpp>

namespace NFS {
    namespace DEVFS {

        ssize_t DevNode::read(void *buf, size_t count, off_t offset, int fdflags) {
            NLib::ScopeSpinlock guard(&this->spin);

            if (!this->device) {
                return -ENODEV;
            }

            return this->device->driver->read(this->attr.st_rdev, buf, count, offset, fdflags);
        }

        ssize_t DevNode::write(const void *buf, size_t count, off_t offset, int fdflags) {
            NLib::ScopeSpinlock guard(&this->spin);

            if (!this->device) {
                return -ENODEV;
            }

            return this->device->driver->write(this->attr.st_rdev, buf, count, offset, fdflags);
        }

        int DevNode::open(int flags) {
            NLib::ScopeSpinlock guard(&this->spin);

            if (!this->device) {
                return -ENODEV;
            }

            return this->device->driver->open(this->attr.st_rdev, flags);
        }

        int DevNode::close(int fdflags) {
            NLib::ScopeSpinlock guard(&this->spin);

            if (!this->device) {
                return -ENODEV;
            }

            return this->device->driver->close(this->attr.st_rdev, fdflags);
        }

        int DevNode::mmap(void *addr, size_t offset, uint64_t flags, int fdflags) {
            NLib::ScopeSpinlock guard(&this->spin);

            if (!this->device) {
                return -ENODEV;
            }

            return this->device->driver->mmap(this->attr.st_rdev, addr, offset, flags, fdflags);
        }

        int DevNode::munmap(void *addr, int fdflags) {
            NLib::ScopeSpinlock guard(&this->spin);

            if (!this->device) {
                return -ENODEV;
            }

            return this->device->driver->munmap(this->attr.st_rdev, addr, fdflags);
        }

        int DevNode::ioctl(unsigned long request, uint64_t arg) {
            NLib::ScopeSpinlock guard(&this->spin);

            if (!this->device) {
                return -ENODEV;
            }

            return this->device->driver->ioctl(this->attr.st_rdev, request, arg);
        }

        int DevNode::stat(struct VFS::stat *st) {
            NLib::ScopeSpinlock guard(&this->spin);
            if (!this->device) {
                return -ENODEV;
            }

            int ret = this->device->driver->stat(this->attr.st_dev, st);
            if (ret == NOSTAT) { // XXX: Make constant. Specific error code so that the device node knows to retrieve its stat attributes instead of the driver.
                *st = this->attr;
                return 0;
            }
            return ret;
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
                dev->ifnode = dnode; // Give device a reference to the node it is connected to.
            } else {
                delete dnode; // Invalid node.
                return NULL;
            }
            return dnode;
        }
    }
}
