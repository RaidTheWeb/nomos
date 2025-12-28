#include <fs/devfs.hpp>
#include <mm/ucopy.hpp>

namespace NFS {
    namespace DEVFS {

        ssize_t DevNode::read(void *buf, size_t count, off_t offset, int fdflags) {
            if (!this->device) {
                return -ENODEV;
            }

            return this->device->driver->read(this->attr.st_rdev, buf, count, offset, fdflags);
        }

        ssize_t DevNode::write(const void *buf, size_t count, off_t offset, int fdflags) {
            if (!this->device) {
                return -ENODEV;
            }

            return this->device->driver->write(this->attr.st_rdev, buf, count, offset, fdflags);
        }

        ssize_t DevNode::readlink(char *buf, size_t bufsiz) {
            NLib::ScopeSpinlock guard(&this->metalock);

            if (!VFS::S_ISLNK(this->attr.st_mode)) {
                return -EINVAL;
            }

            if (!this->symlinktarget) {
                return -EINVAL;
            }

            size_t tocopy = NLib::strlen(this->symlinktarget);
            if (bufsiz < tocopy) {
                tocopy = bufsiz;
            }
            ssize_t res = NMem::UserCopy::copyto(buf, this->symlinktarget, tocopy);
            if (res < 0) {
                return res;
            }

            return tocopy;
        }

        ssize_t DevNode::readdir(void *buf, size_t count, off_t offset) {
            NLib::ScopeSpinlock guard(&this->metalock);

            if (!VFS::S_ISDIR(this->attr.st_mode)) {
                return -ENOTDIR;
            }

            size_t bytesread = 0;
            size_t curroffset = 0;
            size_t reclen = sizeof(struct VFS::dirent);

            // Add "." entry.
            if (curroffset >= (size_t)offset) {
                if (bytesread + reclen > count) {
                    return bytesread;
                }
                struct VFS::dirent *dentry = (struct VFS::dirent *)((uint8_t *)buf + bytesread);
                dentry->d_ino = this->attr.st_ino;
                dentry->d_off = bytesread + reclen;
                dentry->d_reclen = (uint16_t)reclen;
                dentry->d_type = VFS::S_IFDIR >> 12;
                NLib::memset(dentry->d_name, 0, sizeof(dentry->d_name));
                dentry->d_name[0] = '.';
                bytesread += reclen;
            }
            curroffset += reclen;

            // Add ".." entry.
            if (curroffset >= (size_t)offset) {
                if (bytesread + reclen > count) {
                    return bytesread;
                }
                struct VFS::dirent *dentry = (struct VFS::dirent *)((uint8_t *)buf + bytesread);

                INode *root = this->fs->getroot();
                if (root == this) {
                    dentry->d_ino = this->attr.st_ino; // Parent of root is root.
                } else if (this->parent) {
                    dentry->d_ino = this->parent->getattr().st_ino;
                } else {
                    dentry->d_ino = 0; // No parent.
                }
                root->unref();

                dentry->d_off = bytesread + reclen;
                dentry->d_reclen = (uint16_t)reclen;
                dentry->d_type = VFS::S_IFDIR >> 12;
                NLib::memset(dentry->d_name, 0, sizeof(dentry->d_name));
                dentry->d_name[0] = '.';
                dentry->d_name[1] = '.';
                bytesread += reclen;
            }
            curroffset += reclen;

            NLib::HashMap<DevNode *>::Iterator it = this->children.begin();
            while (it.valid()) {
                DevNode *child = *it.value();
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

        int DevNode::open(int flags) {
            if (!this->device) {
                return 0;
            }

            return this->device->driver->open(this->attr.st_rdev, flags);
        }

        int DevNode::close(int fdflags) {
            if (!this->device) {
                return 0;
            }

            return this->device->driver->close(this->attr.st_rdev, fdflags);
        }

        int DevNode::poll(short events, short *revents, int fdflags) {
            if (!this->device) {
                return -ENODEV;
            }

            return this->device->driver->poll(this->attr.st_rdev, events, revents, fdflags);
        }

        int DevNode::mmap(void *addr, size_t count, size_t offset, uint64_t flags, int fdflags) {
            if (!this->device) {
                return -ENODEV;
            }

            return this->device->driver->mmap(this->attr.st_rdev, addr, count, offset, flags, fdflags);
        }

        int DevNode::munmap(void *addr, size_t count, size_t offset, int fdflags) {
            if (!this->device) {
                return -ENODEV;
            }

            return this->device->driver->munmap(this->attr.st_rdev, addr, count, offset, fdflags);
        }

        int DevNode::ioctl(unsigned long request, uint64_t arg) {
            if (!this->device) {
                return -ENODEV;
            }

            return this->device->driver->ioctl(this->attr.st_rdev, request, arg);
        }

        int DevNode::stat(struct VFS::stat *st) {

            if (!this->device) {
                NLib::ScopeSpinlock guard(&this->metalock);
                *st = this->attr;
                return 0;
            }

            int ret = this->device->driver->stat(this->attr.st_dev, st);
            if (ret == NOSTAT) {
                this->metalock.acquire();
                *st = this->attr;
                this->metalock.release();
                return 0;
            }
            return ret;
        }

        VFS::INode *DevNode::resolvesymlink(void) {
            if (!VFS::S_ISLNK(this->attr.st_mode)) {
                return NULL;
            }

            if (!this->symlinktarget) {
                return NULL;
            }
            VFS::VFS *vfs = this->fs->getvfs();
            VFS::INode *node;
            ssize_t res = vfs->resolve(this->symlinktarget, &node, this->getparent(), false);
            if (res < 0) {
                return NULL;
            }
            return node;
        }

        VFS::INode *DevNode::lookup(const char *name) {
            NLib::ScopeSpinlock guard(&this->metalock);

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
            NLib::ScopeSpinlock guard(&this->metalock);

            if (!VFS::S_ISDIR(this->attr.st_mode)) {
                return false;
            }

            DevNode *dnode = (DevNode *)node;

            node->setparent(this);
            this->children.insert(dnode->getname(), dnode);

            // If adding a directory, increment parent's st_nlink for the '..' entry.
            if (VFS::S_ISDIR(node->getattr().st_mode)) {
                this->attr.st_nlink++;
            }

            return true;
        }

        bool DevNode::remove(const char *name) {
            NLib::ScopeSpinlock guard(&this->metalock);

            if (!VFS::S_ISDIR(this->attr.st_mode)) {
                return false;
            }

            // Need to check if we're removing a directory to decrement st_nlink.
            DevNode **child = this->children.find(name);
            if (child && VFS::S_ISDIR((*child)->attr.st_mode)) {
                // Removing a directory, decrement parent's st_nlink for the '..' entry.
                if (this->attr.st_nlink > 0) {
                    this->attr.st_nlink--;
                }
            }

            return this->children.remove(name);
        }


        int DevFileSystem::mount(const char *src, const char *path, VFS::INode *mntnode, uint64_t flags, const void *data) {
            (void)src;
            (void)path;
            (void)flags;
            (void)data;

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

        int DevFileSystem::umount(int flags) {
            (void)flags;
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

        ssize_t DevFileSystem::create(const char *name, VFS::INode **nodeout, struct VFS::stat attr) {
            NLib::ScopeSpinlock guard(&this->spin);
            attr.st_ino = this->nextinode++;

            DevNode *dnode = new DevNode(this, name, attr);
            NDev::Device *dev = NDev::registry->get(attr.st_rdev);
            if (dev) {
                dnode->setdev(dev);
                dev->ifnode = dnode; // Give device a reference to the node it is connected to.
            } else {
                if (VFS::S_ISDIR(attr.st_mode)) {
                    NUtil::printf("devfs: Creating directory node `%s` without associated device.\n", name);
                    // Directories can exist without devices.
                    *nodeout = dnode;
                    return 0;
                }
                delete dnode; // Invalid node.
                return -EINVAL;
            }
            *nodeout = dnode;
            return 0;
        }

        int DevFileSystem::unlink(VFS::INode *node, VFS::INode *parent) {
            uint64_t ino = node->getattr().st_ino;

            // Remove from parent.
            bool worked = parent->remove(node->getname());
            parent->unref();
            node->unref(); // Drop our reference.

            if (!worked) {
                return -EINVAL; // Removal failed.
            }

            ssize_t res = node->unlink(); // Returns 0 if we're good to delete the node.
            if (res == 0) {
                delete node; // Delete the node.
            }
            return 0;
        }

        static struct VFS::fsreginfo devfsinfo = {
            .name = "devfs"
        };

        REGFS(devfs, DevFileSystem::instance, &devfsinfo);
    }
}
