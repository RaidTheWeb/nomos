#include <fs/devfs.hpp>
#include <mm/ucopy.hpp>

namespace NFS {
    namespace DEVFS {
        NArch::Spinlock devlock;
        NLib::DoubleList<struct regclass> registeredclasses;
        NLib::DoubleList<struct regdevfile> registered;
        NLib::DoubleList<DevFileSystem *> mountedinstances;

        void registerinstance(DevFileSystem *fs) {
            NLib::ScopeSpinlock guard(&devlock);
            mountedinstances.push(fs);
        }

        void unregisterinstance(DevFileSystem *fs) {
            NLib::ScopeSpinlock guard(&devlock);
            mountedinstances.remove([](DevFileSystem *inst, void *arg) {
                return inst == (DevFileSystem *)arg;
            }, (void *)fs);
        }

        struct regclass *findclass(const char *name) {
            // NOTE: Caller is expected to hold devlock.
            NLib::DoubleList<struct regclass>::Iterator it = registeredclasses.begin();
            while (it.valid()) {
                struct regclass *cls = it.get();
                if (!NLib::strcmp(cls->name, name)) {
                    return cls;
                }
                it.next();
            }
            return NULL;
        }

        void registerclass(const char *name) {
            NLib::ScopeSpinlock guard(&devlock);

            // Check if already registered.
            if (findclass(name)) {
                return;
            }

            struct regclass newclass {
                .name = NLib::strdup(name)
            };

            registeredclasses.push(newclass);

            // Propagate to all mounted instances.
            NLib::DoubleList<DevFileSystem *>::Iterator it = mountedinstances.begin();
            while (it.valid()) {
                DevFileSystem *fs = *it.get();
                fs->createclassnode(name);
                it.next();
            }
        }

        void unregisterclass(const char *name) {
            NLib::ScopeSpinlock guard(&devlock);

            // Remove from all mounted instances first.
            NLib::DoubleList<DevFileSystem *>::Iterator fsit = mountedinstances.begin();
            while (fsit.valid()) {
                DevFileSystem *fs = *fsit.get();
                fs->removeclassnode(name);
                fsit.next();
            }

            registeredclasses.remove([](struct regclass cls, void *arg) {
                if (!NLib::strcmp(cls.name, (const char *)arg)) {
                    delete[] cls.name;
                    return true;
                }
                return false;
            }, (void *)name);
        }

        void registerdevfile(const char *name, struct VFS::stat attr, const char *classname) {
            NLib::ScopeSpinlock guard(&devlock);

            struct regdevfile newdevfile {
                .name = NLib::strdup(name),
                .classname = classname ? NLib::strdup(classname) : NULL,
                .attr = attr
            };

            registered.push(newdevfile);

            // Propagate to all mounted instances.
            NLib::DoubleList<DevFileSystem *>::Iterator it = mountedinstances.begin();
            while (it.valid()) {
                DevFileSystem *fs = *it.get();
                fs->createdevnode(name, attr, classname);
                it.next();
            }
        }

        void unregisterdevfile(const char *name, const char *classname) {
            NLib::ScopeSpinlock guard(&devlock);

            // Remove from all mounted instances first.
            NLib::DoubleList<DevFileSystem *>::Iterator fsit = mountedinstances.begin();
            while (fsit.valid()) {
                DevFileSystem *fs = *fsit.get();
                fs->removedevnode(name, classname);
                fsit.next();
            }

            registered.remove([](struct regdevfile devfile, void *arg) {
                const char **args = (const char **)arg;
                const char *name = args[0];
                const char *classname = args[1];

                bool namematch = !NLib::strcmp(devfile.name, name);
                bool classmatch = (devfile.classname == NULL && classname == NULL) ||
                                  (devfile.classname && classname && !NLib::strcmp(devfile.classname, classname));

                if (namematch && classmatch) {
                    delete[] devfile.name;
                    if (devfile.classname) {
                        delete[] devfile.classname;
                    }
                    return true;
                }
                return false;
            }, (void *)(const char *[]){name, classname});
        }

        DevNode *lookupdevnode(const char *name, const char *classname) {
            NLib::ScopeSpinlock guard(&devlock);

            // Get the first mounted instance.
            if (mountedinstances.empty()) {
                return NULL;
            }

            DevFileSystem *fs = mountedinstances.front();
            DevNode *rootnode = (DevNode *)fs->getroot();

            DevNode *parentnode = rootnode;
            if (classname) {
                DevNode **classptr = rootnode->getchildren().find(classname);
                if (classptr) {
                    parentnode = *classptr;
                } else {
                    rootnode->unref();
                    return NULL;
                }
            }

            DevNode **nodeptr = parentnode->getchildren().find(name);
            rootnode->unref();

            if (nodeptr) {
                (*nodeptr)->ref();
                return *nodeptr;
            }
            return NULL;
        }

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
            NLib::ScopeIRQSpinlock guard(&this->metalock);

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
            NLib::ScopeIRQSpinlock guard(&this->metalock);

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

            // Iterate over children in this directory.
            NLib::HashMap<DevNode *>::Iterator it = this->children.begin();
            while (it.valid()) {
                DevNode *child = *it.value();
                const char *childname = it.key();

                if (curroffset >= (size_t)offset) {
                    if (bytesread + reclen > count) {
                        return bytesread;
                    }

                    struct VFS::stat childattr = child->getattr();
                    struct VFS::dirent *dentry = (struct VFS::dirent *)((uint8_t *)buf + bytesread);
                    dentry->d_ino = childattr.st_ino;
                    dentry->d_off = bytesread + reclen;
                    dentry->d_reclen = (uint16_t)reclen;
                    dentry->d_type = (childattr.st_mode & VFS::S_IFMT) >> 12;
                    NLib::memset(dentry->d_name, 0, sizeof(dentry->d_name));
                    NLib::strncpy(dentry->d_name, (char *)childname, sizeof(dentry->d_name) - 1);
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
                NLib::ScopeIRQSpinlock guard(&this->metalock);
                *st = this->attr;
                return 0;
            }

            int ret = this->device->driver->stat(this->attr.st_dev, st);
            if (ret == NOSTAT) {
                NLib::ScopeIRQSpinlock guard(&this->metalock);
                *st = this->attr;
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
            NLib::ScopeIRQSpinlock guard(&this->metalock);

            if (!VFS::S_ISDIR(this->attr.st_mode)) {
                return NULL;
            }

            // Nodes are created eagerly by registration functions, so just check the children map.
            DevNode **cached = this->children.find(name);
            if (cached && *cached) {
                (*cached)->ref();
                return (*cached);
            }

            return NULL;
        }

        bool DevNode::add(VFS::INode *node) {
            NLib::ScopeIRQSpinlock guard(&this->metalock);

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
            NLib::ScopeIRQSpinlock guard(&this->metalock);

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

            // Register this instance for automatic updates and populate with existing devices.
            registerinstance(this);

            // Populate with existing classes and devices.
            devlock.acquire();

            // First create all class directories.
            NLib::DoubleList<struct regclass>::Iterator clsit = registeredclasses.begin();
            while (clsit.valid()) {
                struct regclass *cls = clsit.get();
                DevNode *rootnode = (DevNode *)this->root;
                DevNode **existing = rootnode->getchildren().find(cls->name);
                if (!existing) {
                    struct VFS::stat attr {
                        .st_ino = this->nextinode++,
                        .st_mode = 0755 | VFS::S_IFDIR,
                    };
                    DevNode *classnode = new DevNode(this, cls->name, attr);
                    rootnode->add(classnode);
                }
                clsit.next();
            }

            // Then create all device file nodes.
            NLib::DoubleList<struct regdevfile>::Iterator devit = registered.begin();
            while (devit.valid()) {
                struct regdevfile *devfile = devit.get();
                DevNode *parentnode = (DevNode *)this->root;

                // If device has a class, find or create that class directory.
                if (devfile->classname) {
                    DevNode **classptr = parentnode->getchildren().find(devfile->classname);
                    if (classptr) {
                        parentnode = *classptr;
                    } else {
                        // Class directory doesn't exist yet, create it.
                        struct VFS::stat attr {
                            .st_ino = this->nextinode++,
                            .st_mode = 0755 | VFS::S_IFDIR,
                        };
                        DevNode *classnode = new DevNode(this, devfile->classname, attr);
                        ((DevNode *)this->root)->add(classnode);
                        parentnode = classnode;
                    }
                }

                // Check if device already exists in parent.
                DevNode **existingdev = parentnode->getchildren().find(devfile->name);
                if (!existingdev) {
                    struct VFS::stat attr = devfile->attr;
                    attr.st_ino = this->nextinode++;
                    DevNode *devnode = new DevNode(this, devfile->name, attr);
                    NDev::Device *dev = NDev::registry->get(attr.st_rdev);
                    if (dev) {
                        devnode->setdev(dev);
                    }
                    parentnode->add(devnode);
                }

                devit.next();
            }

            devlock.release();
            return 0;
        }

        DevFileSystem::~DevFileSystem(void) {
            unregisterinstance(this);
        }

        int DevFileSystem::umount(int flags) {
            (void)flags;
            NLib::ScopeSpinlock guard(&this->spin);

            if (!this->mounted) {
                return -EINVAL;
            }

            // Unregister before cleanup.
            unregisterinstance(this);

            delete this->root;

            this->root = NULL;
            this->mounted = false;
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
            } else {
                if (VFS::S_ISDIR(attr.st_mode)) {
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

        DevNode *DevFileSystem::createclassnode(const char *classname) {
            NLib::ScopeSpinlock guard(&this->spin);

            if (!this->root) {
                return NULL;
            }

            DevNode *rootnode = (DevNode *)this->root;
            DevNode **existing = rootnode->getchildren().find(classname);
            if (existing) {
                return *existing; // Already exists.
            }

            struct VFS::stat attr {
                .st_ino = this->nextinode++,
                .st_mode = 0755 | VFS::S_IFDIR,
            };
            DevNode *classnode = new DevNode(this, classname, attr);
            rootnode->add(classnode);
            return classnode;
        }

        void DevFileSystem::removeclassnode(const char *classname) {
            NLib::ScopeSpinlock guard(&this->spin);

            if (!this->root) {
                return;
            }

            DevNode *rootnode = (DevNode *)this->root;
            DevNode **existing = rootnode->getchildren().find(classname);
            if (existing) {
                DevNode *classnode = *existing;
                rootnode->remove(classname);
                delete classnode;
            }
        }

        DevNode *DevFileSystem::createdevnode(const char *name, struct VFS::stat attr, const char *classname) {
            NLib::ScopeSpinlock guard(&this->spin);

            if (!this->root) {
                return NULL;
            }

            DevNode *parentnode = (DevNode *)this->root;

            // If device has a class, find or create that class directory.
            if (classname) {
                DevNode **classptr = parentnode->getchildren().find(classname);
                if (classptr) {
                    parentnode = *classptr;
                } else {
                    // Class directory doesn't exist yet, create it.
                    struct VFS::stat classattr {
                        .st_ino = this->nextinode++,
                        .st_mode = 0755 | VFS::S_IFDIR,
                    };
                    DevNode *classnode = new DevNode(this, classname, classattr);
                    ((DevNode *)this->root)->add(classnode);
                    parentnode = classnode;
                }
            }

            // Check if device already exists in parent.
            DevNode **existingdev = parentnode->getchildren().find(name);
            if (existingdev) {
                return *existingdev; // Already exists.
            }

            attr.st_ino = this->nextinode++;
            DevNode *devnode = new DevNode(this, name, attr);
            NDev::Device *dev = NDev::registry->get(attr.st_rdev);
            if (dev) {
                devnode->setdev(dev);
            }
            parentnode->add(devnode);
            return devnode;
        }

        void DevFileSystem::removedevnode(const char *name, const char *classname) {
            NLib::ScopeSpinlock guard(&this->spin);

            if (!this->root) {
                return;
            }

            DevNode *parentnode = (DevNode *)this->root;

            // If device has a class, find that class directory.
            if (classname) {
                DevNode **classptr = parentnode->getchildren().find(classname);
                if (classptr) {
                    parentnode = *classptr;
                } else {
                    return; // Class doesn't exist, nothing to remove.
                }
            }

            DevNode **existing = parentnode->getchildren().find(name);
            if (existing) {
                DevNode *devnode = *existing;
                parentnode->remove(name);
                delete devnode;
            }
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

        static struct VFS::fsreginfo devtmpfsinfo = {
            .name = "devtmpfs" // Technically, this is an implementation of a devtmpfs.
        };

        REGFS(devfs, DevFileSystem::instance, &devfsinfo);
        REGFS(devtmpfs, DevFileSystem::instance, &devtmpfsinfo);
    }
}
