#ifdef __x86_64__
#include <arch/x86_64/cpu.hpp>
#endif
#include <fs/vfs.hpp>
#include <lib/errno.hpp>
#include <mm/ucopy.hpp>

namespace NFS {
    namespace VFS {
        VFS vfs = VFS();

        int VFS::mount(const char *path, IFileSystem *fs) {
            NLib::ScopeSpinlock guard(&this->mountlock);

            this->mounts.push((struct VFS::mntpoint) { path, fs, NULL });
            Path mntpath = Path(path);

            if (!mntpath.depth() && !this->root) { // Attempt to assign root if we haven't already.
                this->root = fs->getroot();
            }

            if (fs->mount(path) != 0) {
                this->umount(path);
                return -EINVAL;
            }
            return 0;
        }

        int VFS::umount(const char *path) {
            NLib::ScopeSpinlock guard(&this->mountlock);

            bool worked = this->mounts.remove([](struct mntpoint mnt, void *udata) {
                const char *p = (const char *)udata;
                if (!NLib::strcmp(mnt.path, p)) {
                    mnt.fs->umount();
                    return true;
                }
                return false;
            }, (void *)path);

            if (worked) {
                Path mntpath = Path(path);
                if (!mntpath.depth() && this->root) { // If this is assigned on the root, we should remove the root reference.
                    this->root = NULL;
                }
            }

            return worked ? 0 : -1;
        }

        struct VFS::mntpoint *VFS::findmount(Path *path) {
            struct mntpoint *best = NULL;
            size_t depth = 0;

            NLib::DoubleList<struct mntpoint>::Iterator it = this->mounts.begin();

            for (; it.valid(); it.next()) {
                Path mntpath = Path(it.get()->path);
                bool matches = true;
                NLib::DoubleList<const char *>::Iterator mpit = mntpath.iterator();
                NLib::DoubleList<const char *>::Iterator pit = path->iterator();

                size_t i = 0;
                for (; i < mntpath.depth(); pit.next(), mpit.next(), i++) {
                    if (i >= path->depth() || NLib::strcmp(*mpit.get(), *pit.get())) {
                        matches = false;
                        break;
                    }
                }

                // Handle special case of '/' mounting point.
                if (!mntpath.depth() && mntpath.isabsolute()) { // Mount path is probably '/'.
                    if (path->isabsolute()) { // Search path is probably '/'. Add it as a potential match.
                        best = it.get();
                        depth = 0;
                        continue;
                    }
                }

                if (matches && mntpath.depth() > depth) {
                    best = it.get();
                    depth = mntpath.depth();
                }
            }

            return best;
        }

        INode *VFS::resolve(const char *path, INode *relativeto, bool symlink) {
            Path rp = Path(path);

            if (!rp.depth()) { // Empty path, we're referring to our current directory.
                return relativeto ? relativeto : this->root; // If we're working relative to a specific directory, we should return it, otherwise, root.
            }

            if (!rp.isabsolute()) {
                INode *base = relativeto ? relativeto : this->root;

                // Prepend elements to construct an absolute path.
                while (base && base != this->root) {
                    rp.pushcomponent(base->getname(), false);
                    base = base->getparent();
                }

                rp.setabsolute();
            }

            Path pobj = Path(rp.construct()); // Forcibly collapse resultant path.

            struct mntpoint *mount = this->findmount(&pobj);
            if (!mount) {
                return NULL; // Path is invalid. No mountpoint handles this path.
            }

            Path mntpath = Path(mount->path);
            size_t skip = mntpath.depth(); // How many components of the main path should we skip to just get the path relative to the mount path?

            NLib::DoubleList<const char *>::Iterator it = pobj.iterator();
            for (size_t i = 0; i < skip && it.valid(); i++) {
                it.next(); // Skip over components relevant to the mount path.
            }

            INode *current = mount->fs->getroot();

            while (it.valid()) {
                if (!NLib::strcmp(*it.get(), "..")) {
                    INode *parent = current->getparent();

                    if (!parent) {
                        return NULL; // No parent. Failed.
                    }

                    current = parent;
                    it.next();
                    continue;
                }

                INode *next = current->lookup(*it.get());
                current->unref(); // Unreference old

                if (!next) {
                    return NULL;
                }

                it.next();
                current = next;
                if (symlink && S_ISLNK(current->getattr().st_mode)) { // If this node is a symbolic link.
                    current = current->resolvesymlink(); // Unwrap into real path.
                    if (!current) {
                        return NULL; // Invalid symbolic link.
                    }
                }
            }

            return current;
        }

        INode *VFS::create(const char *path, struct stat attr) {
            Path pobj = Path(path);

            if (!pobj.depth()) {
                return NULL; // Cannot create root.
            }

            const char *parentpath = pobj.dirname();
            INode *parent = this->resolve(parentpath);
            delete parentpath; // Caller is expected to free `dirname()`.
            if (!parent) {
                return NULL; // Parent doesn't already exist.
            }

            struct mntpoint *mount = this->findmount(&pobj);
            if (!mount) {
                return NULL; // Invalid mounting point.
            }

            INode *node = mount->fs->create(pobj.basename(), attr);
            parent->add(node);
            parent->unref();

            if (node) {
                node->unref();
            }

            return node;
        }

        int FileDescriptorTable::open(INode *node, int flags) {
            NLib::ScopeSpinlock guard(&this->lock);

            int fd = this->openfds.findfirst();
            if (fd == -1) {
                fd = this->openfds.getsize();
                if (fd + 32 > MAXFDS) {
                    return -EMFILE; // Too many open files.
                }

                if (!this->fds.resize(fd + 32)) {
                    return -ENOMEM;
                }

                if (!this->openfds.resize(fd + 32)) {
                    return -ENOMEM;
                }

                if (!this->closeonexec.resize(fd + 32)) {
                    return -ENOMEM;
                }
            }

            this->fds[fd] = new FileDescriptor(node, flags);
            if (!this->fds[fd]) {
                return -ENOMEM;
            }

            this->openfds.set(fd);
            return fd;
        }

        int FileDescriptorTable::close(int fd) {
            NLib::ScopeSpinlock guard(&this->lock);

            if (fd < 0 || fd >= (int)this->fds.getsize() || !this->fds[fd] || !this->openfds.test(fd)) {
                return -EBADF;
            }

            if (this->fds[fd]->unref() == 0) {
                delete this->fds[fd];
            }
            this->fds[fd] = NULL;
            this->openfds.clear(fd); // Mark as unallocated.
            this->closeonexec.clear(fd); // Mark as unallocated. If this was never set in the first place, nothing changes.
            return 0; // All went well.
        }

        int FileDescriptorTable::dup(int oldfd) {
            NLib::ScopeSpinlock guard(&this->lock);

            if (oldfd < 0 || oldfd >= (int)this->fds.getsize() || !this->fds[oldfd] || !this->openfds.test(oldfd)) {
                return -EBADF;
            }

            int newfd = this->openfds.findfirst();
            if (newfd == -1) { // None available. :broken_heart: emoji
                newfd = this->openfds.getsize(); // New FD will be the new bit from this resize. Simply saves another call to findfirst().
                if (newfd + 32 > MAXFDS) {
                    return -EMFILE; // Too many open files.
                }

                if (!this->fds.resize(newfd + 32)) { // Resize vector. It'll grow to accomodate the new data.

                    return -ENOMEM;
                }

                if (!this->openfds.resize(newfd + 32)) {
                    return -ENOMEM;
                }
                if (!this->closeonexec.resize(newfd + 32)) { // Both bitmaps needs to be maintained.
                    return -ENOMEM;
                }
            }

            this->fds[newfd] = this->fds[oldfd];
            this->fds[newfd]->ref(); // Increase reference count of descriptor. We're now referring to it by another additional FD.
            this->openfds.set(newfd); // Set bit to mark as allocated.
            return newfd;
        }

        int FileDescriptorTable::dup2(int oldfd, int newfd) {
            NLib::ScopeSpinlock guard(&this->lock);

            if (oldfd < 0 || oldfd >= (int)this->fds.getsize() || !this->fds[oldfd] || !this->openfds.test(oldfd)) { // Discard if we can tell that the FD is bad.
                return -EBADF;
            }

            if (newfd < 0 || newfd > MAXFDS) { // Discard if this is a negative. Positive FDs are still valid, because we can just expand the FD table. Arbitrary maximum is imposed to prevent rampant memory consumption.
                return -EBADF;
            }

            if (newfd >= (int)this->fds.getsize()) {
                if (!this->fds.resize(newfd + 1)) {
                    return -ENOMEM;
                }

                if (!this->openfds.resize(newfd + 1)) {
                    return -ENOMEM;
                }
                if (!this->closeonexec.resize(newfd + 1)) { // Both bitmaps needs to be maintained.
                    return -ENOMEM;
                }
            }

            if (this->openfds.test(newfd)) {
                if (this->fds[newfd]->unref() == 0) { // Decrement reference within our table.
                    delete fds[newfd];
                }
            }

            this->fds[newfd] = this->fds[oldfd];
            this->fds[newfd]->ref();
            this->openfds.set(newfd); // Occupy new FD.
            return newfd;
        }

        FileDescriptor *FileDescriptorTable::get(int fd) {
            NLib::ScopeSpinlock guard(&this->lock);

            NUtil::printf("FD: %d, %lu, %u.\n", fd, this->fds.getsize(), this->openfds.test(fd));
            if (fd < 0 || fd >= (int)this->fds.getsize() || !this->openfds.test(fd)) {
                // If the fd is negative, over our current maximum, or not currently allocated:
                return NULL;
            }
            return this->fds[fd]; // Otherwise: Return it.
        }

        FileDescriptorTable *FileDescriptorTable::fork(void) {
            NLib::ScopeSpinlock guard(&this->lock);

            FileDescriptorTable *newtable = new FileDescriptorTable();

            if (!newtable->fds.resize(this->fds.getsize()) || !newtable->openfds.resize(this->fds.getsize()) || !newtable->closeonexec.resize(this->fds.getsize())) { // Attempt to resize all tracking of FDs, failure returns NULL, and deletes the allocation (for the sake of memory usage).
                delete newtable;
                return NULL;
            }

            for (size_t i = 0; i < this->fds.getsize(); i++) {
                if (this->openfds.test(i)) { // There is an open FD, copy it.
                    newtable->fds[i] = this->fds[i]; // Copy reference.
                    newtable->fds[i]->ref(); // Increase refcount.
                    newtable->openfds.set(i); // Mark as allocated.
                    if (this->closeonexec.test(i)) { // If this is also marked as close on exec.
                        newtable->closeonexec.set(i); // Mark as allocated.
                    }
                } else {
                    this->openfds.clear(i);
                    this->closeonexec.clear(i);
                }
            }

            return newtable;
        }

        void FileDescriptorTable::doexec(void) {
            NLib::ScopeSpinlock guard(&this->lock);

            for (size_t i = 0; i < this->closeonexec.getsize(); i++) { // Effectively the same logic as closeall(), but we only close FDs marked as close-on-exec.
                if (this->closeonexec.test(i)) {
                    if (this->fds[i]->unref() == 0) {
                        delete this->fds[i];
                    }
                    this->fds[i] = NULL;
                }
            }
        }

        void FileDescriptorTable::closeall(void) {
            NLib::ScopeSpinlock guard(&this->lock);

            for (size_t i = 0; i < this->openfds.getsize(); i++) {
                if (this->openfds.test(i)) { // Allocated. Free associated if without reference.
                    if (this->fds[i]->unref() == 0) {
                        delete this->fds[i]; // Delete descriptor itself if we ran out of references.
                    }
                    this->fds[i] = NULL;
                }
            }
        }

        bool VFS::checkaccess(INode *node, int flags, uint32_t uid, uint32_t gid) {
            struct stat st = node->getattr();

            // Root always bypasses.
            if (uid == 0) {
                return true;
            }

            if ((flags & O_ACCMODE) == O_RDONLY || (flags & O_ACCMODE) == O_RDWR) {
                if (uid == st.st_uid) {
                    if (!(st.st_mode & S_IRUSR)) {
                        return false;
                    }
                } else if (gid == st.st_gid) {
                    if (!(st.st_mode & S_IRGRP)) {
                        return false;
                    }
                } else {
                    if (!(st.st_mode & S_IROTH)) {
                        return false;
                    }
                }
            }

            if ((flags & O_ACCMODE) == O_WRONLY || (flags & O_ACCMODE) == O_RDWR) {
                if (uid == st.st_uid) {
                    if (!(st.st_mode & S_IWUSR)) {
                        return false;
                    }
                } else if (gid == st.st_gid) {
                    if (!(st.st_mode & S_IWGRP)) {
                        return false;
                    }
                } else {
                    if (!(st.st_mode & S_IWOTH)) {
                        return false;
                    }
                }
            }

            if (flags & O_EXEC || S_ISDIR(st.st_mode)) {
                if (uid == st.st_uid) {
                    if (!(st.st_mode & S_IXUSR)) {
                        return false;
                    }
                } else if (gid == st.st_gid) {
                    if (!(st.st_mode & S_IXGRP)) {
                        return false;
                    }
                } else {
                    if (!(st.st_mode & S_IXOTH)) {
                        return false;
                    }
                }
            }

            return true;
        }

        extern "C" uint64_t sys_openat(int dirfd, const char *path, int flags, unsigned int mode) {
            NUtil::printf("sys_openat(%d, %s, %d, %u).\n", dirfd, path, flags, mode);

            ssize_t pathsize = NMem::UserCopy::strnlen(path, 1024); // XXX: Maximum path length.
            if (pathsize < 0) {
                return pathsize; // Contains errno.
            }

            char *pathbuf = new char[pathsize + 1];
            if (!pathbuf) {
                return -ENOMEM;
            }

            int ret = NMem::UserCopy::strncpy(pathbuf, path, pathsize);
            if (ret < 0) {
                delete[] pathbuf;
                return ret; // Contains errno.
            }

            pathbuf[pathsize] = '\0';

            INode *dirnode = NULL;

            NSched::Process *proc = NArch::CPU::get()->currthread->process;

            if (pathbuf[0] == '/') { // Absolute path invalidates dirfd.
                dirnode = vfs.getroot();
            } else {
                if (dirfd == AT_FDCWD) { // Special case: FD is CWD.
                    dirnode = proc->cwd;
                    if (!dirnode) { // If the process has no CWD, we use root.
                        dirnode = vfs.getroot();
                    } else {
                        dirnode->ref(); // Increase reference.
                    }
                } else {
                    FileDescriptor *desc = proc->fdtable->get(dirfd);
                    if (!desc) {
                        return -EBADF;
                    }

                    dirnode = desc->getnode();
                    if (!S_ISDIR(dirnode->getattr().st_mode)) {
                        dirnode->unref();
                        return -ENOTDIR;
                    }
                }
            }

            INode *node = vfs.resolve(pathbuf, dirnode, !(flags & O_NOFOLLOW));
            dirnode->unref();

            if (!node) { // Couldn't find it. Check if there's a reason to create it.
                if (!(flags & O_CREAT)) {
                    return -ENOENT; // Don't bother if there's no create flag.
                }
            }

            struct stat st = node->getattr();

            if ((flags & O_DIRECTORY) && !S_ISDIR(st.st_mode)) {
                node->unref();
                return -ENOTDIR;
            }

            if (!vfs.checkaccess(node, flags, proc->euid, proc->egid)) {
                node->unref();
                return -EACCES;
            }

            // if ((flags & O_TRUNC) && S_ISREG(st.st_mode)) {

            // }

            int fd = NArch::CPU::get()->currthread->process->fdtable->open(node, flags);
            node->unref(); // Unreference. FD table will handle the reference.

            return fd;
        }

        extern "C" uint64_t sys_close(int fd) {
            NUtil::printf("sys_close(%d).\n", fd);
            return 0;
        }

        extern "C" uint64_t sys_read(int fd, void *buf, size_t count) {
            NUtil::printf("sys_read(%d, %p, %lu).\n", fd, buf, count);
            return count;
        }

        extern "C" uint64_t sys_write(int fd, const void *buf, size_t count) {
            NUtil::printf("sys_write(%d, %p, %lu).\n", fd, buf, count);
            return count;
        }

        extern "C" uint64_t sys_seek(int fd, off_t off, int whence) {
            NUtil::printf("sys_seek(%d, %ld, %d).\n", fd, off, whence);
            return 0;
        }
    }
}
