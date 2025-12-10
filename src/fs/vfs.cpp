#ifdef __x86_64__
#include <arch/x86_64/cpu.hpp>
#endif
#include <fs/pipefs.hpp>
#include <fs/vfs.hpp>
#include <lib/errno.hpp>
#include <mm/ucopy.hpp>
#include <sys/syscall.hpp>

namespace NFS {
    namespace VFS {
        VFS vfs = VFS();

        int VFS::mount(const char *path, IFileSystem *fs) {
            INode *mntnode = NULL;
            Path mntpath = Path(path);

            // Resolve the mountpoint node (except for root mount).
            if (mntpath.depth() > 0) {
                ssize_t ret = this->resolve(path, &mntnode, NULL, true);
                if (ret < 0) {
                    return ret; // Mountpoint doesn't exist.
                }
            }

            {
                NLib::ScopeSpinlock guard(&this->mountlock);
                this->mounts.push((struct VFS::mntpoint) { path, fs, mntnode });

                if (!mntpath.depth() && !this->root) { // Attempt to assign root if we haven't already.
                    this->root = fs->getroot();
                }
            }

            if (fs->mount(path, mntnode) != 0) {
                this->umount(path);
                if (mntnode) {
                    mntnode->unref();
                }
                return -EINVAL;
            }
            return 0;
        }

        int VFS::umount(const char *path) {
            struct umount_ud {
                const char *match;
                IFileSystem *fs;
                size_t depth;
                bool found;
            } ud = { path, NULL, 0, false };

            {
                NLib::ScopeSpinlock guard(&this->mountlock);

                bool worked = this->mounts.remove([](struct mntpoint mnt, void *udata) {
                    struct umount_ud *u = (struct umount_ud *)udata;
                    if (!NLib::strcmp(mnt.path, u->match)) {
                        u->fs = mnt.fs;
                        Path mntpath = Path(mnt.path);
                        u->depth = mntpath.depth();
                        u->found = true;
                        return true;
                    }
                    return false;
                }, (void *)&ud);

                if (ud.found) {
                    if (!ud.depth && this->root) { // If this was the root mount, clear root reference.
                        this->root = NULL;
                    }
                }

                if (!ud.found) {
                    return -1;
                }
            }

            if (ud.fs) {
                ud.fs->umount();
            }

            return 0;
        }

        struct VFS::mntpoint *VFS::findmount(Path *path) {
            NLib::ScopeSpinlock guard(&this->mountlock);
            // Find the best matching mount point for the given path.
            // The best matching mount point is the one with the longest matching prefix.
            // However, we must consider mounting points shadowed by others.

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

                if (!mntpath.depth() && mntpath.isabsolute() && path->isabsolute()) {
                    matches = true;
                }

                if (matches && mntpath.depth() >= depth) {
                    best = it.get();
                    depth = mntpath.depth();
                }
            }

            return best;
        }

        ssize_t VFS::resolve(const char *path, INode **nodeout, INode *relativeto, bool symlink) {
            constexpr size_t MAX_SYMLINK_DEPTH = 40;

            Path rp = Path(path);

            if (!rp.depth()) { // Empty path, we're referring to our current directory.
                INode *result = relativeto ? relativeto : this->root;
                if (result) {
                    result->ref(); // Caller expects a referenced node.
                } else {
                    return -ENOENT;
                }

                *nodeout = result;
                return 0;
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

            const char *rpstr = rp.construct();
            Path pobj = Path(rpstr); // Forcibly collapse resultant path.
            delete[] rpstr;

            struct mntpoint *mount = this->findmount(&pobj);
            if (!mount) {
                return -ENOENT; // Path is invalid. No mountpoint handles this path.
            }

            Path mntpath = Path(mount->path);
            size_t skip = mntpath.depth(); // How many components of the main path should we skip to just get the path relative to the mount path?

            NLib::DoubleList<const char *>::Iterator it = pobj.iterator();
            for (size_t i = 0; i < skip && it.valid(); i++) {
                it.next(); // Skip over components relevant to the mount path.
            }

            INode *current = mount->fs->getroot();
            size_t symlink_depth = 0; // Track symlink resolution depth to prevent infinite loops.

            while (it.valid()) {
                if (!NLib::strcmp(*it.get(), "..")) {
                    INode *parent = current->getparent();

                    if (!parent) {
                        current->unref(); // Clean up before returning.
                        return -ENOENT; // No parent. Failed.
                    }

                    parent->ref(); // Increment refcount for parent.
                    current->unref(); // Unreference old current.
                    current = parent;
                    it.next();
                    continue;
                }

                // Check that we have search permission on the current node.
                if (!this->checkaccess(current, O_RDONLY | O_EXEC, 0, 0)) {
                    current->unref();
                    return -EACCES;
                }

                INode *next = current->lookup(*it.get());
                current->unref(); // Unreference old

                if (!next) {
                    return -ENOENT;
                }

                it.next();
                current = next;
                if (symlink && S_ISLNK(current->getattr().st_mode)) { // If this node is a symbolic link.
                    if (symlink_depth >= MAX_SYMLINK_DEPTH) {
                        current->unref();
                        return -ELOOP; // Too many levels of symbolic links.
                    }
                    INode *resolved = current->resolvesymlink();
                    if (!resolved) {
                        current->unref();
                        return -ENOENT; // Invalid symbolic link.
                    }
                    current->unref(); // Unreference the symlink node.
                    current = resolved; // Resolved already has refcount from resolvesymlink.
                    symlink_depth++;

                    while (!it.valid() && S_ISLNK(current->getattr().st_mode)) {
                        if (symlink_depth >= MAX_SYMLINK_DEPTH) {
                            current->unref();
                            return -ELOOP; // Too many levels of symbolic links.
                        }
                        INode *nextresolved = current->resolvesymlink();
                        if (!nextresolved) {
                            current->unref();
                            return -ENOENT;
                        }
                        current->unref();
                        current = nextresolved;
                        symlink_depth++;
                    }
                }
            }

            *nodeout = current;
            return 0;
        }

        INode *VFS::create(const char *path, struct stat attr) {
            Path pobj = Path(path);

            if (!pobj.depth()) {
                return NULL; // Cannot create root.
            }

            const char *parentpath = pobj.dirname();
            INode *parent;
            ssize_t res = this->resolve(parentpath, &parent);
            delete parentpath; // Caller is expected to free `dirname()`.
            if (res < 0) {
                return NULL; // Parent doesn't already exist.
            }

            struct mntpoint *mount = this->findmount(&pobj);
            if (!mount) {
                parent->unref(); // Don't leak parent reference.
                return NULL; // Invalid mounting point.
            }

            INode *node = mount->fs->create(pobj.basename(), attr);
            if (!node) {
                parent->unref();
                return NULL; // Creation failed.
            }
            parent->add(node);
            parent->unref();

            return node;
        }

        int VFS::unlink(const char *path, INode *relativeto, int flags, int uid, int gid) {
            Path pobj = Path(path);

            if (!pobj.depth()) {
                return -EINVAL; // Cannot unlink root.
            }

            // Resolve the node to unlink.
            INode *node = NULL;
            ssize_t res = this->resolve(path, &node, relativeto, true);
            if (res < 0) {
                return res; // Failed to resolve path.
            }

            // Get parent directory.
            INode *parent = node->getparent();
            if (!parent) {
                node->unref();
                return -EINVAL; // Cannot unlink root node.
            }
            parent->ref();

            // Check if we're trying to unlink a directory.
            struct stat st = node->getattr();
            if (S_ISDIR(st.st_mode)) {
                if (!(flags & AT_REMOVEDIR)) {
                    // Trying to unlink a directory without AT_REMOVEDIR flag.
                    parent->unref();
                    node->unref();
                    return -EISDIR;
                }
                if (!node->empty()) {
                    // Directory is not empty.
                    parent->unref();
                    node->unref();
                    return -ENOTEMPTY;
                }
            } else {
                if (flags & AT_REMOVEDIR) {
                    // AT_REMOVEDIR specified but target is not a directory.
                    parent->unref();
                    node->unref();
                    return -ENOTDIR;
                }
            }

            if (!this->checkaccess(parent, O_RDWR | O_EXEC, uid, gid)) {
                parent->unref();
                node->unref();
                return -EACCES; // No write/search permission on parent directory.
            }

            // Find the mountpoint for this path to call filesystem-specific unlink.
            struct mntpoint *mount = this->findmount(&pobj);
            if (!mount) {
                parent->unref();
                node->unref();
                return -EINVAL; // Invalid mounting point.
            }

            // Call filesystem-specific unlink.
            const char *pathstr = pobj.construct();
            int ret = mount->fs->unlink(pathstr);
            delete[] pathstr;

            parent->unref();
            node->unref();

            return ret;
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

            if (flags & O_CLOEXEC) {
                this->closeonexec.set(fd);
            }

            this->openfds.set(fd);
            return fd;
        }

        void FileDescriptorTable::reserve(int fd, INode *node, int flags) {
            NLib::ScopeSpinlock guard(&this->lock);

            this->fds[fd] = new FileDescriptor(node, flags);
            if (!this->fds[fd]) {
                return;
            }

            this->openfds.set(fd);
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

        int FileDescriptorTable::dup2(int oldfd, int newfd, bool fcntl) {
            NLib::ScopeSpinlock guard(&this->lock);

            if (oldfd < 0 || oldfd >= (int)this->fds.getsize() || !this->fds[oldfd] || !this->openfds.test(oldfd)) { // Discard if we can tell that the FD is bad.
                return -EBADF;
            }

            if (fcntl) {
                if (newfd < 0) {
                    return -EINVAL;
                }

                // Find lowest-numbered available fd >= newfd.
                int candidate = -1;
                for (int i = newfd; i < (int)this->openfds.getsize(); i++) {
                    if (!this->openfds.test(i)) {
                        candidate = i;
                        break;
                    }
                }

                if (candidate == -1) {
                    candidate = this->openfds.getsize();
                    if (candidate + 32 > MAXFDS) {
                        return -EMFILE;
                    }

                    if (!this->fds.resize(candidate + 32)) {
                        return -ENOMEM;
                    }

                    if (!this->openfds.resize(candidate + 32)) {
                        return -ENOMEM;
                    }

                    if (!this->closeonexec.resize(candidate + 32)) {
                        return -ENOMEM;
                    }
                }

                this->fds[candidate] = this->fds[oldfd];
                this->fds[candidate]->ref();
                this->openfds.set(candidate);
                return candidate;
            }

            // Non-fcntl (dup2) semantics: newfd is exact target.
            if (newfd < 0 || newfd > MAXFDS) { // Discard if this is a negative. Positive FDs are still valid, because we can just expand the FD table. Arbitrary maximum is imposed to prevent rampant memory consumption.
                return -EBADF;
            }

            if (oldfd == newfd) {
                return newfd; // Don't even bother.
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

            bool stdstream = (newfd == NSched::STDIN_FILENO) || (newfd == NSched::STDOUT_FILENO) || (newfd == NSched::STDERR_FILENO);

            if (this->openfds.test(newfd) && !stdstream) { // Don't bother closing original file descriptor if its a standard stream.
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

                    INode *node = newtable->fds[i]->getnode();
                    if (S_ISFIFO(node->getattr().st_mode)) {
                        // Pipes get special treatment, and need to have open called on them again to update reader/writer counts.
                        node->open(newtable->fds[i]->getflags());
                    }
                    node->unref();

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

        bool FileDescriptorTable::iscloseonexec(int fd) {
            NLib::ScopeSpinlock guard(&this->lock);

            if (fd < 0 || fd >= (int)this->fds.getsize() || !this->openfds.test(fd)) {
                return false;
            }

            return this->closeonexec.test(fd);
        }

        void FileDescriptorTable::setcloseonexec(int fd, bool closeit) {
            NLib::ScopeSpinlock guard(&this->lock);

            if (fd < 0 || fd >= (int)this->fds.getsize() || !this->openfds.test(fd)) {
                return;
            }

            if (closeit) {
                this->closeonexec.set(fd);
            } else {
                this->closeonexec.clear(fd);
            }
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
            SYSCALL_LOG("sys_openat(%d, %s, %d, %u).\n", dirfd, path, flags, mode);

            ssize_t pathsize = NMem::UserCopy::strnlen(path, 1024); // XXX: Maximum path length.
            if (pathsize < 0) {
                SYSCALL_RET(pathsize); // Contains errno.
            }

            char *pathbuf = new char[pathsize + 1];
            if (!pathbuf) {
                SYSCALL_RET(-ENOMEM);
            }

            int ret = NMem::UserCopy::strncpyfrom(pathbuf, path, pathsize);
            if (ret < 0) {
                delete[] pathbuf;
                SYSCALL_RET(ret); // Contains errno.
            }

            pathbuf[pathsize] = '\0';

            INode *dirnode = NULL;

            NSched::Process *proc = NArch::CPU::get()->currthread->process;
            NLib::ScopeIRQSpinlock guard(&proc->lock);

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
                        delete[] pathbuf;
                        SYSCALL_RET(-EBADF);
                    }

                    dirnode = desc->getnode();
                    if (!S_ISDIR(dirnode->getattr().st_mode)) {
                        dirnode->unref();
                        delete[] pathbuf;
                        SYSCALL_RET(-ENOTDIR);
                    }
                }
            }

            INode *node;
            ssize_t res = vfs.resolve(pathbuf, &node, dirnode, !(flags & O_NOFOLLOW));
            dirnode->unref();
            if (res == -EACCES) { // We don't have permission to traverse the path.
                delete[] pathbuf;
                SYSCALL_RET(-EACCES); // Propagate access error.
            }

            if (res != 0) { // Couldn't find it. Check if there's a reason to create it.
                if (!(flags & O_CREAT)) {
                    delete[] pathbuf;
                    SYSCALL_RET(res); // Don't bother if there's no create flag.
                }
                // Create the node.
                struct stat attr = { 0 };
                attr.st_mode = mode;
                node = vfs.create(pathbuf, attr);
                if (res != 0) {
                    delete[] pathbuf;
                    SYSCALL_RET(-EIO); // Generic I/O error.
                }
            }

            delete[] pathbuf;

            struct stat st = node->getattr();

            if ((flags & O_DIRECTORY) && !S_ISDIR(st.st_mode)) { // If we're supposed to open a directory, we'd have to verify that the node is a directory.
                node->unref();
                SYSCALL_RET(-ENOTDIR);
            }

            if ((flags & O_RDWR) && S_ISFIFO(st.st_mode)) { // Can't open FIFOs in read-write mode.
                node->unref();
                SYSCALL_RET(-EINVAL);
            }

            if (!vfs.checkaccess(node, flags, proc->euid, proc->egid)) { // Check if current process' effective UID and GID are valid for access the node in this way.
                node->unref();
                SYSCALL_RET(-EACCES);
            }

            int accmode = flags & O_ACCMODE;

            switch (accmode) {
                case O_RDONLY:
                    if (flags & O_TRUNC) {
                        node->unref();
                        SYSCALL_RET(-EINVAL); // Can't truncate without write access.
                    }
                    break;
                case O_WRONLY:
                case O_RDWR:
                    if (S_ISDIR(st.st_mode)) {
                        node->unref();
                        SYSCALL_RET(-EISDIR); // Can't write to directory.
                    }
                    break;
                default:
                    node->unref();
                    SYSCALL_RET(-EINVAL);
            }

            // if ((flags & O_TRUNC) && S_ISREG(st.st_mode)) {

            // }

            int fd = proc->fdtable->open(node, flags);
            node->open(flags); // Trigger open hook.
            node->unref(); // Unreference. FD table will handle the reference.

            SYSCALL_RET(fd);
        }

        extern "C" uint64_t sys_dup(int fd, int flags) {
            SYSCALL_LOG("sys_dup(%d, %d).\n", fd, flags);

            NSched::Process *proc = NArch::CPU::get()->currthread->process;

            SYSCALL_RET(proc->fdtable->dup(fd));
        }

        extern "C" uint64_t sys_dup2(int fd, int flags, int newfd) {
            SYSCALL_LOG("sys_dup2(%d, %d, %d).\n", fd, flags, newfd);

            NSched::Process *proc = NArch::CPU::get()->currthread->process;

            SYSCALL_RET(proc->fdtable->dup2(fd, newfd));
        }

        extern "C" uint64_t sys_close(int fd) {
            SYSCALL_LOG("sys_close(%d).\n", fd);

            if (fd < 0) {
                SYSCALL_RET(-EBADF);
            }

            if (fd == NSched::STDIN_FILENO || fd == NSched::STDOUT_FILENO || fd == NSched::STDERR_FILENO) {
                SYSCALL_RET(0); // Refuse to close standard streams.
            }

            NSched::Process *proc = NArch::CPU::get()->currthread->process;

            FileDescriptor *desc = proc->fdtable->get(fd);
            if (!desc) {
                SYSCALL_RET(-EBADF);
            }

            INode *node = desc->getnode();
            int res = node->close(desc->getflags()); // Trigger close hook.
            node->unref();
            if (res < 0) {
                SYSCALL_RET(res);
            }

            res = proc->fdtable->close(fd);
            if (res < 0) {
                SYSCALL_RET(res);
            }

            SYSCALL_RET(0);
        }

        extern "C" uint64_t sys_getdents(int fd, void *buf, size_t count) {
            SYSCALL_LOG("sys_getdents(%d, %p, %lu).\n", fd, buf, count);

            if (fd < 0) {
                SYSCALL_RET(-EBADF);
            }

            if (!buf && count > 0) {
                SYSCALL_RET(-EFAULT);
            }

            if (!NMem::UserCopy::valid(buf, count)) {
                SYSCALL_RET(-EFAULT); // Invalid buffer.
            }

            NSched::Process *proc = NArch::CPU::get()->currthread->process;

            FileDescriptor *desc = proc->fdtable->get(fd);
            if (!desc) {
                SYSCALL_RET(-EBADF);
            }

            INode *node = desc->getnode();

            struct stat st = node->getattr();
            if (!S_ISDIR(st.st_mode)) {
                node->unref();
                SYSCALL_RET(-ENOTDIR);
            }

            ssize_t read = node->readdir(buf, count, desc->getoff());
            node->unref();
            if (read < 0) {
                SYSCALL_RET(read); // Return error code.
            }

            desc->addoff(read); // Increment offset.

            SYSCALL_RET(read); // Return the actual number of bytes read.
        }

        extern "C" uint64_t sys_fchdir(int fd) {
            SYSCALL_LOG("sys_fchdir(%d).\n", fd);

            if (fd < 0) {
                SYSCALL_RET(-EBADF);
            }

            NSched::Process *proc = NArch::CPU::get()->currthread->process;
            NLib::ScopeIRQSpinlock guard(&proc->lock);

            FileDescriptor *desc = proc->fdtable->get(fd);
            if (!desc) {
                SYSCALL_RET(-EBADF);
            }

            INode *node = desc->getnode();

            struct stat st = node->getattr();
            if (!S_ISDIR(st.st_mode)) {
                node->unref();
                SYSCALL_RET(-ENOTDIR);
            }

            if (proc->cwd) {
                proc->cwd->unref(); // Unreference old CWD.
            }
            proc->cwd = node; // Set new CWD.
            SYSCALL_RET(0);
        }

        extern "C" uint64_t sys_chdir(const char *path) {
            SYSCALL_LOG("sys_chdir(%s).\n", path);

            ssize_t pathsize = NMem::UserCopy::strnlen(path, 1024); // XXX: Maximum path length.
            if (pathsize < 0) {
                SYSCALL_RET(pathsize); // Contains errno.
            }

            char *pathbuf = new char[pathsize + 1];
            if (!pathbuf) {
                SYSCALL_RET(-ENOMEM);
            }

            int ret = NMem::UserCopy::strncpyfrom(pathbuf, path, pathsize);
            if (ret < 0) {
                delete[] pathbuf;
                SYSCALL_RET(ret); // Contains errno.
            }

            pathbuf[pathsize] = '\0';

            NSched::Process *proc = NArch::CPU::get()->currthread->process;

            NLib::ScopeIRQSpinlock guard(&proc->lock);

            INode *node;
            ssize_t res = vfs.resolve(pathbuf, &node, proc->cwd, true);
            delete[] pathbuf;

            if (res < 0) {
                SYSCALL_RET(res);
            }

            struct stat st = node->getattr();
            if (!S_ISDIR(st.st_mode)) {
                node->unref();
                SYSCALL_RET(-ENOTDIR);
            }

            if (proc->cwd) {
                proc->cwd->unref(); // Unreference old CWD.
            }
            proc->cwd = node; // Set new CWD.
            SYSCALL_RET(0);
        }

        extern "C" uint64_t sys_getcwd(char *buf, size_t size) {
            SYSCALL_LOG("sys_getcwd(%p, %lu).\n", buf, size);

            if (!buf || size == 0) {
                SYSCALL_RET(-EINVAL);
            }

            if (!NMem::UserCopy::valid(buf, size)) {
                SYSCALL_RET(-EFAULT);
            }

            NSched::Process *proc = NArch::CPU::get()->currthread->process;
            NLib::ScopeIRQSpinlock guard(&proc->lock);

            INode *cwd = proc->cwd;
            if (!cwd) {
                cwd = vfs.getroot(); // getroot() increments refcount.
                if (!cwd) {
                    SYSCALL_RET(-ENOENT);
                }
            } else {
                cwd->ref(); // Increase reference for our use.
            }

            // Build path by walking up the parent chain to root.
            Path resultpath = Path(true); // Start with absolute path.
            INode *current = cwd;
            INode *root = vfs.getroot(); // getroot() increments refcount.

            while (current && current != root) {
                const char *name = current->getname();
                if (name && name[0] != '\0') {
                    resultpath.pushcomponent(name, false); // Push to front (we're walking backwards).
                }
                INode *parent = current->getparent();

                if (!parent) {
                    // Reached root without finding VFS root - this shouldn't happen.
                    current->unref();
                    root->unref();
                    SYSCALL_RET(-ENOENT);
                }

                parent->ref(); // Increment parent refcount.
                current->unref(); // Decrement current refcount.
                current = parent;
            }

            // Clean up remaining references.
            if (current) {
                current->unref();
            }
            root->unref();

            const char *pathstr = resultpath.construct();
            if (!pathstr) {
                SYSCALL_RET(-ENOMEM);
            }

            size_t pathlen = NLib::strlen(pathstr);
            if (pathlen + 1 > size) {
                delete[] pathstr;
                SYSCALL_RET(-ERANGE);
            }

            // Copy to userspace.
            int ret = NMem::UserCopy::copyto(buf, pathstr, pathlen + 1);
            delete[] pathstr;

            if (ret < 0) {
                SYSCALL_RET(ret);
            }

            SYSCALL_RET((uint64_t)buf); // Return the buffer pointer on success.
        }

        extern "C" uint64_t sys_read(int fd, void *buf, size_t count) {
            SYSCALL_LOG("sys_read(%d, %p, %lu).\n", fd, buf, count);
            if (fd < 0) {
                SYSCALL_RET(-EBADF);
            }

            if (!buf && count > 0) {
                SYSCALL_RET(-EFAULT);
            }

            if (!NMem::UserCopy::valid(buf, count)) {
                SYSCALL_RET(-EFAULT); // Invalid buffer.
            }

            NSched::Process *proc = NArch::CPU::get()->currthread->process;

            FileDescriptor *desc = proc->fdtable->get(fd);
            if (!desc) {
                SYSCALL_RET(-EBADF);
            }

            int accmode = desc->getflags() & O_ACCMODE;

            if (accmode != O_RDONLY && accmode != O_RDWR) {
                SYSCALL_RET(-EBADF); // Not open for read.
            }

            INode *node = desc->getnode();

            struct stat st = node->getattr();

            if (S_ISDIR(st.st_mode)) {
                node->unref();
                SYSCALL_RET(-EISDIR);
            }

            if (S_ISLNK(st.st_mode)) {
                node->unref();
                SYSCALL_RET(-EINVAL);
            }

            ssize_t read = node->read(buf, count, desc->getoff(), desc->getflags());
            node->unref();
            if (read < 0) {
                SYSCALL_RET(read); // Return error code.
            }

            desc->addoff(read); // Increment offset.

            SYSCALL_RET(read); // Return the actual number of bytes read.
        }

        extern "C" uint64_t sys_write(int fd, const void *buf, size_t count) {
            SYSCALL_LOG("sys_write(%d, %p, %lu).\n", fd, buf, count);

            if (fd < 0) {
                SYSCALL_RET(-EBADF);
            }

            if (!buf && count > 0) {
                SYSCALL_RET(-EFAULT);
            }

            if (!NMem::UserCopy::valid(buf, count)) {
                SYSCALL_RET(-EFAULT); // Invalid buffer.
            }

            NSched::Process *proc = NArch::CPU::get()->currthread->process;

            FileDescriptor *desc = proc->fdtable->get(fd);
            if (!desc) {
                SYSCALL_RET(-EBADF);
            }

            int accmode = desc->getflags() & O_ACCMODE;

            if (accmode != O_WRONLY && accmode != O_RDWR) {
                SYSCALL_RET(-EBADF);
            }

            INode *node = desc->getnode();
            struct stat st = node->getattr();
            if (S_ISDIR(st.st_mode)) {
                node->unref();
                SYSCALL_RET(-EISDIR);
            }

            uint64_t wroff = desc->getoff();
            if (desc->getflags() & O_APPEND) {
                wroff = st.st_size; // We should begin at the end of the file.
            }

            ssize_t written = node->write(buf, count, wroff, desc->getflags());
            node->unref();
            if (written < 0) {
                SYSCALL_RET(written);
            }

            if (!(desc->getflags() & O_APPEND)) {
                desc->setoff(wroff + written); // New offset should be here.
            }

            SYSCALL_RET(written);
        }

        extern "C" uint64_t sys_ioctl(int fd, unsigned long request, uint64_t arg) {
            SYSCALL_LOG("sys_ioctl(%d, %lu, %p).\n", fd, request, arg);

            if (fd < 0) {
                SYSCALL_RET(-EBADF);
            }

            // Note: arg validation is request-specific and handled by ioctl implementation
            // Some ioctls use arg as an integer value, not a pointer

            NSched::Process *proc = NArch::CPU::get()->currthread->process;

            FileDescriptor *desc = proc->fdtable->get(fd);
            if (!desc) {
                SYSCALL_RET(-EBADF);
            }

            INode *node = desc->getnode();

            struct stat st = node->getattr();

            if (!S_ISCHR(st.st_mode)) {
                node->unref();
                SYSCALL_RET(-ENOTTY); // Not character special.
            }
            int ret = node->ioctl(request, arg);
            node->unref();

            SYSCALL_RET(ret);
        }

        extern "C" uint64_t sys_seek(int fd, off_t off, int whence) {
            SYSCALL_LOG("sys_seek(%d, %ld, %d).\n", fd, off, whence);

            if (fd < 0) {
                SYSCALL_RET(-EBADF);
            }

            NSched::Process *proc = NArch::CPU::get()->currthread->process;

            FileDescriptor *desc = proc->fdtable->get(fd);
            if (!desc) {
                SYSCALL_RET(-EBADF);
            }

            INode *node = desc->getnode();

            struct stat st = node->getattr();

            if (S_ISFIFO(st.st_mode) || S_ISSOCK(st.st_mode)) {
                node->unref();
                SYSCALL_RET(-ESPIPE);
            }
            node->unref();

            off_t newoff = 0;
            switch (whence) {
                case SEEK_SET:
                    newoff = off; // Works from absolute position.
                    break;
                case SEEK_CUR:
                    newoff = desc->getoff() + off; // Relative.
                    break;
                case SEEK_END:
                    newoff = st.st_size + off; // Relative from end of file.
                    break;
                default:
                    return -EINVAL;
            }

            if (newoff < 0) {
                SYSCALL_RET(-EINVAL); // Ultimately, invalid offset.
            }

            desc->setoff(newoff); // Set new offset.
            SYSCALL_RET(newoff);
        }

        extern "C" uint64_t sys_fcntl(int fd, int cmd, uint64_t arg) {
            SYSCALL_LOG("sys_fcntl(%d, %d, %p).\n", fd, cmd, arg);

            if (fd < 0) {
                SYSCALL_RET(-EBADF);
            }

            NSched::Process *proc = NArch::CPU::get()->currthread->process;

            FileDescriptor *desc = proc->fdtable->get(fd);
            if (!desc) {
                SYSCALL_RET(-EBADF);
            }

            switch (cmd) {
                case F_DUPFD:
                    SYSCALL_RET(proc->fdtable->dup2(fd, (int)arg, true));
                case F_GETFD:
                    SYSCALL_RET(proc->fdtable->iscloseonexec(fd) ? FD_CLOEXEC : 0);
                case F_SETFD:
                    if (arg & FD_CLOEXEC) {
                        proc->fdtable->setcloseonexec(fd, true);
                    } else {
                        proc->fdtable->setcloseonexec(fd, false);
                    }
                    SYSCALL_RET(0);
                case F_GETFL:
                    SYSCALL_RET(desc->getflags());
                case F_SETFL:
                    desc->setflags((int)arg);
                    SYSCALL_RET(0);
                case F_DUPFD_CLOEXEC: {
                    int newfd = proc->fdtable->dup2(fd, (int)arg, true);
                    if (newfd >= 0) {
                        proc->fdtable->setcloseonexec(newfd, true);
                    }
                    SYSCALL_RET(newfd);
                }
                default:
                    SYSCALL_RET(-EINVAL);
            }
        }

        // Userspace definition of `struct stat`.
        struct ustat {
            uint64_t        st_dev;
            uint64_t        st_ino;
            uint64_t        st_nlink;
            uint32_t        st_mode;
            uint32_t        st_uid;
            uint32_t        st_gid;
            uint64_t        st_rdev;
            int64_t         st_size;
            int64_t         st_blksize;
            int64_t         st_blocks;
            long            st_atime;
            long            st_atime_nsec;
            long            st_mtime;
            long            st_mtime_nsec;
            long            st_ctime;
            long            st_ctime_nsec;
        };

        extern "C" uint64_t sys_stat(int fd, const char *path, size_t len, struct ustat *statbuf, int flags) {
            SYSCALL_LOG("sys_stat(%d, %s, %lu, %p, %d).\n", fd, path, len, statbuf, flags);

            if (fd == AT_FDCWD) {
                // Stat is path relative to CWD.
                ssize_t pathsize = NMem::UserCopy::strnlen(path, len);
                if (pathsize < 0) {
                    SYSCALL_RET(pathsize); // Contains errno.
                }
                char *pathbuf = new char[pathsize + 1];
                if (!pathbuf) {
                    SYSCALL_RET(-ENOMEM);
                }

                int ret = NMem::UserCopy::strncpyfrom(pathbuf, path, pathsize);
                if (ret < 0) {
                    delete[] pathbuf;
                    SYSCALL_RET(ret); // Contains errno.
                }

                pathbuf[pathsize] = '\0';

                NSched::Process *proc = NArch::CPU::get()->currthread->process;
                proc->lock.acquire();
                INode *node;
                ssize_t res = vfs.resolve(pathbuf, &node, proc->cwd, !(flags & AT_SYMLINK_NOFOLLOW));
                proc->lock.release();
                delete[] pathbuf;
                if (res < 0) {
                    SYSCALL_RET(res);
                }

                struct stat st = node->getattr();
                node->unref();

                struct ustat ust;
                ust.st_dev = st.st_dev;
                ust.st_ino = st.st_ino;
                ust.st_nlink = st.st_nlink;
                ust.st_mode = st.st_mode;
                ust.st_uid = st.st_uid;
                ust.st_gid = st.st_gid;
                ust.st_rdev = st.st_rdev;
                ust.st_size = st.st_size;
                ust.st_blksize = st.st_blksize;
                ust.st_blocks = st.st_blocks;
                ust.st_atime = st.st_atime;
                ust.st_atime_nsec = 0;
                ust.st_mtime = st.st_mtime;
                ust.st_mtime_nsec = 0;
                ust.st_ctime = st.st_ctime;
                ust.st_ctime_nsec = 0;

                res = NMem::UserCopy::copyto(statbuf, &ust, sizeof(struct ustat));
                if (res < 0) {
                    SYSCALL_RET(res);
                }
                SYSCALL_RET(0);
            } else if (fd >= 0) {
                if (len == 0) { // Stat should be of an FD.
                    // Ensure that path is empty string.
                    char ch;
                    int res = NMem::UserCopy::copyfrom(&ch, path, 1);
                    if (res < 0) {
                        SYSCALL_RET(res);
                    }
                    if (ch != '\0') {
                        SYSCALL_RET(-EINVAL);
                    }

                    NSched::Process *proc = NArch::CPU::get()->currthread->process;
                    FileDescriptor *desc = proc->fdtable->get(fd);
                    if (!desc) {
                        SYSCALL_RET(-EBADF);
                    }

                    INode *node = desc->getnode();
                    struct stat st = node->getattr();
                    node->unref();

                    struct ustat ust;
                    ust.st_dev = st.st_dev;
                    ust.st_ino = st.st_ino;
                    ust.st_nlink = st.st_nlink;
                    ust.st_mode = st.st_mode;
                    ust.st_uid = st.st_uid;
                    ust.st_gid = st.st_gid;
                    ust.st_rdev = st.st_rdev;
                    ust.st_size = st.st_size;
                    ust.st_blksize = st.st_blksize;
                    ust.st_blocks = st.st_blocks;
                    ust.st_atime = st.st_atime;
                    ust.st_atime_nsec = 0;
                    ust.st_mtime = st.st_mtime;
                    ust.st_mtime_nsec = 0;
                    ust.st_ctime = st.st_ctime;
                    ust.st_ctime_nsec = 0;

                    int res2 = NMem::UserCopy::copyto(statbuf, &ust, sizeof(struct ustat));
                    if (res2 < 0) {
                        SYSCALL_RET(res2);
                    }
                    SYSCALL_RET(0);
                } else { // Stat is path relative to FD.
                    ssize_t pathsize = NMem::UserCopy::strnlen(path, len);
                    if (pathsize < 0) {
                        SYSCALL_RET(pathsize); // Contains errno.
                    }
                    char *pathbuf = new char[pathsize + 1];
                    if (!pathbuf) {
                        SYSCALL_RET(-ENOMEM);
                    }

                    int ret = NMem::UserCopy::strncpyfrom(pathbuf, path, pathsize);
                    if (ret < 0) {
                        delete[] pathbuf;
                        SYSCALL_RET(ret); // Contains errno.
                    }

                    pathbuf[pathsize] = '\0';

                    NSched::Process *proc = NArch::CPU::get()->currthread->process;
                    FileDescriptor *desc = proc->fdtable->get(fd);
                    if (!desc) {
                        delete[] pathbuf;
                        SYSCALL_RET(-EBADF);
                    }

                    INode *dirnode = desc->getnode();
                    if (!S_ISDIR(dirnode->getattr().st_mode)) {
                        dirnode->unref();
                        delete[] pathbuf;
                        SYSCALL_RET(-ENOTDIR);
                    }

                    INode *node;
                    ssize_t res = vfs.resolve(pathbuf, &node, dirnode, !(flags & AT_SYMLINK_NOFOLLOW));
                    dirnode->unref();
                    delete[] pathbuf;
                    if (res < 0) {
                        SYSCALL_RET(res);
                    }

                    struct stat st = node->getattr();
                    node->unref();
                    struct ustat ust;
                    ust.st_dev = st.st_dev;
                    ust.st_ino = st.st_ino;
                    ust.st_nlink = st.st_nlink;
                    ust.st_mode = st.st_mode;
                    ust.st_uid = st.st_uid;
                    ust.st_gid = st.st_gid;
                    ust.st_rdev = st.st_rdev;
                    ust.st_size = st.st_size;
                    ust.st_blksize = st.st_blksize;
                    ust.st_blocks = st.st_blocks;
                    ust.st_atime = st.st_atime;
                    ust.st_atime_nsec = 0;
                    ust.st_mtime = st.st_mtime;
                    ust.st_mtime_nsec = 0;
                    ust.st_ctime = st.st_ctime;
                    ust.st_ctime_nsec = 0;

                    int res2 = NMem::UserCopy::copyto(statbuf, &ust, sizeof(struct ustat));
                    if (res2 < 0) {
                        SYSCALL_RET(res2);
                    }
                    SYSCALL_RET(0);
                }
            }
            SYSCALL_RET(-EBADF); // Invalid FD.
        }

        extern "C" uint64_t sys_access(int fd, const char *path, size_t len, int mode) {
            SYSCALL_LOG("sys_access(%d, %p, %lu, %d).\n", fd, path, len, mode);

            ssize_t pathsize = NMem::UserCopy::strnlen(path, len);
            if (pathsize < 0) {
                SYSCALL_RET(pathsize); // Contains errno.
            }
            char *pathbuf = new char[pathsize + 1];
            if (!pathbuf) {
                SYSCALL_RET(-ENOMEM);
            }

            int ret = NMem::UserCopy::strncpyfrom(pathbuf, path, pathsize);
            if (ret < 0) {
                delete[] pathbuf;
                SYSCALL_RET(ret); // Contains errno.
            }

            pathbuf[pathsize] = '\0';

            NSched::Process *proc = NArch::CPU::get()->currthread->process;
            proc->lock.acquire();

            INode *dirnode;
            if (fd == AT_FDCWD) {
                dirnode = proc->cwd;
                if (!dirnode) {
                    dirnode = vfs.getroot();
                } else {
                    dirnode->ref();
                }
            } else {
                FileDescriptor *desc = proc->fdtable->get(fd);
                if (!desc) {
                    delete[] pathbuf;
                    proc->lock.release();
                    SYSCALL_RET(-EBADF);
                }

                dirnode = desc->getnode();
                if (!S_ISDIR(dirnode->getattr().st_mode)) {
                    dirnode->unref();
                    delete[] pathbuf;
                    proc->lock.release();
                    SYSCALL_RET(-ENOTDIR);
                }
            }
            proc->lock.release();

            INode *node;
            ssize_t res = vfs.resolve(pathbuf, &node, dirnode, true);
            dirnode->unref();
            delete[] pathbuf;
            if (res < 0) {
                SYSCALL_RET(res);
            }

            int accflags = 0;
            if (mode & F_OK) {
                accflags = 0; // Just checking for existence.
            } else {
                if (mode & R_OK) {
                    accflags |= O_RDONLY;
                }
                if (mode & W_OK) {
                    accflags |= O_WRONLY;
                }
                if (mode & X_OK) {
                    accflags |= O_EXEC;
                }
            }

            proc->lock.acquire();
            // Compare against real UID/GID.
            bool ok = vfs.checkaccess(node, accflags, proc->uid, proc->gid);
            proc->lock.release();
            node->unref();
            if (ok) {
                SYSCALL_RET(0);
            } else {
                SYSCALL_RET(-EACCES);
            }
        }

        extern "C" uint64_t sys_pipe(int pipefd[2], int flags) {
            SYSCALL_LOG("sys_pipe(%p).\n", pipefd);

            if (!pipefd) {
                SYSCALL_RET(-EFAULT);
            }

            if (!NMem::UserCopy::valid(pipefd, sizeof(int) * 2)) {
                SYSCALL_RET(-EFAULT);
            }

            if (!(flags & O_CLOEXEC || flags & O_NONBLOCK || flags == 0)) {
                SYSCALL_RET(-EINVAL);
            }

            struct stat attr {
                .st_ino = 1,
                .st_mode = S_IFIFO | 0666
            };

            PipeFS::PipeNode *pipe = (PipeFS::PipeNode *)PipeFS::pipefs->create("", attr);
            if (!pipe) {
                SYSCALL_RET(-ENOMEM);
            }

            NSched::Process *proc = NArch::CPU::get()->currthread->process;
            NLib::ScopeIRQSpinlock guard(&proc->lock);

            // Open read end.
            int readfd = proc->fdtable->open(pipe, O_RDONLY | (flags & (O_CLOEXEC | O_NONBLOCK)));
            if (readfd < 0) {
                pipe->unref();
                SYSCALL_RET(readfd);
            }
            pipe->open(O_RDONLY); // Trigger open hook.

            // Open write end.
            int writefd = proc->fdtable->open(pipe, O_WRONLY | (flags & (O_CLOEXEC | O_NONBLOCK)));
            if (writefd < 0) {
                proc->fdtable->close(readfd);
                pipe->unref();
                SYSCALL_RET(writefd);
            }
            pipe->open(O_WRONLY); // Trigger open hook.

            pipe->unref(); // FD table holds references now.

            int res = NMem::UserCopy::copyto(pipefd, &readfd, sizeof(int));
            if (res < 0) {
                proc->fdtable->close(readfd);
                proc->fdtable->close(writefd);
                SYSCALL_RET(res);
            }
            res = NMem::UserCopy::copyto(pipefd + 1, &writefd, sizeof(int));
            if (res < 0) {
                proc->fdtable->close(readfd);
                proc->fdtable->close(writefd);
                SYSCALL_RET(res);
            }

            SYSCALL_RET(0);
        }

        extern "C" uint64_t sys_readlink(int fd, const char *path, size_t len, char *buf, size_t bufsize) {
            SYSCALL_LOG("sys_readlink(%d, %s, %lu, %p, %lu).\n", fd, path, len, buf, bufsize);

            ssize_t pathsize = NMem::UserCopy::strnlen(path, len);
            if (pathsize < 0) {
                SYSCALL_RET(pathsize); // Contains errno.
            }
            char *pathbuf = new char[pathsize + 1];
            if (!pathbuf) {
                SYSCALL_RET(-ENOMEM);
            }

            int ret = NMem::UserCopy::strncpyfrom(pathbuf, path, pathsize);
            if (ret < 0) {
                delete[] pathbuf;
                SYSCALL_RET(ret); // Contains errno.
            }

            pathbuf[pathsize] = '\0';

            NSched::Process *proc = NArch::CPU::get()->currthread->process;
            proc->lock.acquire();

            INode *dirnode;
            if (fd == AT_FDCWD) {
                dirnode = proc->cwd;
                if (!dirnode) {
                    dirnode = vfs.getroot();
                } else {
                    dirnode->ref();
                }
            } else {
                FileDescriptor *desc = proc->fdtable->get(fd);
                if (!desc) {
                    delete[] pathbuf;
                    proc->lock.release();
                    SYSCALL_RET(-EBADF);
                }

                dirnode = desc->getnode();
                if (!S_ISDIR(dirnode->getattr().st_mode)) {
                    dirnode->unref();
                    delete[] pathbuf;
                    proc->lock.release();
                    SYSCALL_RET(-ENOTDIR);
                }
            }
            proc->lock.release();

            INode *node;
            ssize_t res = vfs.resolve(pathbuf, &node, dirnode, false);
            dirnode->unref();
            delete[] pathbuf;
            if (res < 0) {
                SYSCALL_RET(res);
            }

            ssize_t read = node->readlink(buf, bufsize);
            node->unref();
            if (read < 0) {
                SYSCALL_RET(read); // Return error code.
            }

            SYSCALL_RET(read); // Return number of bytes read.
        }

        extern "C" ssize_t sys_unlink(int fd, const char *path, size_t len, int flags) {
            SYSCALL_LOG("sys_unlink(%d, %p, %lu, %d).\n", fd, path, len, flags);

            ssize_t pathsize = NMem::UserCopy::strnlen(path, len);
            if (pathsize < 0) {
                SYSCALL_RET(pathsize); // Contains errno.
            }
            char *pathbuf = new char[pathsize + 1];
            if (!pathbuf) {
                SYSCALL_RET(-ENOMEM);
            }
            int ret = NMem::UserCopy::strncpyfrom(pathbuf, path, pathsize);
            if (ret < 0) {
                delete[] pathbuf;
                SYSCALL_RET(ret); // Contains errno.
            }
            pathbuf[pathsize] = '\0';

            NSched::Process *proc = NArch::CPU::get()->currthread->process;
            proc->lock.acquire();
            INode *dirnode;
            if (fd == AT_FDCWD) {
                dirnode = proc->cwd;
                if (!dirnode) {
                    dirnode = vfs.getroot();
                } else {
                    dirnode->ref();
                }
            } else {
                FileDescriptor *desc = proc->fdtable->get(fd);
                if (!desc) {
                    delete[] pathbuf;
                    proc->lock.release();
                    SYSCALL_RET(-EBADF);
                }
                dirnode = desc->getnode();
                if (!S_ISDIR(dirnode->getattr().st_mode)) {
                    dirnode->unref();
                    delete[] pathbuf;
                    proc->lock.release();
                    SYSCALL_RET(-ENOTDIR);
                }
            }

            ssize_t res = vfs.unlink(pathbuf, dirnode, flags, proc->uid, proc->gid);
            proc->lock.release();
            dirnode->unref();
            delete[] pathbuf;
            SYSCALL_RET(res); // Return result of unlink operation.
        }

        struct timespec {
            long tv_sec;
            long tv_nsec;
        };

        extern "C" uint64_t sys_ppoll(struct pollfd *fds, size_t nfds, struct timespec *tmo_p, struct NLib::sigset *sigmask) {
            SYSCALL_LOG("sys_ppoll(%p, %u, %p, %p).\n", fds, nfds, tmo_p, sigmask);
            SYSCALL_RET(-ENOSYS); // Not implemented yet.
        }
    }
}
