#ifdef __x86_64__
#include <arch/x86_64/cpu.hpp>
#endif
#include <fs/devfs.hpp>
#include <fs/pipefs.hpp>
#include <fs/vfs.hpp>
#include <lib/errno.hpp>
#include <mm/pagecache.hpp>
#include <mm/ucopy.hpp>
#include <sys/clock.hpp>
#include <sys/syscall.hpp>

namespace NFS {
    namespace VFS {
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
            proc->lock.acquire();

            if (pathbuf[0] == '/') { // Absolute path invalidates dirfd.
                dirnode = vfs->getroot();
            } else {
                if (dirfd == AT_FDCWD) { // Special case: FD is CWD.
                    dirnode = proc->cwd;
                    if (!dirnode) { // If the process has no CWD, we use root.
                        dirnode = vfs->getroot();
                    } else {
                        dirnode->ref(); // Increase reference.
                    }
                } else {
                    FileDescriptor *desc = proc->fdtable->get(dirfd);
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
            }

            int uid = proc->euid;;
            int gid = proc->egid;
            INode *procroot = proc->root;
            if (procroot) {
                procroot->ref(); // Increase reference for our use.
            }
            proc->lock.release();

            INode *node;
            ssize_t res = vfs->resolve(pathbuf, &node, dirnode, !(flags & O_NOFOLLOW), procroot);
            dirnode->unref();
            if (procroot) {
                procroot->unref();
            }
            if (res == -EACCES) { // We don't have permission to traverse the path.
                delete[] pathbuf;
                SYSCALL_RET(-EACCES); // Propagate access error.
            }

            if (res != 0) { // Couldn't find it. Check if there's a reason to create it.
                if (!(flags & O_CREAT)) {
                    delete[] pathbuf;
                    SYSCALL_RET(res); // Don't bother if there's no create flag.
                }
                // Re-acquire procroot for create operation.
                proc->lock.acquire();
                INode *procroot = proc->root;
                if (procroot) {
                    procroot->ref();
                }
                proc->lock.release();

                // Create the node.
                struct stat attr = { 0 };
                attr.st_mode = mode | S_IFREG;
                attr.st_uid = uid;
                attr.st_gid = gid;
                ssize_t res = vfs->create(pathbuf, &node, attr, dirnode, procroot);
                if (procroot) {
                    procroot->unref();
                }
                if (res < 0) {
                    delete[] pathbuf;
                    SYSCALL_RET(res); // Creation failed.
                }
            }

            delete[] pathbuf;

            struct stat st = node->getattr();

            if ((flags & O_DIRECTORY) && !S_ISDIR(st.st_mode)) { // If we're supposed to open a directory, we'd have to verify that the node is a directory.
                node->unref();
                SYSCALL_RET(-ENOTDIR);
            }

            if (!vfs->checkaccess(node, flags, uid, gid)) { // Check if current process' effective UID and GID are valid for access the node in this way.
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

            // Truncate regular files if O_TRUNC is set and we have write access.
            if ((flags & O_TRUNC) && S_ISREG(st.st_mode)) {
                ssize_t truncres = node->truncate(0);
                if (truncres < 0) {
                    node->unref();
                    SYSCALL_RET(truncres);
                }
            }

            int fd = proc->fdtable->open(node, flags);
            if (fd < 0) {
                node->unref();
                SYSCALL_RET(fd); // Propagate error.
            }

            res = node->open(flags); // Trigger open hook.
            if (res < 0) {
                proc->fdtable->close(fd); // Clean up FD table entry and call INode::close().
                node->unref();
                SYSCALL_RET(res); // Open failed.
            }

            if (S_ISCHR(st.st_mode) && !(flags & O_NOCTTY)) { // Check if we should try setting a controlling terminal. POSIX says only if O_NOCTTY is not set, and the file is a character device. We also require that the process is a session leader without a controlling terminal.
                proc->lock.acquire();
                bool isleader = proc->session && proc->session->id == proc->id;
                uint64_t currentctty = __atomic_load_n(&proc->tty, memory_order_relaxed);
                proc->lock.release();

                if (isleader && currentctty == 0) {
                    node->ioctl(0x540e, 0); // TIOCSCTTY. Ignore errors (not all char devices are TTYs).
                }
            }

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

            // Only O_CLOEXEC is a valid flag for dup3.
            if (flags & ~O_CLOEXEC) {
                SYSCALL_RET(-EINVAL);
            }

            NSched::Process *proc = NArch::CPU::get()->currthread->process;

            SYSCALL_RET(proc->fdtable->dup2(fd, newfd, false, flags & O_CLOEXEC));
        }

        extern "C" uint64_t sys_close(int fd) {
            SYSCALL_LOG("sys_close(%d).\n", fd);

            if (fd < 0) {
                SYSCALL_RET(-EBADF);
            }

            NSched::Process *proc = NArch::CPU::get()->currthread->process;

            int res = proc->fdtable->close(fd);
            SYSCALL_RET(res);
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

            // POSIX requires search (execute) permission on the directory.
            proc->lock.acquire();
            int uid = proc->euid;
            int gid = proc->egid;
            proc->lock.release();

            if (!vfs->checkaccess(node, O_EXEC, uid, gid)) {
                node->unref();
                SYSCALL_RET(-EACCES);
            }

            proc->lock.acquire();
            INode *oldcwd = proc->cwd;
            proc->cwd = node; // Set new CWD.
            if (node->fs) {
                node->fs->fsref();  // New filesystem gets a reference
            }
            proc->lock.release();

            if (oldcwd) {
                if (oldcwd->fs) {
                    oldcwd->fs->fsunref();  // Old filesystem loses a reference
                }
                oldcwd->unref(); // Unreference old CWD.
            }
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
            proc->lock.acquire();
            int uid = proc->euid;
            int gid = proc->egid;
            INode *cwd = proc->cwd;
            if (cwd) {
                cwd->ref(); // Increase reference for our use.
            }
            INode *procroot = proc->root;
            if (procroot) {
                procroot->ref(); // Increase reference for our use.
            }
            proc->lock.release();

            INode *node;
            ssize_t res = vfs->resolve(pathbuf, &node, cwd, true, procroot);
            delete[] pathbuf;

            if (cwd) {
                cwd->unref(); // Unreference old CWD reference.
            }
            if (procroot) {
                procroot->unref();
            }

            if (res < 0) {
                SYSCALL_RET(res);
            }

            struct stat st = node->getattr();
            if (!S_ISDIR(st.st_mode)) {
                node->unref();
                SYSCALL_RET(-ENOTDIR);
            }

            // POSIX requires search (execute) permission on the directory.
            if (!vfs->checkaccess(node, O_EXEC, uid, gid)) {
                node->unref();
                SYSCALL_RET(-EACCES);
            }

            proc->lock.acquire();
            INode *oldcwd = proc->cwd;
            proc->cwd = node; // Set new CWD.
            if (node->fs) {
                node->fs->fsref();  // New filesystem gets a reference
            }
            proc->lock.release();

            if (oldcwd) {
                if (oldcwd->fs) {
                    oldcwd->fs->fsunref();  // Old filesystem loses a reference
                }
                oldcwd->unref(); // Unreference old CWD.
            }
            SYSCALL_RET(0);
        }

        extern "C" uint64_t sys_chroot(const char *path) {
            SYSCALL_LOG("sys_chroot(%s).\n", path);

            // Only root (euid == 0) can call chroot.
            NSched::Process *proc = NArch::CPU::get()->currthread->process;
            proc->lock.acquire();
            int euid = proc->euid;
            proc->lock.release();

            if (euid != 0) {
                SYSCALL_RET(-EPERM);
            }

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

            proc->lock.acquire();
            int uid = proc->euid;
            int gid = proc->egid;
            INode *cwd = proc->cwd;
            if (cwd) {
                cwd->ref(); // Increase reference for our use.
            }
            INode *procroot = proc->root;
            if (procroot) {
                procroot->ref(); // Increase reference for our use.
            }
            proc->lock.release();

            INode *node;
            ssize_t res = vfs->resolve(pathbuf, &node, cwd, true, procroot);
            delete[] pathbuf;

            if (cwd) {
                cwd->unref(); // Unreference old CWD reference.
            }
            if (procroot) {
                procroot->unref();
            }

            if (res < 0) {
                SYSCALL_RET(res);
            }

            struct stat st = node->getattr();
            if (!S_ISDIR(st.st_mode)) {
                node->unref();
                SYSCALL_RET(-ENOTDIR);
            }

            // POSIX requires search (execute) permission on the directory.
            if (!vfs->checkaccess(node, O_EXEC, uid, gid)) {
                node->unref();
                SYSCALL_RET(-EACCES);
            }

            proc->lock.acquire();
            INode *oldroot = proc->root;
            proc->root = node; // Set new root.
            if (node->fs) {
                node->fs->fsref();  // New filesystem gets a reference
            }
            proc->lock.release();

            if (oldroot) {
                if (oldroot->fs) {
                    oldroot->fs->fsunref();  // Old filesystem loses a reference
                }
                oldroot->unref(); // Unreference old root.
            }
            SYSCALL_RET(0);
        }

        extern "C" ssize_t sys_getcwd(char *buf, size_t size) {
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
                cwd = vfs->getroot(); // getroot() increments refcount.
                if (!cwd) {
                    SYSCALL_RET(-ENOENT);
                }
            } else {
                cwd->ref(); // Increase reference for our use.
            }

            // Get the effective root (process root if chrooted, otherwise global root).
            INode *effroot = proc->root;
            if (!effroot) {
                effroot = vfs->getroot(); // getroot() increments refcount.
            } else {
                effroot->ref();
            }

            // Build path by walking up the parent chain to effective root.
            Path resultpath = Path(true); // Start with absolute path.
            INode *current = cwd;

            while (current && current != effroot) {
                const char *name = current->getname();
                if (name && name[0] != '\0') {
                    resultpath.pushcomponent(name, false); // Push to front (we're walking backwards).
                }
                INode *parent = current->getparent();

                if (!parent) {
                    // Reached root without finding effective root, this shouldn't happen.
                    current->unref();
                    effroot->unref();
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
            effroot->unref();

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

            SYSCALL_RET(pathlen + 1); // Return the length including null terminator on success.
        }

        extern "C" uint64_t sys_read(int fd, void *buf, size_t count) {
            SYSCALL_LOG("sys_read(%d, %p, %lu).\n", fd, buf, count);
            if (fd < 0) {
                SYSCALL_RET(-EBADF);
            }

            if (!buf && count > 0) {
                SYSCALL_RET(-EFAULT);
            }

            if (!NMem::UserCopy::valid(buf, count)) { // Validation check protects underlying stuff from kernel addresses being passed through.
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
                    SYSCALL_RET(-EINVAL);
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
                case F_SETLK64:
                case F_SETLKW64:
                case F_GETLK64:
                    // XXX: Unimplemented.
                    SYSCALL_RET(-ENOSYS);
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

                INode *cwd = proc->cwd;
                if (!cwd) {
                    cwd = vfs->getroot(); // If the process has no CWD, we use root.
                } else {
                    cwd->ref(); // Increase reference.
                }
                INode *procroot = proc->root;
                if (procroot) {
                    procroot->ref();
                }
                proc->lock.release();

                INode *node;
                ssize_t res = vfs->resolve(pathbuf, &node, cwd, !(flags & AT_SYMLINK_NOFOLLOW), procroot);
                cwd->unref();
                if (procroot) {
                    procroot->unref();
                }
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
                    proc->lock.acquire();
                    INode *procroot = proc->root;
                    if (procroot) {
                        procroot->ref();
                    }
                    proc->lock.release();

                    FileDescriptor *desc = proc->fdtable->get(fd);
                    if (!desc) {
                        if (procroot) {
                            procroot->unref();
                        }
                        delete[] pathbuf;
                        SYSCALL_RET(-EBADF);
                    }

                    INode *dirnode = desc->getnode();
                    if (!S_ISDIR(dirnode->getattr().st_mode)) {
                        dirnode->unref();
                        if (procroot) {
                            procroot->unref();
                        }
                        delete[] pathbuf;
                        SYSCALL_RET(-ENOTDIR);
                    }

                    INode *node;
                    ssize_t res = vfs->resolve(pathbuf, &node, dirnode, !(flags & AT_SYMLINK_NOFOLLOW), procroot);
                    dirnode->unref();
                    if (procroot) {
                        procroot->unref();
                    }
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

        extern "C" uint64_t sys_access(int fd, const char *path, size_t len, int mode, int flags) {
            SYSCALL_LOG("sys_access(%d, %s, %lu, %d, %d).\n", fd, path, len, mode, flags);

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

            INode *dirnode = NULL;
            if (pathbuf[0] == '/') { // Absolute path invalidates dirfd.
                dirnode = vfs->getroot();
            } else {
                if (fd == AT_FDCWD) { // Special case: FD is CWD.
                    dirnode = proc->cwd;
                    if (!dirnode) { // If the process has no CWD, we use root.
                        dirnode = vfs->getroot();
                    } else {
                        dirnode->ref(); // Increase reference.
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
            }

            // Use real UID/GID unless AT_EACCESS is set.
            int uid = (flags & AT_EACCESS) ? proc->euid : proc->uid;
            int gid = (flags & AT_EACCESS) ? proc->egid : proc->gid;
            INode *procroot = proc->root;
            if (procroot) {
                procroot->ref();
            }
            proc->lock.release();

            INode *node;
            ssize_t res = vfs->resolve(pathbuf, &node, dirnode, !(flags & AT_SYMLINK_NOFOLLOW), procroot);
            dirnode->unref();
            if (procroot) {
                procroot->unref();
            }
            delete[] pathbuf;

            if (res < 0) {
                SYSCALL_RET(res); // File not found or other resolution error.
            }

            // F_OK just checks for existence, which we've already verified.
            if (mode == F_OK) {
                node->unref();
                SYSCALL_RET(0);
            }

            struct stat st = node->getattr();
            node->unref();

            // Root always has access (except for execute on non-executable files).
            if (uid == 0) {
                // Root can read/write anything, but execute only if at least one execute bit is set.
                if ((mode & X_OK) && !S_ISDIR(st.st_mode) && !(st.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH))) {
                    SYSCALL_RET(-EACCES);
                }
                SYSCALL_RET(0);
            }

            // Check each requested permission.
            if (mode & R_OK) {
                if (uid == (int)st.st_uid) {
                    if (!(st.st_mode & S_IRUSR)) {
                        SYSCALL_RET(-EACCES);
                    }
                } else if (gid == (int)st.st_gid) {
                    if (!(st.st_mode & S_IRGRP)) {
                        SYSCALL_RET(-EACCES);
                    }
                } else {
                    if (!(st.st_mode & S_IROTH)) {
                        SYSCALL_RET(-EACCES);
                    }
                }
            }

            if (mode & W_OK) {
                if (uid == (int)st.st_uid) {
                    if (!(st.st_mode & S_IWUSR)) {
                        SYSCALL_RET(-EACCES);
                    }
                } else if (gid == (int)st.st_gid) {
                    if (!(st.st_mode & S_IWGRP)) {
                        SYSCALL_RET(-EACCES);
                    }
                } else {
                    if (!(st.st_mode & S_IWOTH)) {
                        SYSCALL_RET(-EACCES);
                    }
                }
            }

            if (mode & X_OK) {
                if (uid == (int)st.st_uid) {
                    if (!(st.st_mode & S_IXUSR)) {
                        SYSCALL_RET(-EACCES);
                    }
                } else if (gid == (int)st.st_gid) {
                    if (!(st.st_mode & S_IXGRP)) {
                        SYSCALL_RET(-EACCES);
                    }
                } else {
                    if (!(st.st_mode & S_IXOTH)) {
                        SYSCALL_RET(-EACCES);
                    }
                }
            }

            SYSCALL_RET(0);
        }

        extern "C" uint64_t sys_pipe(int pipefd[2], int flags) {
            SYSCALL_LOG("sys_pipe(%p).\n", pipefd);

            if (!pipefd) {
                SYSCALL_RET(-EFAULT);
            }

            if (!NMem::UserCopy::valid(pipefd, sizeof(int) * 2)) {
                SYSCALL_RET(-EFAULT);
            }

            // Only O_CLOEXEC and O_NONBLOCK are valid flags for pipe2.
            if (flags & ~(O_CLOEXEC | O_NONBLOCK)) {
                SYSCALL_RET(-EINVAL);
            }

            struct stat attr {
                .st_ino = 1,
                .st_mode = S_IFIFO | 0666
            };

            PipeFS::PipeNode *pipe;
            ssize_t res = PipeFS::pipefs->create("", (INode **)&pipe, attr);
            if (res < 0) {
                SYSCALL_RET(res);
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
                proc->fdtable->close(readfd); // Close and undo pipe->open(O_RDONLY).
                pipe->unref();
                SYSCALL_RET(writefd);
            }
            pipe->open(O_WRONLY); // Trigger open hook.

            pipe->unref(); // FD table holds references now.

            res = NMem::UserCopy::copyto(pipefd, &readfd, sizeof(int));
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
                    dirnode = vfs->getroot();
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
            INode *procroot = proc->root;
            if (procroot) {
                procroot->ref();
            }
            proc->lock.release();

            INode *node;
            ssize_t res = vfs->resolve(pathbuf, &node, dirnode, false, procroot);
            dirnode->unref();
            if (procroot) {
                procroot->unref();
            }
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
            SYSCALL_LOG("sys_unlink(%d, %s, %lu, %d).\n", fd, path, len, flags);

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
                    dirnode = vfs->getroot();
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

            int uid = proc->uid;
            int gid = proc->gid;
            INode *procroot = proc->root;
            if (procroot) {
                procroot->ref();
            }
            proc->lock.release();
            ssize_t res = vfs->unlink(pathbuf, dirnode, flags, uid, gid, procroot);
            dirnode->unref();
            if (procroot) {
                procroot->unref();
            }
            delete[] pathbuf;
            SYSCALL_RET(res); // Return result of unlink operation.
        }

        extern "C" uint64_t sys_ppoll(struct pollfd *fds, size_t nfds, struct NSys::Clock::timespec *timeout, NLib::sigset_t *sigmask) {
            SYSCALL_LOG("sys_ppoll(%p, %u, %p, %p).\n", fds, nfds, timeout, sigmask);

            struct pollfd *kfds = NULL;
            if (nfds > 0) {
                if (!fds) {
                    SYSCALL_RET(-EFAULT);
                }

                size_t fds_size = sizeof(struct pollfd) * nfds;
                if (!NMem::UserCopy::valid(fds, fds_size)) {
                    SYSCALL_RET(-EFAULT);
                }

                kfds = new struct pollfd[nfds];
                if (!kfds) {
                    SYSCALL_RET(-ENOMEM);
                }

                int res = NMem::UserCopy::copyfrom(kfds, fds, fds_size);
                if (res < 0) {
                    delete[] kfds;
                    SYSCALL_RET(res);
                }
            } else {
                // No fds to poll.
                struct NSys::Clock::timespec ktmo;
                if (timeout) { // Simply just wait for the timeout period.
                    if (!NMem::UserCopy::valid(timeout, sizeof(struct NSys::Clock::timespec))) {
                        SYSCALL_RET(-EFAULT);
                    }
                    int res = NMem::UserCopy::copyfrom(&ktmo, timeout, sizeof(struct NSys::Clock::timespec));
                    if (res < 0) {
                        SYSCALL_RET(res);
                    }

                    if (ktmo.tv_sec < 0 || ktmo.tv_nsec < 0 || ktmo.tv_nsec >= 1000000000) {
                        SYSCALL_RET(-EINVAL);
                    }

                    uint64_t timeoutms = ktmo.tv_sec * 1000 + ktmo.tv_nsec / 1000000;
                    int ret = NSched::sleep(timeoutms);
                    if (ret < 0) {
                        SYSCALL_RET(ret); // Return -EINTR if interrupted.
                    }
                } else {
                    // Infinite wait, so just yield (this acts like a sys_pause would).

                    // XXX: Set thread signal mask?

                    NLib::sigset_t ksigmask;
                    if (sigmask) {
                        if (!NMem::UserCopy::valid(sigmask, sizeof(ksigmask))) {
                            delete[] kfds;
                            SYSCALL_RET(-EFAULT);
                        }
                        int res = NMem::UserCopy::copyfrom(&ksigmask, sigmask, sizeof(ksigmask));
                        if (res < 0) {
                            delete[] kfds;
                            SYSCALL_RET(res);
                        }
                    } else {
                        // Empty signal mask.
                        NLib::memset(&ksigmask, 0, sizeof(ksigmask));
                    }

                    // Apply signal mask for the duration of the poll (per-thread).
                    NSched::Thread *thread = NArch::CPU::get()->currthread;
                    NSched::Process *proc = thread->process;
                    NLib::sigset_t oldmask = __atomic_load_n(&thread->blocked, memory_order_acquire);
                    __atomic_store_n(&thread->blocked, ksigmask, memory_order_release);

                    // Untracked sleep state, so we won't be woken up until a signal arrives.
                    NSched::setthreadstate(NArch::CPU::get()->currthread, NSched::Thread::PAUSED, "sys_ppoll");
                    NSched::yield();

                    // Restore old signal mask before returning (per-thread).
                    __atomic_store_n(&thread->blocked, oldmask, memory_order_release);

                    SYSCALL_RET(-EINTR); // Indicate we were interrupted by a signal.
                }

                SYSCALL_RET(0);
            }


            NLib::sigset_t ksigmask;
            if (sigmask) {
                if (!NMem::UserCopy::valid(sigmask, sizeof(ksigmask))) {
                    delete[] kfds;
                    SYSCALL_RET(-EFAULT);
                }
                int res = NMem::UserCopy::copyfrom(&ksigmask, sigmask, sizeof(ksigmask));
                if (res < 0) {
                    delete[] kfds;
                    SYSCALL_RET(res);
                }
            } else {
                // Empty signal mask.
                NLib::memset(&ksigmask, 0, sizeof(ksigmask));
            }

            struct NSys::Clock::timespec ktmo;
            if (timeout) { // Simply just wait for the timeout period.
                if (!NMem::UserCopy::valid(timeout, sizeof(struct NSys::Clock::timespec))) {
                    delete[] kfds;
                    SYSCALL_RET(-EFAULT);
                }
                int res = NMem::UserCopy::copyfrom(&ktmo, timeout, sizeof(struct NSys::Clock::timespec));
                if (res < 0) {
                    delete[] kfds;
                    SYSCALL_RET(res);
                }

                if (ktmo.tv_sec < 0 || ktmo.tv_nsec < 0 || ktmo.tv_nsec >= 1000000000) {
                    delete[] kfds;
                    SYSCALL_RET(-EINVAL);
                }
            }

            // Apply signal mask for the duration of the poll (per-thread).
            NSched::Thread *thread = NArch::CPU::get()->currthread;
            NSched::Process *proc = thread->process;
            NLib::sigset_t oldmask = __atomic_load_n(&thread->blocked, memory_order_acquire);
            __atomic_store_n(&thread->blocked, ksigmask, memory_order_release);

            size_t eventcount = 0; // How many fds ended up with non-zero revents.

            // Track timeout using monotonic clock for accurate timing.
            uint64_t deadlinens = 0;
            bool hastimeout = (timeout != NULL);
            if (hastimeout) {
                struct NSys::Clock::timespec now;
                NSys::Clock::Clock *clock = NSys::Clock::getclock(NSys::Clock::CLOCK_MONOTONIC);
                if (clock && clock->gettime(&now) == 0) {
                    deadlinens = (uint64_t)now.tv_sec * 1000000000ULL + (uint64_t)now.tv_nsec;
                    deadlinens += (uint64_t)ktmo.tv_sec * 1000000000ULL + (uint64_t)ktmo.tv_nsec;
                }
            }

            while (true) {
                for (size_t i = 0; i < nfds; i++) {
                    if (kfds[i].fd < 0) {
                        continue; // Ignore negative FDs.
                    }

                    NSched::Process *proc = NArch::CPU::get()->currthread->process;
                    INode *node = NULL;
                    int flags = 0;

                    // Hold proc->lock only for FD lookup, release before poll().
                    {
                        NLib::ScopeIRQSpinlock guard(&proc->lock);
                        FileDescriptor *desc = proc->fdtable->get(kfds[i].fd);
                        if (!desc) {
                            // Restore old signal mask before returning (per-thread).
                            __atomic_store_n(&thread->blocked, oldmask, memory_order_release);
                            delete[] kfds;
                            SYSCALL_RET(-EBADF);
                        }
                        node = desc->getnode();
                        flags = desc->getflags();
                    }

                    struct pollfd *pfd = &kfds[i];
                    int res = node->poll(pfd->events, &pfd->revents, flags);
                    node->unref();
                    if (res < 0) {
                        // Restore old signal mask before returning (per-thread).
                        __atomic_store_n(&thread->blocked, oldmask, memory_order_release);
                        delete[] kfds;
                        SYSCALL_RET(res);
                    }

                    if (pfd->revents != 0) {
                        eventcount++;
                    }
                }

                if (eventcount > 0) {
                    // Some events are ready, break and return what we have thus far.
                    break;
                }

                // No events ready yet, check if we have a timeout.
                if (hastimeout) {
                    // Check remaining time.
                    struct NSys::Clock::timespec now;
                    NSys::Clock::Clock *clock = NSys::Clock::getclock(NSys::Clock::CLOCK_MONOTONIC);
                    uint64_t nowns = 0;
                    if (clock && clock->gettime(&now) == 0) {
                        nowns = (uint64_t)now.tv_sec * 1000000000ULL + (uint64_t)now.tv_nsec;
                    }

                    if (nowns >= deadlinens) {
                        // Timeout expired.
                        break;
                    }

                    // Calculate remaining time in ms.
                    uint64_t remainingns = deadlinens - nowns;
                    uint64_t remainingms = (remainingns + 999999) / 1000000; // Round up to ms.

                    if (remainingms == 0) {
                        break; // Timeout effectively expired.
                    }

                    // Sleep for a small interval (min of remaining time or 10ms) to allow checking for events.
                    uint64_t sleepms = remainingms < 10 ? remainingms : 10;
                    int ret = NSched::sleep(sleepms);
                    if (ret < 0) {
                        // Sleep was interrupted by signal. Restore old mask and return.
                        __atomic_store_n(&thread->blocked, oldmask, memory_order_release);
                        delete[] kfds;
                        SYSCALL_RET(ret);
                    }
                    // Continue loop to re-poll fds after short sleep.
                    continue;
                }

                NSched::yield(); // Yield to avoid thrashing the CPU.
            }
            // Restore old signal mask before returning (per-thread).
            __atomic_store_n(&thread->blocked, oldmask, memory_order_release);

            // Copy results back to userspace.
            if (nfds > 0 && kfds) {
                int res = NMem::UserCopy::copyto(fds, kfds, sizeof(struct pollfd) * nfds);
                delete[] kfds;
                if (res < 0) {
                    SYSCALL_RET(res);
                }
            }

            SYSCALL_RET(eventcount);
        }

        extern "C" uint64_t sys_mknodat(int fd, const char *path, size_t len, int mode, int dev) {
            SYSCALL_LOG("sys_mknodat(%d, %s, %lu, %o, %d).\n", fd, path, len, mode, dev);

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
                    dirnode = vfs->getroot();
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

            // Check permissions to create in this directory.
            bool ok = vfs->checkaccess(dirnode, O_WRONLY | O_EXEC, proc->euid, proc->egid);
            if (!ok) {
                dirnode->unref();
                delete[] pathbuf;
                proc->lock.release();
                SYSCALL_RET(-EACCES);
            }

            // Setup basic attributes, specific filesystems fill in the rest.
            struct stat attr {
                .st_mode = mode,
                .st_uid = proc->euid,
                .st_gid = proc->egid,
                .st_rdev = dev
            };

            INode *procroot = proc->root;
            if (procroot) {
                procroot->ref();
            }
            proc->lock.release();

            INode *nodeout = NULL;
            ssize_t res = vfs->create(pathbuf, &nodeout, attr, dirnode, procroot);
            dirnode->unref();
            if (procroot) {
                procroot->unref();
            }
            delete[] pathbuf;
            if (res < 0) {
                SYSCALL_RET(res);
            }

            nodeout->unref();
            SYSCALL_RET(0);
        }

        extern "C" uint64_t sys_chmod(int fd, const char *path, size_t len, int mode, int flags) {
            SYSCALL_LOG("sys_chmod(%d, %s, %lu, %o, %d).\n", fd, path, len, mode, flags);

            // FCHMODAT-like syscall, handles fchmodat, fchmod, and chmod.

            ssize_t res = NMem::UserCopy::valid(path, len);
            if (res < 0) {
                SYSCALL_RET(res); // Contains errno.
            }

            ssize_t pathsize = NMem::UserCopy::strnlen(path, len);
            if (pathsize < 0) {
                SYSCALL_RET(pathsize); // Contains errno.
            }
            char *pathbuf = new char[pathsize + 1];
            if (!pathbuf) {
                SYSCALL_RET(-ENOMEM);
            }

            res = NMem::UserCopy::strncpyfrom(pathbuf, path, pathsize);
            if (res < 0) {
                delete[] pathbuf;
                SYSCALL_RET(res); // Contains errno.
            }

            pathbuf[pathsize] = '\0';

            NSched::Process *proc = NArch::CPU::get()->currthread->process;
            proc->lock.acquire();
            INode *dirnode;
            if (fd == AT_FDCWD) {
                dirnode = proc->cwd;
                if (!dirnode) {
                    dirnode = vfs->getroot();
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

            int uid = proc->euid;
            int gid = proc->egid;
            INode *procroot = proc->root;
            if (procroot) {
                procroot->ref();
            }
            proc->lock.release();

            // If AT_EMPTY_PATH is set and path is empty, change mode of dirnode itself.
            INode *targetnode = NULL;
            if ((flags & AT_EMPTY_PATH) && pathsize == 0) {
                targetnode = dirnode;
                targetnode->ref();
            } else {
                res = vfs->resolve(pathbuf, &targetnode, dirnode, !(flags & AT_SYMLINK_NOFOLLOW), procroot);
                if (res < 0) {
                    dirnode->unref();
                    if (procroot) {
                        procroot->unref();
                    }
                    delete[] pathbuf;
                    SYSCALL_RET(res);
                }
            }

            dirnode->unref();
            if (procroot) {
                procroot->unref();
            }
            delete[] pathbuf;
            // Check if we have permission to change the mode.
            bool ok = false;
            struct stat st = targetnode->getattr();
            if (uid == 0) {
                ok = true; // Root can always change mode.
            } else if (uid == st.st_uid) {
                ok = true; // Owner can change mode.
            }

            if (!ok) {
                targetnode->unref();
                SYSCALL_RET(-EACCES);
            }

            struct stat newattr = st;
            newattr.st_mode = (st.st_mode & S_IFMT) | (mode & ~S_IFMT);
            targetnode->setattr(newattr);
            targetnode->unref();
            SYSCALL_RET(0);
        }

        extern "C" uint64_t sys_chown(int fd, const char *path, size_t len, int uid, int gid, int flags) {
            SYSCALL_LOG("sys_chown(%d, %s, %lu, %d, %d, %d).\n", fd, path, len, uid, gid, flags);

            ssize_t res = NMem::UserCopy::valid(path, len);
            if (res < 0) {
                SYSCALL_RET(res); // Contains errno.
            }

            ssize_t pathsize = NMem::UserCopy::strnlen(path, len);
            if (pathsize < 0) {
                SYSCALL_RET(pathsize); // Contains errno.
            }
            char *pathbuf = new char[pathsize + 1];
            if (!pathbuf) {
                SYSCALL_RET(-ENOMEM);
            }

            res = NMem::UserCopy::strncpyfrom(pathbuf, path, pathsize);
            if (res < 0) {
                delete[] pathbuf;
                SYSCALL_RET(res); // Contains errno.
            }

            pathbuf[pathsize] = '\0';

            NSched::Process *proc = NArch::CPU::get()->currthread->process;
            proc->lock.acquire();
            INode *dirnode;
            if (fd == AT_FDCWD) {
                dirnode = proc->cwd;
                if (!dirnode) {
                    dirnode = vfs->getroot();
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

            int euid = proc->euid;
            int egid = proc->egid;
            INode *procroot = proc->root;
            if (procroot) {
                procroot->ref();
            }
            proc->lock.release();

            // If AT_EMPTY_PATH is set and path is empty, change owner of dirnode itself.
            INode *targetnode = NULL;
            if ((flags & AT_EMPTY_PATH) && pathsize == 0) {
                targetnode = dirnode;
                targetnode->ref();
            } else {
                res = vfs->resolve(pathbuf, &targetnode, dirnode, !(flags & AT_SYMLINK_NOFOLLOW), procroot);
                if (res < 0) {
                    dirnode->unref();
                    if (procroot) {
                        procroot->unref();
                    }
                    delete[] pathbuf;
                    SYSCALL_RET(res);
                }
            }
            dirnode->unref();
            if (procroot) {
                procroot->unref();
            }
            delete[] pathbuf;
            // Check if we have permission to change the owner.
            bool ok = false;
            struct stat st = targetnode->getattr();
            if (euid == 0) {
                ok = true; // Root can always change owner.
            } else if (euid == st.st_uid) {
                // Non-root can change group to one of their groups.
                if (gid == -1 || gid == st.st_gid) {
                    ok = true;
                }
            }
            if (!ok) {
                targetnode->unref();
                SYSCALL_RET(-EACCES);
            }

            struct stat newattr = st;
            if (uid != -1) {
                newattr.st_uid = uid;
            }
            if (gid != -1) {
                newattr.st_gid = gid;
            }
            targetnode->setattr(newattr);
            targetnode->unref();
            SYSCALL_RET(0);
        }

        extern "C" uint64_t sys_umask(int newmask) {
            SYSCALL_LOG("sys_umask(%o).\n", newmask);

            NSched::Process *proc = NArch::CPU::get()->currthread->process;
            proc->lock.acquire();
            int oldmask = proc->umask;
            proc->umask = newmask & 0777;
            proc->lock.release();

            SYSCALL_RET(oldmask);
        }

        extern "C" ssize_t sys_ftruncate(int fd, off_t len) {
            SYSCALL_LOG("sys_ftruncate(%d, %ld).\n", fd, len);

            if (fd < 0) {
                SYSCALL_RET(-EBADF);
            }

            if (len < 0) {
                SYSCALL_RET(-EINVAL);
            }

            NSched::Process *proc = NArch::CPU::get()->currthread->process;

            FileDescriptor *desc = proc->fdtable->get(fd);
            if (!desc) {
                SYSCALL_RET(-EBADF);
            }

            int accmode = desc->getflags() & O_ACCMODE;
            if (accmode != O_WRONLY && accmode != O_RDWR) {
                SYSCALL_RET(-EINVAL); // POSIX: must be open for writing.
            }

            INode *node = desc->getnode();

            struct stat st = node->getattr();
            if (!S_ISREG(st.st_mode)) {
                node->unref();
                SYSCALL_RET(-EINVAL); // Can only truncate regular files.
            }

            int res = node->truncate(len);
            node->unref();
            SYSCALL_RET(res);
        }

        extern "C" ssize_t sys_sync(void) {
            SYSCALL_LOG("sys_sync().\n");

            vfs->syncall();

            SYSCALL_RET(0);
        }

        extern "C" ssize_t sys_fsync(int fd, int opt) {
            SYSCALL_LOG("sys_fsync(%d, %d).\n", fd, opt);

            NSched::Process *proc = NArch::CPU::get()->currthread->process;

            FileDescriptor *desc = proc->fdtable->get(fd);
            if (!desc) {
                SYSCALL_RET(-EBADF);
            }

            INode *node = desc->getnode();
            int res = node->sync((opt == 0) ? INode::SYNC_FULL : INode::SYNC_DATA);
            node->unref();
            SYSCALL_RET(res);
        }

        extern "C" ssize_t sys_mount(const char *source, const char *target, const char *fstype, uint64_t flags, const void *data) {
            SYSCALL_LOG("sys_mount(%s, %s, %s, %lu, %p).\n", source, target, fstype, flags, data);

            ssize_t srclen = NMem::UserCopy::strnlen(source, 4096);
            if (srclen < 0) {
                SYSCALL_RET(srclen); // Contains errno.
            }

            ssize_t tgtlen = NMem::UserCopy::strnlen(target, 4096);
            if (tgtlen < 0) {
                SYSCALL_RET(tgtlen); // Contains errno.
            }

            ssize_t fstlen = NMem::UserCopy::strnlen(fstype, 256);
            if (fstlen < 0) {
                SYSCALL_RET(fstlen); // Contains errno.
            }

            char *srcbuf = new char[srclen + 1];
            if (!srcbuf) {
                SYSCALL_RET(-ENOMEM);
            }

            char *tgtbuf = new char[tgtlen + 1];
            if (!tgtbuf) {
                delete[] srcbuf;
                SYSCALL_RET(-ENOMEM);
            }

            char *fstbuf = new char[fstlen + 1];
            if (!fstbuf) {
                delete[] srcbuf;
                delete[] tgtbuf;
                SYSCALL_RET(-ENOMEM);
            }

            int res = NMem::UserCopy::strncpyfrom(srcbuf, source, srclen);
            if (res < 0) {
                delete[] srcbuf;
                delete[] tgtbuf;
                delete[] fstbuf;
                SYSCALL_RET(res); // Contains errno.
            }

            res = NMem::UserCopy::strncpyfrom(tgtbuf, target, tgtlen);
            if (res < 0) {
                delete[] srcbuf;
                delete[] tgtbuf;
                delete[] fstbuf;
                SYSCALL_RET(res); // Contains errno.
            }

            res = NMem::UserCopy::strncpyfrom(fstbuf, fstype, fstlen);
            if (res < 0) {
                delete[] srcbuf;
                delete[] tgtbuf;
                delete[] fstbuf;
                SYSCALL_RET(res); // Contains errno.
            }

            srcbuf[srclen] = '\0';
            tgtbuf[tgtlen] = '\0';
            fstbuf[fstlen] = '\0';

            // Perform the mount operation.
            res = vfs->mount(srcbuf, tgtbuf, fstbuf, flags, data);
            delete[] srcbuf;
            delete[] tgtbuf;
            delete[] fstbuf;
            SYSCALL_RET(res);
        }

        extern "C" ssize_t sys_umount(const char *target, int flags) {
            SYSCALL_LOG("sys_umount(%s, %d).\n", target, flags);
            ssize_t tgtlen = NMem::UserCopy::strnlen(target, 4096);
            if (tgtlen < 0) {
                SYSCALL_RET(tgtlen); // Contains errno.
            }

            char *tgtbuf = new char[tgtlen + 1];
            if (!tgtbuf) {
                SYSCALL_RET(-ENOMEM);
            }

            int res = NMem::UserCopy::strncpyfrom(tgtbuf, target, tgtlen);
            if (res < 0) {
                delete[] tgtbuf;
                SYSCALL_RET(res); // Contains errno.
            }

            tgtbuf[tgtlen] = '\0';
            // Perform the unmount operation.
            res = vfs->umount(tgtbuf, flags);
            delete[] tgtbuf;
            SYSCALL_RET(res);
        }

        extern "C" ssize_t sys_rename(int oldfd, const char *oldpath, size_t oldlen, int newfd, const char *newpath, size_t newlen) {
            SYSCALL_LOG("sys_rename(%d, %s, %lu, %d, %s, %lu).\n", oldfd, oldpath, oldlen, newfd, newpath, newlen);

            // Validate and copy old path from userspace.
            ssize_t oldpathsize = NMem::UserCopy::strnlen(oldpath, oldlen);
            if (oldpathsize < 0) {
                SYSCALL_RET(oldpathsize);
            }
            char *oldpathbuf = new char[oldpathsize + 1];
            if (!oldpathbuf) {
                SYSCALL_RET(-ENOMEM);
            }
            int ret = NMem::UserCopy::strncpyfrom(oldpathbuf, oldpath, oldpathsize);
            if (ret < 0) {
                delete[] oldpathbuf;
                SYSCALL_RET(ret);
            }
            oldpathbuf[oldpathsize] = '\0';

            // Validate and copy new path from userspace.
            ssize_t newpathsize = NMem::UserCopy::strnlen(newpath, newlen);
            if (newpathsize < 0) {
                delete[] oldpathbuf;
                SYSCALL_RET(newpathsize);
            }
            char *newpathbuf = new char[newpathsize + 1];
            if (!newpathbuf) {
                delete[] oldpathbuf;
                SYSCALL_RET(-ENOMEM);
            }
            ret = NMem::UserCopy::strncpyfrom(newpathbuf, newpath, newpathsize);
            if (ret < 0) {
                delete[] oldpathbuf;
                delete[] newpathbuf;
                SYSCALL_RET(ret);
            }
            newpathbuf[newpathsize] = '\0';

            NSched::Process *proc = NArch::CPU::get()->currthread->process;
            proc->lock.acquire();

            // Resolve old directory.
            INode *olddirnode;
            if (oldpathbuf[0] == '/') {
                olddirnode = vfs->getroot();
            } else if (oldfd == AT_FDCWD) {
                olddirnode = proc->cwd;
                if (!olddirnode) {
                    olddirnode = vfs->getroot();
                } else {
                    olddirnode->ref();
                }
            } else {
                FileDescriptor *desc = proc->fdtable->get(oldfd);
                if (!desc) {
                    delete[] oldpathbuf;
                    delete[] newpathbuf;
                    proc->lock.release();
                    SYSCALL_RET(-EBADF);
                }
                olddirnode = desc->getnode();
                if (!S_ISDIR(olddirnode->getattr().st_mode)) {
                    olddirnode->unref();
                    delete[] oldpathbuf;
                    delete[] newpathbuf;
                    proc->lock.release();
                    SYSCALL_RET(-ENOTDIR);
                }
            }

            // Resolve new directory.
            INode *newdirnode;
            if (newpathbuf[0] == '/') {
                newdirnode = vfs->getroot();
            } else if (newfd == AT_FDCWD) {
                newdirnode = proc->cwd;
                if (!newdirnode) {
                    newdirnode = vfs->getroot();
                } else {
                    newdirnode->ref();
                }
            } else {
                FileDescriptor *desc = proc->fdtable->get(newfd);
                if (!desc) {
                    olddirnode->unref();
                    delete[] oldpathbuf;
                    delete[] newpathbuf;
                    proc->lock.release();
                    SYSCALL_RET(-EBADF);
                }
                newdirnode = desc->getnode();
                if (!S_ISDIR(newdirnode->getattr().st_mode)) {
                    newdirnode->unref();
                    olddirnode->unref();
                    delete[] oldpathbuf;
                    delete[] newpathbuf;
                    proc->lock.release();
                    SYSCALL_RET(-ENOTDIR);
                }
            }

            int uid = proc->uid;
            int gid = proc->gid;
            INode *procroot = proc->root;
            if (procroot) {
                procroot->ref();
            }
            proc->lock.release();

            // Actual work is done by VFS, of course.
            ssize_t res = vfs->rename(oldpathbuf, olddirnode, newpathbuf, newdirnode, uid, gid, procroot);
            olddirnode->unref();
            newdirnode->unref();
            if (procroot) {
                procroot->unref();
            }
            delete[] oldpathbuf;
            delete[] newpathbuf;
            SYSCALL_RET(res);
        }

        extern "C" ssize_t sys_symlink(int dirfd, const char *target, size_t targetlen, const char *linkpath, size_t linklen) {
            SYSCALL_LOG("sys_symlink(%d, %s, %lu, %s, %lu).\n", dirfd, target, targetlen, linkpath, linklen);

            // Validate and copy target path from userspace.
            ssize_t targetsize = NMem::UserCopy::strnlen(target, targetlen);
            if (targetsize < 0) {
                SYSCALL_RET(targetsize);
            }
            if (targetsize == 0) {
                SYSCALL_RET(-ENOENT); // Empty target is invalid.
            }
            char *targetbuf = new char[targetsize + 1];
            if (!targetbuf) {
                SYSCALL_RET(-ENOMEM);
            }
            int ret = NMem::UserCopy::strncpyfrom(targetbuf, target, targetsize);
            if (ret < 0) {
                delete[] targetbuf;
                SYSCALL_RET(ret);
            }
            targetbuf[targetsize] = '\0';

            // Validate and copy link path from userspace.
            ssize_t linkpathsize = NMem::UserCopy::strnlen(linkpath, linklen);
            if (linkpathsize < 0) {
                delete[] targetbuf;
                SYSCALL_RET(linkpathsize);
            }
            char *linkpathbuf = new char[linkpathsize + 1];
            if (!linkpathbuf) {
                delete[] targetbuf;
                SYSCALL_RET(-ENOMEM);
            }
            ret = NMem::UserCopy::strncpyfrom(linkpathbuf, linkpath, linkpathsize);
            if (ret < 0) {
                delete[] targetbuf;
                delete[] linkpathbuf;
                SYSCALL_RET(ret);
            }
            linkpathbuf[linkpathsize] = '\0';

            NSched::Process *proc = NArch::CPU::get()->currthread->process;
            proc->lock.acquire();

            // Resolve directory for symlink creation.
            INode *dirnode;
            if (linkpathbuf[0] == '/') {
                dirnode = vfs->getroot();
            } else if (dirfd == AT_FDCWD) {
                dirnode = proc->cwd;
                if (!dirnode) {
                    dirnode = vfs->getroot();
                } else {
                    dirnode->ref();
                }
            } else {
                FileDescriptor *desc = proc->fdtable->get(dirfd);
                if (!desc) {
                    delete[] targetbuf;
                    delete[] linkpathbuf;
                    proc->lock.release();
                    SYSCALL_RET(-EBADF);
                }
                dirnode = desc->getnode();
                if (!S_ISDIR(dirnode->getattr().st_mode)) {
                    dirnode->unref();
                    delete[] targetbuf;
                    delete[] linkpathbuf;
                    proc->lock.release();
                    SYSCALL_RET(-ENOTDIR);
                }
            }

            // Get parent directory path of the symlink to check write permission.
            INode *procroot = proc->root;
            if (procroot) {
                procroot->ref();
            }
            proc->lock.release();

            Path linkpobj = Path(linkpathbuf);
            const char *parentpath = linkpobj.dirname();
            INode *parent = NULL;
            ssize_t res = vfs->resolve(parentpath, &parent, dirnode, true, procroot);
            delete parentpath;
            if (res < 0) {
                dirnode->unref();
                if (procroot) {
                    procroot->unref();
                }
                delete[] targetbuf;
                delete[] linkpathbuf;
                SYSCALL_RET(res);
            }

            // Get process credentials.
            proc->lock.acquire();
            int peuid = proc->euid;
            int pegid = proc->egid;
            proc->lock.release();

            // Check write permission on parent directory.
            bool ok = vfs->checkaccess(parent, O_WRONLY | O_EXEC, peuid, pegid);
            if (!ok) {
                parent->unref();
                dirnode->unref();
                if (procroot) {
                    procroot->unref();
                }
                delete[] targetbuf;
                delete[] linkpathbuf;
                SYSCALL_RET(-EACCES);
            }
            parent->unref();

            // Setup symlink attributes.
            struct stat attr {
                .st_mode = static_cast<uint32_t>(S_IFLNK | 0777), // Symlinks typically have 0777 permissions (actual permission determined by target).
                .st_uid = peuid,
                .st_gid = pegid
            };

            // Create the symlink node.
            INode *nodeout = NULL;
            res = vfs->create(linkpathbuf, &nodeout, attr, dirnode, procroot);
            dirnode->unref();
            if (procroot) {
                procroot->unref();
            }
            delete[] linkpathbuf;
            if (res < 0) {
                delete[] targetbuf;
                SYSCALL_RET(res);
            }

            ssize_t written = nodeout->setsymlinkdata(targetbuf, targetsize);
            delete[] targetbuf;

            if (written < 0) {
                nodeout->unref();
                SYSCALL_RET(written);
            }

            nodeout->unref();
            SYSCALL_RET(0);
        }

        extern "C" ssize_t sys_pivotroot(const char *newroot, size_t newlen, const char *putold, size_t putoldlen) {
            SYSCALL_LOG("sys_pivotroot(%s, %lu, %s, %lu).\n", newroot, newlen, putold, putoldlen);

            // Only root (euid == 0) can call pivotroot.
            NSched::Process *proc = NArch::CPU::get()->currthread->process;
            proc->lock.acquire();
            int euid = proc->euid;
            INode *procroot = proc->root;
            if (procroot) {
                procroot->ref(); // Hold reference while we check.
            }
            proc->lock.release();

            if (euid != 0) {
                if (procroot) {
                    procroot->unref();
                }
                SYSCALL_RET(-EPERM);
            }

            // Copy new_root path from userspace.
            ssize_t newrootsize = NMem::UserCopy::strnlen(newroot, newlen);
            if (newrootsize < 0) {
                if (procroot) {
                    procroot->unref();
                }
                SYSCALL_RET(newrootsize);
            }

            char *newrootbuf = new char[newrootsize + 1];
            if (!newrootbuf) {
                if (procroot) {
                    procroot->unref();
                }
                SYSCALL_RET(-ENOMEM);
            }

            int ret = NMem::UserCopy::strncpyfrom(newrootbuf, newroot, newrootsize);
            if (ret < 0) {
                delete[] newrootbuf;
                if (procroot) {
                    procroot->unref();
                }
                SYSCALL_RET(ret);
            }
            newrootbuf[newrootsize] = '\0';

            // Copy put_old path from userspace.
            ssize_t putoldsize = NMem::UserCopy::strnlen(putold, putoldlen);
            if (putoldsize < 0) {
                delete[] newrootbuf;
                if (procroot) {
                    procroot->unref();
                }
                SYSCALL_RET(putoldsize);
            }

            char *putoldbuf = new char[putoldsize + 1];
            if (!putoldbuf) {
                delete[] newrootbuf;
                if (procroot) {
                    procroot->unref();
                }
                SYSCALL_RET(-ENOMEM);
            }

            ret = NMem::UserCopy::strncpyfrom(putoldbuf, putold, putoldsize);
            if (ret < 0) {
                delete[] newrootbuf;
                delete[] putoldbuf;
                if (procroot) {
                    procroot->unref();
                }
                SYSCALL_RET(ret);
            }
            putoldbuf[putoldsize] = '\0';

            // Validate paths are absolute.
            if (newrootbuf[0] != '/' || putoldbuf[0] != '/') {
                delete[] newrootbuf;
                delete[] putoldbuf;
                if (procroot) {
                    procroot->unref();
                }
                SYSCALL_RET(-EINVAL);
            }

            // Normalise paths.
            Path newrootpath = Path(newrootbuf);
            const char *newrootnorm = newrootpath.construct();
            if (!newrootnorm) {
                delete[] newrootbuf;
                delete[] putoldbuf;
                if (procroot) {
                    procroot->unref();
                }
                SYSCALL_RET(-ENOMEM);
            }

            Path putoldpath = Path(putoldbuf);
            const char *putoldnorm = putoldpath.construct();
            if (!putoldnorm) {
                delete[] newrootnorm;
                delete[] newrootbuf;
                delete[] putoldbuf;
                if (procroot) {
                    procroot->unref();
                }
                SYSCALL_RET(-ENOMEM);
            }

            delete[] newrootbuf;
            delete[] putoldbuf;

            // Verify putold path would be under newroot (so it doesn't just poof into thin air).
            size_t newrootnormlen = NLib::strlen(newrootnorm);
            if (NLib::strncmp(putoldnorm, newrootnorm, newrootnormlen) != 0) {
                if (procroot) {
                    procroot->unref();
                }
                delete[] newrootnorm;
                delete[] putoldnorm;
                SYSCALL_RET(-EINVAL);
            }

            // Also verify there's a path separator after (unless newroot is "/").
            if (newrootnormlen > 1 && putoldnorm[newrootnormlen] != '/' && putoldnorm[newrootnormlen] != '\0') {
                if (procroot) {
                    procroot->unref();
                }
                delete[] newrootnorm;
                delete[] putoldnorm;
                SYSCALL_RET(-EINVAL);
            }

            // Resolve putold BEFORE acquiring mount lock (resolve() uses findmount() which takes the lock).
            INode *putoldnode = NULL;
            ssize_t res = vfs->resolve(putoldnorm, &putoldnode, NULL, true, NULL);
            if (res < 0) {
                if (procroot) {
                    procroot->unref();
                }
                delete[] newrootnorm;
                delete[] putoldnorm;
                SYSCALL_RET(res);
            }

            if (!S_ISDIR(putoldnode->getattr().st_mode)) {
                putoldnode->unref();
                if (procroot) {
                    procroot->unref();
                }
                delete[] newrootnorm;
                delete[] putoldnorm;
                SYSCALL_RET(-ENOTDIR);
            }

            // Now acquire mount lock for the rest of the operation.
            NLib::ScopeSpinlock mountguard(&vfs->mountlock);

            // Verify the calling process's root is *actually* the current root (and not something else, or a fake root through chroot).
            INode *currentvfsroot = vfs->getroot();
            if (procroot && procroot != currentvfsroot) {
                procroot->unref();
                delete[] newrootnorm;
                delete[] putoldnorm;
                SYSCALL_RET(-EINVAL);
            }
            if (procroot) {
                procroot->unref();
                procroot = NULL;
            }

            // Find newroot and oldroot mount points.
            struct VFS::mntpoint *newrootmnt = NULL;
            struct VFS::mntpoint *oldrootmnt = NULL;

            NLib::DoubleList<struct VFS::mntpoint>::Iterator it = vfs->mounts.begin();
            for (; it.valid(); it.next()) {
                struct VFS::mntpoint *mnt = it.get();
                if (!NLib::strcmp(mnt->path, newrootnorm)) {
                    newrootmnt = mnt;
                }
                if (!NLib::strcmp(mnt->path, "/")) {
                    oldrootmnt = mnt;
                }
            }

            if (!newrootmnt) {
                // newroot is not a mount point.
                putoldnode->unref();
                delete[] newrootnorm;
                delete[] putoldnorm;
                SYSCALL_RET(-EINVAL);
            }

            if (!oldrootmnt) {
                // No root mount? This shouldn't happen.
                putoldnode->unref();
                delete[] newrootnorm;
                delete[] putoldnorm;
                SYSCALL_RET(-EINVAL);
            }

            // Cannot pivot to current root.
            if (newrootmnt == oldrootmnt) {
                putoldnode->unref();
                delete[] newrootnorm;
                delete[] putoldnorm;
                SYSCALL_RET(-EBUSY);
            }

            // Calculate the relative path from newroot to putold.
            const char *putoldrelative = putoldnorm + newrootnormlen;
            if (*putoldrelative == '/') {
                putoldrelative++; // Skip leading slash.
            }

            // Build the new path for the old root mount. /mnt/oldroot -> /oldroot
            size_t putoldrellen = NLib::strlen(putoldrelative);
            char *oldrootnewpath = new char[putoldrellen + 2]; // +2 for leading "/" and null terminator.
            if (!oldrootnewpath) {
                putoldnode->unref();
                delete[] newrootnorm;
                delete[] putoldnorm;
                SYSCALL_RET(-ENOMEM);
            }
            NLib::memset(oldrootnewpath, 0, putoldrellen + 2); // Ensure null-termination.
            oldrootnewpath[0] = '/';
            NLib::strcpy(oldrootnewpath + 1, (char *)putoldrelative);

            // Update mount paths:
            // 1. All mounts under "/" (except newroot subtree) get prefixed with putold relative path.
            // 2. newroot mount becomes "/".
            // 3. Old root mount becomes putold path (relative to newroot, i.e., "/putold_relative").

            // Pre-allocate all new mount paths to ensure atomicity.
            // Count mounts and allocate path storage.
            size_t mountcount = 0;
            it = vfs->mounts.begin();
            for (; it.valid(); it.next()) {
                mountcount++;
            }

            char **newpaths = new char*[mountcount];
            if (!newpaths) {
                delete[] oldrootnewpath;
                putoldnode->unref();
                delete[] newrootnorm;
                delete[] putoldnorm;
                SYSCALL_RET(-ENOMEM);
            }

            // Initialise to NULL for safe cleanup.
            for (size_t i = 0; i < mountcount; i++) {
                newpaths[i] = NULL;
            }

            // Calculate and allocate all new paths.
            size_t idx = 0;
            bool allocfailed = false;
            it = vfs->mounts.begin();
            for (; it.valid() && !allocfailed; it.next(), idx++) {
                struct VFS::mntpoint *mnt = it.get();

                if (mnt == newrootmnt) {
                    // newroot becomes "/".
                    newpaths[idx] = NLib::strdup("/");
                    if (!newpaths[idx]) {
                        allocfailed = true;
                    }
                } else if (mnt == oldrootmnt) {
                    // Old root becomes the putold path.
                    newpaths[idx] = NLib::strdup(oldrootnewpath);
                    if (!newpaths[idx]) {
                        allocfailed = true;
                    }
                } else {
                    // Check if this mount was under newroot.
                    if (!NLib::strncmp(mnt->path, newrootnorm, newrootnormlen) &&
                        (mnt->path[newrootnormlen] == '/' || mnt->path[newrootnormlen] == '\0')) {
                        // This mount is under newroot, make it relative to newroot.
                        const char *relpath = mnt->path + newrootnormlen;
                        if (*relpath == '\0') {
                            // Keep original path (will be handled specially).
                            newpaths[idx] = NULL;
                        } else {
                            // relpath starts with "/", so it's already absolute-style relative to newroot.
                            newpaths[idx] = NLib::strdup(relpath);
                            if (!newpaths[idx]) {
                                allocfailed = true;
                            }
                        }
                    } else {
                        // This mount was under old root (not under newroot).
                        size_t newpathlen = NLib::strlen(oldrootnewpath) + NLib::strlen(mnt->path) + 1;
                        newpaths[idx] = new char[newpathlen];
                        if (!newpaths[idx]) {
                            allocfailed = true;
                        } else {
                            NLib::strcpy(newpaths[idx], oldrootnewpath);
                            NLib::strcat(newpaths[idx], (char *)mnt->path);
                        }
                    }
                }
            }

            if (allocfailed) {
                // Clean up all allocated paths.
                for (size_t i = 0; i < mountcount; i++) {
                    if (newpaths[i]) {
                        delete[] newpaths[i];
                    }
                }
                delete[] newpaths;
                delete[] oldrootnewpath;
                putoldnode->unref();
                delete[] newrootnorm;
                delete[] putoldnorm;
                SYSCALL_RET(-ENOMEM);
            }

            // Now atomically apply all path updates.
            idx = 0;
            it = vfs->mounts.begin();
            for (; it.valid(); it.next(), idx++) {
                struct VFS::mntpoint *mnt = it.get();
                if (newpaths[idx]) {
                    delete[] mnt->path;
                    mnt->path = newpaths[idx];
                }
            }
            delete[] newpaths;


            INode *newvfsroot = newrootmnt->fs->getroot();
            INode *oldvfsroot = vfs->setroot(newvfsroot);

            INode *oldmntdir = NULL;
            if (putoldrellen > 0) {
                // Traverse each component of the putoldrelative path within the new root filesystem.
                Path relpath = Path(putoldrelative);
                NLib::DoubleList<const char *>::Iterator pathit = relpath.iterator();
                INode *current = newvfsroot;
                current->ref();

                while (pathit.valid()) {
                    const char *comp = *pathit.get();
                    INode *next = current->lookup(comp);
                    current->unref();
                    if (!next) {
                        current = NULL;
                        break;
                    }
                    current = next;
                    pathit.next();
                }
                oldmntdir = current; // May be NULL if lookup failed.
            }

            if (oldrootmnt->mntnode) {
                oldrootmnt->mntnode->unref();
            }
            if (oldmntdir) {
                oldrootmnt->mntnode = oldmntdir; // lookup() returns a referenced node.
            } else {
                // Fallback: if we can't find the directory, use putoldnode (may not work correctly).
                putoldnode->ref();
                oldrootmnt->mntnode = putoldnode;
            }

            if (newrootmnt->mntnode) {
                newrootmnt->mntnode->unref();
            }
            newrootmnt->mntnode = NULL;

            // Now update all processes' root and cwd if they pointed to old root.
            NSched::pidtablelock.acquire();
            NLib::KVHashMap<size_t, NSched::Process *>::Iterator pit = NSched::pidtable->begin();
            for (; pit.valid(); pit.next()) {
                NSched::Process *p = *pit.value();
                p->lock.acquire();

                // If process root was the old VFS root, update to new root.
                if (p->root == oldvfsroot || p->root == NULL) {
                    newvfsroot->ref();
                    if (newvfsroot->fs) {
                        newvfsroot->fs->fsref();  // New filesystem gets a reference
                    }
                    if (p->root) {
                        if (p->root->fs) {
                            p->root->fs->fsunref();  // Old filesystem loses a reference
                        }
                        p->root->unref();
                    }
                    p->root = newvfsroot;
                }

                // If process cwd was the old VFS root, update to new root.
                if (p->cwd == oldvfsroot) {
                    newvfsroot->ref();
                    if (newvfsroot->fs) {
                        newvfsroot->fs->fsref();  // New filesystem gets a reference
                    }
                    if (p->cwd->fs) {
                        p->cwd->fs->fsunref();  // Old filesystem loses a reference
                    }
                    p->cwd->unref();
                    p->cwd = newvfsroot;
                }

                p->lock.release();
            }
            NSched::pidtablelock.release();

            // Release old VFS root reference.
            if (oldvfsroot) {
                oldvfsroot->unref();
            }

            delete[] oldrootnewpath;
            putoldnode->unref();
            delete[] newrootnorm;
            delete[] putoldnorm;

            SYSCALL_RET(0);
        }

    }
}