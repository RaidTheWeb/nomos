#ifndef _FS__VFS_HPP
#define _FS__VFS_HPP

#ifdef __x86_64__
#include <arch/x86_64/sync.hpp>
#endif
#include <lib/bitmap.hpp>
#include <lib/errno.hpp>
#include <lib/list.hpp>
#include <lib/sync.hpp>
#include <stddef.h>
#include <stdint.h>

namespace NFS {

    namespace VFS {

        enum type {
            S_IFMT      = 0170000, // File type bitmask.
            S_IFSOCK    = 0140000, // Socket type.
            S_IFLNK     = 0120000, // Symlink type.
            S_IFREG     = 0100000, // Regular type.
            S_IFBLK     = 0060000, // Block device type.
            S_IFDIR     = 0040000, // Directory type.
            S_IFCHR     = 0020000, // Character device type.
            S_IFIFO     = 0010000, // FIFO pipe type.
            S_NONE      = 0000000
        };

        enum perm {
            S_ISUID     = 04000, // SUID bit.
            S_ISGID     = 02000, // SGID bit.
            S_ISVTX     = 01000,

            S_IRWXU     = 00700, // RWX user mask. Can also be used to set all at once.
            S_IRUSR     = 00400, // User read bit.
            S_IWUSR     = 00200, // User write bit.
            S_IXUSR     = 00100, // User execute bit.

            S_IRWXG     = 00070, // RWX group mask. Can also be used to set all at once.
            S_IRGRP     = 00040, // Group read bit.
            S_IWGRP     = 00020, // Group write bit.
            S_IXGRP     = 00010, // Group execute bit.

            S_IRWXO     = 00007, // RWX other mask. Can also be used to set all at once.
            S_IROTH     = 00004, // Other read bit.
            S_IWOTH     = 00002, // Other write bit.
            S_IXOTH     = 00001  // Other execute bit.
        };

        enum access {
            F_OK        = 0, // File exists.
            R_OK        = 4, // File can be read.
            W_OK        = 2, // File can be written to.
            X_OK        = 1 // File can be executed.
        };

        static const ssize_t AT_FDCWD = -100; // Special FD for openat that signifies we should use the current working directory.


        enum seek {
            SEEK_SET = 0,
            SEEK_CUR = 1,
            SEEK_END = 2
        };

        enum flags {
            O_RDONLY    = 0,
            O_WRONLY    = 1,
            O_RDWR      = 2,

            O_CREAT     = 0100,
            O_EXCL      = 0200,
            O_NOCTTY    = 0400,
            O_TRUNC     = 01000,
            O_APPEND    = 02000,
            O_NONBLOCK  = 04000,
            O_DSYNC     = 010000,
            O_ASYNC     = 020000,
            O_DIRECT    = 040000,
            O_LARGEFILE = 0100000,
            O_DIRECTORY = 0200000,
            O_NOFOLLOW  = 0400000,
            O_NOATIME   = 01000000,
            O_CLOEXEC   = 02000000,
            O_SYNC      = 04010000,
            O_RSYNC     = 04010000,
            O_PATH      = 010000000,
            O_EXEC      = 010000000,
            O_TMPFILE   = 020000000,

            O_ACCMODE   = (03 | O_PATH)
        };

        constexpr bool S_ISSOCK(uint32_t m) {
            return (m & S_IFMT) == S_IFSOCK;
        }
        constexpr bool S_ISLNK(uint32_t m) {
            return (m & S_IFMT) == S_IFLNK;
        }
        constexpr bool S_ISREG(uint32_t m) {
            return (m & S_IFMT) == S_IFREG;
        }
        constexpr bool S_ISBLK(uint32_t m) {
            return (m & S_IFMT) == S_IFBLK;
        }
        constexpr bool S_ISDIR(uint32_t m) {
            return (m & S_IFMT) == S_IFDIR;
        }
        constexpr bool S_ISCHR(uint32_t m) {
            return (m & S_IFMT) == S_IFCHR;
        }
        constexpr bool S_ISFIFO(uint32_t m) {
            return (m & S_IFMT) == S_IFIFO;
        }

        struct stat {
            uint64_t st_dev     = 0;
            uint32_t st_ino     = 0;
            uint32_t st_mode    = 0;
            uint32_t st_nlink   = 0;
            uint32_t st_uid     = 0;
            uint32_t st_gid     = 0;
            uint64_t st_rdev    = 0;
            off_t st_size       = 0;
            off_t st_blksize    = 0;
            off_t st_blocks     = 0;
            uint64_t st_atime   = 0;
            uint64_t st_mtime   = 0;
            uint64_t st_ctime   = 0;
        };

        enum pollevents {
            POLLIN              = (1 << 0), // Data to read.
            POLLPRI             = (1 << 1), // Urgent data to read.
            POLLOUT             = (1 << 2), // Write can occur.
            POLLERR             = (1 << 3), // Error.
            POLLHUP             = (1 << 4), // Hang up.
            POLLNVAL            = (1 << 5), // Invalid.
            POLLRDNORM          = (1 << 6), // POLLIN.
            POLLWRNORM          = (1 << 7)  // POLLOUT.
        };

        struct pollfd {
            int fd;
            short events;
            short revents;
        };

        class IFileSystem;

        class Path {
            private:
                NLib::DoubleList<const char *> components;
                bool absolute;
            public:
                // Version to build path from scratch.
                Path(bool absolute) {
                    this->absolute = absolute;
                }

                Path(const char *path) {
                    absolute = path[0] == '/'; // If it starts with /, it's absolute.
                    const char *start = path + (absolute ? 1 : 0);
                    const char *end = start;

                    while (*end) {
                        while (*end && *end != '/') {
                            end++;
                        }

                        if (end > start) {
                            char *comp = NLib::strndup(start, end - start);

                            if (!NLib::strncmp(comp, ".", end - start)) {
                                ; // Nothing needs to be done, basically ignored.
                            } else if (!NLib::strncmp(comp, "..", end - start)) { // We can resolve moving down a directory within the path itself. But only if we actually have components to work with. Otherwise, we keep `..`.
                                if (!this->components.empty() && NLib::strcmp(this->components.back(), "..")) {
                                    this->components.popback(); // We move back down.
                                } else if (!this->absolute) {
                                    this->components.pushback(comp); // Push .. for relative.
                                }
                            } else {
                                this->components.pushback(comp); // Move up.
                            }
                        }

                        while (*end == '/') {
                            end++;
                        }
                        start = end;
                    }
                }

                ~Path(void) {
                    this->components.foreach([](const char **data) {
                        delete *data; // Free memory.
                    });
                }

                bool isabsolute(void) {
                    return this->absolute;
                }

                // Force path to be absolute. Valuable in path concatenation.
                void setabsolute(void) {
                    this->absolute = true;
                }

                NLib::DoubleList<const char *>::Iterator iterator(void) {
                    return this->components.begin();
                }

                void pushcomponent(const char *comp, bool back = true) {
                    char *dup = NLib::strdup(comp);

                    if (back) {
                        this->components.pushback(dup);
                    } else {
                        this->components.push(dup);
                    }
                }

                const char *construct(void) {
                    char *res = new char[1024]; // Allocate string.
                    NLib::memset(res, 0, 1024);
                    char *ptr = res; // Point to start for working pointer.

                    if (this->absolute) {
                        *ptr++ = '/';
                    }

                    this->components.forcmp([](const char **c, void *udata) {
                        const char *comp = *c;
                        char **p = (char **)udata;
                        for (size_t i = 0; i < NLib::strlen(comp); i++) {
                            *(*p) = (char)comp[i]; // Set part.
                            (*p)++; // Increment pointer.
                        }
                        *(*p) = '/'; // Add slash between components.
                        (*p)++;
                    }, (void *)&ptr);

                    // Remove trailing zero.
                    if (!this->components.empty()) {
                        *(ptr - 1) = '\0';
                    }

                    return res;
                }

                bool equals(const char *normalised) {
                    const char *path = this->construct();
                    if (!NLib::strcmp(path, normalised)) {
                        delete path;
                        return true;
                    }
                    return false;
                }

                size_t depth(void) {
                    return this->components.size();
                }

                const char *basename(void) {
                    if (this->components.empty()) {
                        return this->absolute ? "/" : "";
                    }
                    return this->components.back();
                }

                // NOTE: Caller is expected to free result.
                const char *dirname(void) {
                    if (this->components.empty()) {
                        return this->absolute ? "/" : "";
                    }

                    const char *base = this->components.popback();
                    const char *ret = this->construct();
                    this->components.pushback(base); // Add back.
                    return ret;
                }
        };

        // Generic VFS node interface.
        class INode {
            protected:
                uint32_t refcount = 0;
                NArch::Spinlock metalock; // Meta lock for this node.
                IFileSystem *fs;
                struct stat attr;
                const char *name;
                INode *parent = NULL;
            public:
                INode(IFileSystem *fs, const char *name, struct stat attr) {
                    this->fs = fs;
                    this->attr = attr;
                    this->name = NLib::strdup(name);
                }

                virtual ~INode(void) = default;

                virtual ssize_t read(void *buf, size_t count, off_t offset, int fdflags) = 0;
                virtual ssize_t write(const void *buf, size_t count, off_t offset, int fdflags) = 0;
                virtual int open(int flags) {
                    (void)flags;
                    return 0;
                }
                virtual int close(int fdflags) {
                    (void)fdflags;
                    return 0;
                }
                virtual int mmap(void *addr, size_t offset, uint64_t flags, int fdflags) {
                    (void)addr;
                    (void)offset;
                    (void)flags;
                    (void)fdflags;
                    return -EFAULT;
                }
                virtual int munmap(void *addr, int fdflags) {
                    (void)addr;
                    (void)fdflags;
                    return -EFAULT;
                }
                virtual int ioctl(unsigned long request, uint64_t arg) {
                    (void)request;
                    (void)arg;
                    return -EINVAL;
                }
                virtual int poll(int events, int *revents, int fdflags) {
                    (void)events;
                    (void)revents;
                    (void)fdflags;
                    return -EINVAL;
                }
                virtual int stat(struct stat *st) {
                    *st = this->getattr();
                    return 0;
                }

                // Locate child by name.
                virtual INode *lookup(const char *name) = 0;
                // Add child node.
                virtual bool add(INode *node) = 0;
                // Remove child node by name.
                virtual bool remove(const char *name) = 0;

                void setparent(INode *parent) {
                    NLib::ScopeSpinlock guard(&this->metalock);
                    this->parent = parent;
                }

                INode *getparent(void) {
                    NLib::ScopeSpinlock guard(&this->metalock);
                    return this->parent;
                }

                const char *getname(void) {
                    NLib::ScopeSpinlock guard(&this->metalock);
                    return this->name;
                }

                virtual INode *resolvesymlink(void) = 0;

                struct stat getattr(void) {
                    NLib::ScopeSpinlock guard(&this->metalock);
                    return this->attr;
                }

                void setattr(struct stat attr) {
                    NLib::ScopeSpinlock guard(&this->metalock);
                    this->attr = attr;
                }

                void ref(void) {
                    __atomic_add_fetch(&this->refcount, 1, memory_order_seq_cst);
                }
                void unref(void) {
                    __atomic_sub_fetch(&this->refcount, 1, memory_order_seq_cst);
                }
        };

        class VFS;

        // Generic filesystem interface.
        class IFileSystem {
            protected:
                INode *root = NULL;
                NArch::Spinlock spin;
                VFS *vfs;
                bool mounted = false;
            public:
                virtual ~IFileSystem(void) {
                    if (this->root) {
                        this->root->unref();
                    }
                }

                virtual INode *getroot(void) {
                    this->root->ref();
                    return this->root;
                }

                virtual VFS *getvfs(void) {
                    return this->vfs;
                }

                virtual int mount(const char *path) = 0; // Called upon mount -> Good for initialising nodes.
                virtual int umount(void) = 0; // Called upon unmount -> Good for clean up.
                virtual int sync(void) = 0; // Called whenever a sync is required.

                // Create a node.
                virtual INode *create(const char *name, struct stat attr) = 0;
        };

        class VFS {
            private:
                struct mntpoint {
                    const char *path;
                    IFileSystem *fs;
                    INode *mntnode;
                };
                NLib::DoubleList<struct mntpoint> mounts;
                NArch::Spinlock mountlock; // XXX: RW lock?

                INode *root = NULL;

                struct mntpoint *findmount(Path *path);
            public:
                // Mount filesystem on path.
                int mount(const char *path, IFileSystem *fs);
                // Unmount filesystem on path.
                int umount(const char *path);

                virtual INode *getroot(void) {
                    this->root->ref();
                    return this->root;
                }

                // Check if UID or GID are allowed to access the node, given the flags.
                bool checkaccess(INode *node, int flags, uint32_t uid, uint32_t gid);

                // Resolve node by path.
                INode *resolve(const char *path, INode *relativeto = NULL, bool symlink = true);

                INode *create(const char *path, struct stat attr);
        };

        class FileDescriptor {
            private:
                INode *node;
                size_t offset; // In-file offset.
                size_t refcount; // Reference count.
                int flags;
            public:

                FileDescriptor(INode *node, int flags) {
                    this->refcount = 1;
                    this->flags = flags;
                    this->offset = 0;
                    this->node = node;
                    if (this->node) {
                        this->node->ref();
                    }
                }

                ~FileDescriptor(void) {
                    if (this->node) {
                        this->node->unref();
                    }
                }

                INode *getnode(void) {
                    this->node->ref();
                    return this->node;
                }

                int getflags(void) {
                    return this->flags;
                }

                size_t getoff(void) {
                    return __atomic_load_n(&this->offset, memory_order_seq_cst);
                }

                void setoff(off_t off) {
                    __atomic_store_n(&this->offset, off, memory_order_seq_cst);
                }

                void addoff(off_t by) {
                    __atomic_add_fetch(&this->offset, by, memory_order_seq_cst);
                }

                size_t ref(void) {
                    __atomic_add_fetch(&this->refcount, 1, memory_order_seq_cst);
                    return __atomic_load_n(&this->refcount, memory_order_seq_cst);
                }

                size_t getref(void) {
                    return __atomic_load_n(&this->refcount, memory_order_seq_cst);
                }

                size_t unref(void) {
                    __atomic_sub_fetch(&this->refcount, 1, memory_order_seq_cst);
                    return __atomic_load_n(&this->refcount, memory_order_seq_cst);
                }
        };

        class FileDescriptorTable {
            private:
                static const int MAXFDS = 1024; // Hard limit on the number of FDs a single descriptor table is capable of handling. Upper limit prevents expansion that would cripple the kernel.

                NArch::Spinlock lock;
                size_t maxfds = 0; // Current maximum number of file descriptors.
                NLib::Bitmap openfds; // File descriptors currently open.
                NLib::Bitmap closeonexec; // File descriptors that we should close before using exec().
                NLib::Vector<FileDescriptor *> fds;
            public:
                FileDescriptorTable(void) : openfds(256), closeonexec(256) {
                    this->fds.resize(256);
                }

                ~FileDescriptorTable(void) {
                    this->closeall();
                }

                void reserve(int fd, INode *node, int flags);

                int open(INode *node, int flags);
                int close(int fd);

                int dup(int oldfd);
                int dup2(int oldfd, int newfd);

                FileDescriptor *get(int fd);

                FileDescriptorTable *fork(void);

                void doexec(void);

                void closeall(void);
        };

        extern VFS vfs;
    }
}

#endif
