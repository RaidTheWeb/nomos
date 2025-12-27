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

// Forward declaration for page cache integration.
namespace NMem {
    class RadixTree;
    class CachePage;
}

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

        enum fcntlcmd {
            F_DUPFD = 0,
            F_GETFD = 1,
            F_SETFD = 2,
            F_GETFL = 3,
            F_SETFL = 4,
            F_GETLK64 = 5,
            F_SETLK64 = 6,
            F_SETLKW64 = 7,

            F_DUPFD_CLOEXEC = 1030
        };

        enum fdflags {
            FD_CLOEXEC = 1
        };

        enum atflags {
            AT_FDCWD                = -100, // Special value used to indicate current working directory.
            AT_SYMLINK_NOFOLLOW     = 0x100,
            AT_REMOVEDIR            = 0x200,
            AT_SYMLINK_FOLLOW       = 0x400,
            AT_EACCESS              = 0x200,
            AT_EMPTY_PATH           = 0x1000
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

        // Is the SUID bit present?
        constexpr bool S_ISSUID(uint32_t m) {
            return (m & S_ISUID);
        }

        // Is the SGID bit present?
        constexpr bool S_ISSGID(uint32_t m) {
            return (m & S_ISGID);
        }

        struct stat {
            uint64_t st_dev     = 0;
            uint64_t st_ino     = 0;
            uint64_t st_nlink   = 1; // Start with a hard link to ourselves. Unlink decrements this, and will delete the node when it reaches 0, and the node has no refcount.
            uint32_t st_mode    = 0;
            uint32_t st_uid     = 0;
            uint32_t st_gid     = 0;
            uint64_t st_rdev    = 0;
            off_t st_size       = 0;
            int64_t st_blksize    = 0;
            int64_t st_blocks     = 0;
            uint64_t st_atime   = 0;
            uint64_t st_mtime   = 0;
            uint64_t st_ctime   = 0;
        };

        struct dirent {
            uint32_t d_ino;              // Inode number.
            off_t d_off;                 // Offset to the next dirent.
            uint16_t d_reclen;           // Length of this record.
            uint8_t d_type;              // Type of file.
            char d_name[256];            // Filename (null-terminated).
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
                // Reference counting semantics are fairly complex.
                // Each time a process opens a file, the refcount is incremented.
                // Each time a process closes a file, the refcount is decremented.
                // Each time a process is forked, refcount is NOT incremented (child shares same open file descriptor).
                // File hard links increment st_nlink in the stat structure.
                // Each time unlink is called, st_nlink is decremented.
                // When st_nlink reaches 0, the file is unlinked from the filesystem namespace.
                // However, the file's data and node are only deleted when both st_nlink and refcount reach 0.
                // This ensures that open file descriptors remain valid even after unlinking.
                size_t refcount = 0;
                NArch::Spinlock metalock; // Meta lock for this node.
                struct stat attr;
                const char *name;
                INode *parent = NULL;

                // Special redirect node for abstracting operations to another node (e.g., for FIFOs).
                INode *redirect = NULL;

                NMem::RadixTree *pagecache = NULL;
            public:
                IFileSystem *fs;

                enum syncmode {
                    SYNC_NONE,
                    SYNC_DATA,
                    SYNC_FULL
                };

                INode(IFileSystem *fs, const char *name, struct stat attr) {
                    this->fs = fs;
                    this->attr = attr;
                    this->name = NLib::strdup(name);
                }

                virtual ~INode(void) = default;

                virtual ssize_t read(void *buf, size_t count, off_t offset, int fdflags) = 0;
                virtual ssize_t write(const void *buf, size_t count, off_t offset, int fdflags) = 0;
                virtual ssize_t readdir(void *buf, size_t count, off_t offset) = 0;
                virtual int open(int flags) {
                    (void)flags;
                    return 0;
                }
                virtual int close(int fdflags) {
                    (void)fdflags;
                    return 0;
                }
                virtual int mmap(void *addr, size_t count, size_t offset, uint64_t flags, int fdflags) {
                    (void)addr;
                    (void)offset;
                    (void)flags;
                    (void)fdflags;
                    return -EFAULT;
                }
                virtual int munmap(void *addr, size_t count, size_t offset, int fdflags) {
                    (void)addr;
                    (void)count;
                    (void)offset;
                    (void)fdflags;
                    return -EFAULT;
                }
                virtual int ioctl(unsigned long request, uint64_t arg) {
                    (void)request;
                    (void)arg;
                    return -EINVAL;
                }
                virtual int poll(short events, short *revents, int fdflags) {
                    (void)events;
                    (void)revents;
                    (void)fdflags;
                    return -EINVAL;
                }
                virtual int stat(struct stat *st) {
                    NLib::ScopeSpinlock guard(&this->metalock);
                    *st = this->attr;
                    return 0;
                }
                virtual int truncate(off_t length) {
                    (void)length;
                    return -EFAULT;
                }
                virtual int sync(enum syncmode mode) {
                    (void)mode;
                    return 0;
                }

                // Locate child by name.
                virtual INode *lookup(const char *name) = 0;
                // Add child node.
                virtual bool add(INode *node) = 0;
                // Remove child node by name.
                virtual bool remove(const char *name) = 0;
                virtual bool empty(void) = 0;

                virtual int unlink(uint64_t *nlink = NULL) {
                    NLib::ScopeSpinlock guard(&this->metalock);
                    if (this->attr.st_nlink == 0) {
                        return -ENOENT;
                    }
                    if (S_ISDIR(this->attr.st_mode)) {
                        if (this->attr.st_nlink < 2) {
                            return -ENOENT; // Inconsistent state.
                        }
                        this->attr.st_nlink -= 2; // Decrement for all references.
                    } else {
                        this->attr.st_nlink--;
                    }
                    if (nlink) {
                        *nlink = this->attr.st_nlink; // Return new link count, for filesystems that need it.
                    }
                    // Return 0 if node can be deleted.
                    if (this->attr.st_nlink == 0 && __atomic_load_n(&this->refcount, memory_order_seq_cst) == 0) {
                        return 0;
                    }
                    NUtil::printf("INode: unlink called, nlink now %llu, refcount %lu\n", this->attr.st_nlink, this->refcount);
                    return 1;
                }

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

                void setname(const char *newname) {
                    NLib::ScopeSpinlock guard(&this->metalock);
                    delete this->name;
                    this->name = NLib::strdup(newname);
                }

                INode *getredirect(void) {
                    NLib::ScopeSpinlock guard(&this->metalock);
                    if (!this->redirect) {
                        return NULL;
                    }
                    this->redirect->ref();
                    return this->redirect;
                }

                virtual INode *resolvesymlink(void) = 0;
                virtual ssize_t readlink(char *buf, size_t bufsize) = 0;

                struct stat getattr(void) {
                    struct stat st;
                    this->stat(&st);
                    return st;
                }

                void setattr(struct stat attr) {
                    NLib::ScopeSpinlock guard(&this->metalock);
                    this->attr = attr;
                }

                Path getpath(void);

                // When wanting to use this node, call ref() to increase reference count.
                void ref(void) {
                    __atomic_add_fetch(&this->refcount, 1, memory_order_seq_cst);
                }

                size_t getrefcount(void) {
                    return __atomic_load_n(&this->refcount, memory_order_seq_cst);
                }

                // When done with this node, call unref() to decrease reference count.
                // This lets the filesystem know when it can safely delete this node (no process is using it anymore).
                void unref(void) {
                    assert(this->refcount > 0, "INode: Attempting to unref node with zero refcount.\n");
                    __atomic_sub_fetch(&this->refcount, 1, memory_order_seq_cst);
                }

                // Get the page cache for this inode. Creates one if it doesn't exist.
                NMem::RadixTree *getpagecache(void);

                // Find a cached page by offset.
                NMem::CachePage *findcachedpage(off_t offset);

                // Find or create a cached page.
                NMem::CachePage *getorcacheepage(off_t offset);

                // Invalidate all cached pages for this inode.
                void invalidatecache(void);

                // Sync all dirty cached pages for this inode.
                int synccache(void);

                // Read data through the page cache.
                ssize_t readcached(void *buf, size_t count, off_t offset);

                // Write data through the page cache.
                ssize_t writecached(const void *buf, size_t count, off_t offset);



                // Read page, but we can override it for speeding up page-wise reads.
                virtual int readpage(NMem::CachePage *page);
                // Write page, but we can override it for speeding up page-wise writes.
                virtual int writepage(NMem::CachePage *page);
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

                virtual int mount(const char *src, const char *path, INode *mntnode, uint64_t flags, const void *data) = 0; // Called upon mount -> Good for initialising nodes.
                virtual int umount(int flags) = 0; // Called upon unmount -> Good for clean up.
                virtual int sync(void) = 0; // Called whenever a sync is required.

                // Create a node.
                virtual ssize_t create(const char *name, INode **nodeout, struct stat attr) = 0;
                // Unlink a node from its parent, on the filesystem. NOTE: Expects caller to hold references to both node and parent, and will unref them as needed.
                virtual int unlink(INode *node, INode *parent) = 0; // Unlink a node.
                // Rename a node.
                virtual int rename(INode *oldparent, INode *node, INode *newparent, const char *newname, INode *target) {
                    (void)oldparent;
                    (void)node;
                    (void)newparent;
                    (void)newname;
                    (void)target;
                    return -EXDEV;
                }
        };

        typedef IFileSystem *(fsfactory_t)(VFS *vfs);

        __attribute__((used))
        static const uint32_t FS_MAGIC = 0x5346534c; // "LSFS" in little-endian

        struct fsreginfo {
            const char *name;
        };

        struct fsregentry {
            uint32_t magic;
            fsfactory_t *factory;
            struct fsreginfo *info;
        } __attribute__((aligned(16)));

        extern "C" struct fsregentry __filesystems_start[];
        extern "C" struct fsregentry __filesystems_end[];

        // Call this function at the bottom of filesystem implementation files to register them.
#define REGFS(fsname, factoryfn, fsinfo) \
    extern "C" __attribute__((section(".filesystems"), used)) struct NFS::VFS::fsregentry fsname##_entry = { \
        .magic = NFS::VFS::FS_MAGIC, \
        .factory = factoryfn, \
        .info = fsinfo \
    }

        class VFS {
            public:
                struct mntpoint {
                    const char *path;
                    IFileSystem *fs;
                    INode *mntnode;
                };

                NArch::Spinlock mountlock; // XXX: RW lock?

                NLib::DoubleList<struct mntpoint> mounts;

                NLib::HashMap<fsfactory_t *> filesystems;
            private:

                INode *root = NULL;

                struct mntpoint *_findmount(Path *path);
            public:
                VFS(void) { };

                struct mntpoint *findmount(Path *path);

                // Mount filesystem on path, with a new filesystem instance.
                int mount(const char *src, const char *path, const char *fs, uint64_t flags, const void *data);
                // Mount filesystem on path, with an existing filesystem instance.
                int mount(const char *src, const char *path, IFileSystem *fs, uint64_t flags, const void *data);
                // Unmount filesystem on path.
                int umount(const char *path, int flags);

                virtual INode *getroot(void) {
                    this->root->ref();
                    return this->root;
                }

                // Check if UID or GID are allowed to access the node, given the flags.
                bool checkaccess(INode *node, int flags, uint32_t uid, uint32_t gid);

                // Resolve node by path.
                ssize_t resolve(const char *path, INode **nodeout, INode *relativeto = NULL, bool symlink = true);

                ssize_t create(const char *path, INode **nodeout, struct stat attr, INode *relativeto = NULL);
                int unlink(const char *path, INode *relativeto = NULL, int flags = 0, int uid = 0, int gid = 0);
                int rename(const char *oldpath, INode *oldrelativeto, const char *newpath, INode *newrelativeto, int uid = 0, int gid = 0);

                int identifyfs(const char *src);

                // Sync all mounted filesystems.
                void syncall(void);
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
                    return __atomic_load_n(&this->flags, memory_order_acquire);
                }

                void setflags(int flags) {
                    __atomic_store_n(&this->flags, flags, memory_order_release);
                }

                size_t getoff(void) {
                    return __atomic_load_n(&this->offset, memory_order_acquire);
                }

                void setoff(off_t off) {
                    __atomic_store_n(&this->offset, off, memory_order_release);
                }

                void addoff(off_t by) {
                    __atomic_add_fetch(&this->offset, by, memory_order_acq_rel);
                }

                size_t ref(void) {
                    __atomic_add_fetch(&this->refcount, 1, memory_order_acq_rel);
                    return __atomic_load_n(&this->refcount, memory_order_acquire);
                }

                size_t getref(void) {
                    return __atomic_load_n(&this->refcount, memory_order_acquire);
                }

                size_t unref(void) {
                    __atomic_sub_fetch(&this->refcount, 1, memory_order_acq_rel);
                    return __atomic_load_n(&this->refcount, memory_order_acquire);
                }
        };

        class FileDescriptorTable {
            private:
                static const int MAXFDS = 1024; // Hard limit on the number of FDs a single descriptor table is capable of handling. Upper limit prevents expansion that would cripple the kernel.

                NLib::RWLock lock;
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
                int dup2(int oldfd, int newfd, bool fcntl = false);

                FileDescriptor *get(int fd);

                FileDescriptorTable *fork(void);

                void doexec(void);

                void setcloseonexec(int fd, bool closeit);
                bool iscloseonexec(int fd);

                void closeall(void);
        };

        extern VFS *vfs;
    }
}

#endif
