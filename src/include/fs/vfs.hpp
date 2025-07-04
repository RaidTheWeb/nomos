#ifndef _FS__VFS_HPP
#define _FS__VFS_HPP

#ifdef __x86_64__
#include <arch/x86_64/sync.hpp>
#endif
#include <lib/list.hpp>
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

        class IFileSystem;

        class Path {
            private:
                NLib::DoubleList<const char *> components;
                bool absolute;
            public:
                Path(const char *path) {
                    absolute = path[0] == '/'; // If it starts with /, it's absolute.
                    const char *start = path + (absolute ? 1 : 0);
                    const char *end = start;

                    while (*end) {
                        while (*end && *end != '/') {
                            end++;
                        }

                        if (end > start) {
                            char *comp = new char[(end - start) + 1];
                            NLib::strncpy(comp, (char *)start, end - start);
                            comp[end - start] = '\0';

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

                bool isabsolute(void) {
                    return this->absolute;
                }

                NLib::DoubleList<const char *>::Iterator iterator(void) {
                    return this->components.begin();
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

                // XXX: Caller is expected to free result.
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
                NArch::Spinlock spin;
                IFileSystem *fs;
                struct stat attr;
                const char *name;
            public:
                INode(IFileSystem *fs, const char *name, struct stat attr) {
                    this->fs = fs;
                    this->attr = attr;
                    this->name = name;
                }

                virtual ~INode(void) = default;

                virtual ssize_t read(void *buf, size_t count, off_t offset) = 0;
                virtual ssize_t write(const void *buf, size_t count, off_t offset) = 0;

                // Locate child by name.
                virtual INode *lookup(const char *name) = 0;
                // Add child node.
                virtual bool add(INode *node) = 0;
                // Remove child node by name.
                virtual bool remove(const char *name) = 0;

                struct stat getattr(void) {
                    NLib::ScopeSpinlock guard(&this->spin);
                    return this->attr;
                }

                void setattr(struct stat attr) {
                    NLib::ScopeSpinlock guard(&this->spin);
                    this->attr = attr;
                }

                void ref(void) {
                    __atomic_add_fetch(&this->refcount, 1, memory_order_seq_cst);
                }
                void unref(void) {
                    __atomic_sub_fetch(&this->refcount, 1, memory_order_seq_cst);
                }
        };

        // Generic filesystem interface.
        class IFileSystem {
            protected:
                INode *root = NULL;
                NArch::Spinlock spin;
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

                virtual int mount(void) = 0; // Called upon mount -> Good for initialising nodes.
                virtual int unmount(void) = 0; // Called upon unmount -> Good for clean up.
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

                // VFS(void);
                ~VFS(void);

                // Mount filesystem on path.
                int mount(const char *path, IFileSystem *fs);
                // Unmount filesystem on path.
                int umount(const char *path);

                // Resolve node by path.
                INode *resolve(const char *path, INode *relativeto = NULL);

                INode *create(const char *path, struct stat attr);
        };
    }
}

#endif
