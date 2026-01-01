#include <fs/posixtar.hpp>
#include <fs/vfs.hpp>
#include <lib/align.hpp>
#include <lib/errno.hpp>
#include <lib/string.hpp>
#include <util/kprint.hpp>
#include <std/stddef.h>

namespace NFS {
    namespace POSIXTAR {

        int POSIXTARFileSystem::mount(const char *src, const char *path, VFS::INode *mntnode, uint64_t flags, const void *data) {
            (void)src;
            (void)flags;
            (void)data;
            int super = this->RAMFS::RAMFileSystem::mount(NULL, path, mntnode, 0, NULL); // Super.
            if (super != 0) {
                return super;
            }

            size_t size = this->modinfo.size;
            uintptr_t loc = this->modinfo.loc;

            NUtil::printf("[fs/ustar]: Enumerating USTAR module `%s` at %p with length %lu.\n", this->modinfo.path, loc, size);

            struct info *current = (struct info *)loc; // First file is at the start of the archive.
            char longpath[4096] = {0}; // Buffer to store long paths (GNU tar extension).
            char longlink[4096] = {0}; // Buffer to store long link names (GNU tar extension).
            bool haslongpath = false; // Track if we have a pending long path.
            bool haslonglink = false; // Track if we have a pending long link name.

            // As long as we feature the USTAR magic value, it's "theoretically" a valid file.
            while ((uintptr_t)current + sizeof(struct info) <= (loc + size) && !NLib::strncmp(current->magic, "ustar", 5)) {
                char basename[4096] = {0};
                char *lname = current->linkname;

                if (haslongpath) { // Use the long path previously stored.
                    NLib::strncpy(basename, longpath, sizeof(basename) - 1);
                    haslongpath = false;
                } else { // Use the name field.
                    size_t namelen = 0;
                    while (namelen < sizeof(current->name) && current->name[namelen] != '\0') {
                        namelen++;
                    }
                    NLib::memcpy(basename, current->name, namelen);
                    basename[namelen] = '\0';
                }

                if (!NLib::strcmp(basename, "./")) {
                    uint64_t skipsize = oct2int(current->size, sizeof(current->size));
                    current = (struct info *)((uintptr_t)current + 512 + NLib::alignup(skipsize, 512));
                    continue;
                }

                char name[8192];
                NUtil::snprintf(name, sizeof(name), "%s/%s", path, basename);

                uint64_t fsize = oct2int(current->size, sizeof(current->size));
                uint64_t mtime = oct2int(current->mtime, sizeof(current->mtime));
                uint64_t mode = oct2int(current->mode, sizeof(current->mode));
                uint64_t uid = oct2int(current->uid, sizeof(current->uid));
                uint64_t gid = oct2int(current->gid, sizeof(current->gid));

                VFS::INode *node = NULL;
                switch (current->type) {
                    case type::FILE: {
                        if ((uintptr_t)current + 512 + fsize > loc + size) {
                            NUtil::printf("[fs/ustar]: Invalid file size %lu exceeding archive bounds.\n", fsize);
                            return -EINVAL;
                        }

                        struct VFS::stat attr;
                        attr.st_mode = mode | VFS::S_IFREG;
                        attr.st_uid = uid;
                        attr.st_gid = gid;
                        attr.st_mtime = mtime;
                        attr.st_blksize = 512;
                        attr.st_atime = mtime;
                        attr.st_ctime = mtime;
                        ssize_t res = VFS::vfs->create(name, &node, attr);
                        assert(res == 0, "Failed to allocate VFS node.\n");

                        size_t count = node->write((void *)((uintptr_t)current + 512), fsize, 0, 0);
                        assert(count == fsize, "Failed to write VFS node data.\n");
                        node->unref();
                        break;
                    }
                    case type::DIR: {
                        struct VFS::stat attr;
                        attr.st_mode = mode | VFS::S_IFDIR;
                        attr.st_uid = uid;
                        attr.st_gid = gid;
                        attr.st_mtime = mtime;
                        attr.st_atime = mtime;
                        attr.st_ctime = mtime;
                        attr.st_nlink = 2; // Directories start with 2 links (self and parent).
                        ssize_t res = VFS::vfs->create(name, &node, attr);
                        assert(res == 0, "Failed to allocate VFS node.\n");
                        node->unref();
                        break;
                    }
                    case type::SYMLINK: {
                        struct VFS::stat attr;
                        attr.st_mode = mode | VFS::S_IFLNK;
                        attr.st_uid = uid;
                        attr.st_gid = gid;
                        attr.st_mtime = mtime;
                        ssize_t res = VFS::vfs->create(name, &node, attr);
                        assert(res == 0, "Failed to allocate VFS node.\n");

                        // Use long link name if available, otherwise use linkname field.
                        const char *linktarget;
                        size_t len;
                        if (haslonglink) {
                            linktarget = longlink;
                            len = NLib::strlen(longlink);
                            haslonglink = false;
                        } else {
                            linktarget = lname;
                            len = 0;
                            while (len < sizeof(current->linkname) && lname[len] != '\0') {
                                len++;
                            }
                        }

                        size_t count = node->write(linktarget, len + 1, 0, 0);
                        assert(count == len + 1, "Failed to write link to VFS node.\n");
                        node->unref();
                        break;
                    }
                    case type::PATH: {
                        if ((uintptr_t)current + 512 + fsize > loc + size) {
                            NUtil::printf("[fs/ustar]: Invalid long path size %lu exceeding archive bounds.\n", fsize);
                            return -EINVAL;
                        }
                        if (fsize >= sizeof(longpath)) {
                            NUtil::printf("[fs/ustar]: Long path too large (%lu >= %lu).\n", fsize, sizeof(longpath));
                            return -E2BIG;
                        }
                        // Copy the long path data into our buffer
                        NLib::memcpy(longpath, (void *)((uintptr_t)current + 512), fsize);
                        longpath[fsize] = '\0';
                        haslongpath = true;
                        break;
                    }
                    case type::LINK: {
                        if ((uintptr_t)current + 512 + fsize > loc + size) {
                            NUtil::printf("[fs/ustar]: Invalid long link size %lu exceeding archive bounds.\n", fsize);
                            return -EINVAL;
                        }
                        if (fsize >= sizeof(longlink)) {
                            NUtil::printf("[fs/ustar]: Long link too large (%lu >= %lu).\n", fsize, sizeof(longlink));
                            return -E2BIG;
                        }
                        // Copy the long link data into our buffer
                        NLib::memcpy(longlink, (void *)((uintptr_t)current + 512), fsize);
                        longlink[fsize] = '\0';
                        haslonglink = true;
                        break;
                    }

                    default:
                        NUtil::printf("[fs/ustar]: Unsupported file type `%c` for file `%s`, skipping.\n", current->type, name);
                        break;
                    case type::HARDLINK: {
                        const char *linktarget;
                        if (haslonglink) {
                            linktarget = longlink;
                            haslonglink = false;
                        } else {
                            // Copy linkname to a null-terminated buffer.
                            static char linkbuf[101];
                            size_t len = 0;
                            while (len < sizeof(current->linkname) && lname[len] != '\0') {
                                len++;
                            }
                            NLib::memcpy(linkbuf, lname, len);
                            linkbuf[len] = '\0';
                            linktarget = linkbuf;
                        }

                        // Build full path to the target.
                        char targetpath[8192];
                        NUtil::snprintf(targetpath, sizeof(targetpath), "%s/%s", path, linktarget);

                        // Resolve the target node.
                        VFS::INode *target = NULL;
                        ssize_t res = VFS::vfs->resolve(targetpath, &target, NULL, false);
                        if (res < 0 || target == NULL) {
                            NUtil::printf("[fs/ustar]: Hard link target `%s` not found for `%s`.\n", targetpath, name);
                            break;
                        }

                        // Get target's attributes and data.
                        struct VFS::stat targetattr;
                        target->stat(&targetattr);

                        // Create a new node with the same attributes.
                        struct VFS::stat attr;
                        attr.st_mode = targetattr.st_mode;
                        attr.st_uid = uid;
                        attr.st_gid = gid;
                        attr.st_mtime = mtime;
                        attr.st_atime = mtime;
                        attr.st_ctime = mtime;
                        attr.st_blksize = targetattr.st_blksize;

                        res = VFS::vfs->create(name, &node, attr);
                        if (res != 0) {
                            NUtil::printf("[fs/ustar]: Failed to create hard link `%s`.\n", name);
                            target->unref();
                            break;
                        }

                        // Copy data from target to new node.
                        if (targetattr.st_size > 0) {
                            uint8_t *buf = new uint8_t[targetattr.st_size];
                            ssize_t readcount = target->read(buf, targetattr.st_size, 0, 0);
                            if (readcount > 0) {
                                node->write(buf, readcount, 0, 0);
                            }
                            delete[] buf;
                        }

                        target->unref();
                        node->unref();
                        break;
                    }
                }

                current = (struct info *)((uintptr_t)current + 512 + NLib::alignup(fsize, 512));
            }

            return 0;
        }

        void POSIXTARFileSystem::reclaim(void) {
            // Reclaim the initramfs memory by creating a new bitmap zone.
            NUtil::printf("[fs/ustar]: Reclaiming initramfs memory at %p with length %lu.\n", this->modinfo.loc, this->modinfo.size);
            NArch::PMM::newzone(this->modinfo.loc, this->modinfo.size);
        }

    }
}
