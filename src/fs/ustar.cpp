#include <fs/posixtar.hpp>
#include <fs/vfs.hpp>
#include <lib/align.hpp>
#include <lib/errno.hpp>
#include <lib/string.hpp>
#include <util/kprint.hpp>

namespace NFS {
    namespace POSIXTAR {

        int POSIXTARFileSystem::mount(const char *path, VFS::INode *mntnode) {
            int super = this->RAMFS::RAMFileSystem::mount(path, mntnode); // Super.
            if (super != 0) {
                return super;
            }

            NLib::ScopeSpinlock guard(&this->spin);

            size_t size = this->modinfo.size;
            uintptr_t loc = this->modinfo.loc;

            NUtil::printf("[fs/ustar]: Enumerating USTAR module `%s` at %p with length %lu.\n", this->modinfo.path, loc, size);

            struct info *current = (struct info *)loc; // First file is at the start of the archive.
            char longpath[4096] = {0}; // Buffer to store long paths (GNU tar extension).
            bool has_longpath = false; // Track if we have a pending long path.

            // As long as we feature the USTAR magic value, it's "theoretically" a valid file.
            while ((uintptr_t)current + sizeof(struct info) <= (loc + size) && !NLib::strncmp(current->magic, "ustar", 5)) {
                char basename[256] = {0};
                char *lname = current->linkname;

                if (has_longpath) { // Use the long path previously stored.
                    NLib::strncpy(basename, longpath, sizeof(basename) - 1);
                    has_longpath = false;
                } else { // Use the name field.
                    size_t namelen = 0;
                    while (namelen < sizeof(current->name) && current->name[namelen] != '\0') {
                        namelen++;
                    }
                    NLib::memcpy(basename, current->name, namelen);
                    basename[namelen] = '\0';
                }

                if (!NLib::strcmp(basename, "./")) {
                    continue; // We should skip the "current directory".
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
                        node = VFS::vfs.create(name, attr);
                        assert(node, "Failed to allocate VFS node.\n");

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
                        node = VFS::vfs.create(name, attr);
                        assert(node, "Failed to allocate VFS node.\n");
                        node->unref();
                        break;
                    }
                    case type::SYMLINK: {
                        struct VFS::stat attr;
                        attr.st_mode = mode | VFS::S_IFLNK;
                        attr.st_uid = uid;
                        attr.st_gid = gid;
                        attr.st_mtime = mtime;
                        node = VFS::vfs.create(name, attr);
                        assert(node, "Failed to allocate VFS node.\n");

                        size_t len = 0;
                        while (len < sizeof(current->linkname) && lname[len] != '\0') {
                            len++;
                        }

                        size_t count = node->write(lname, len + 1, 0, 0);
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
                        has_longpath = true;
                        break;
                    }
                }

                current = (struct info *)((uintptr_t)current + 512 + NLib::alignup(fsize, 512));
            }
            return 0;
        }

    }
}
