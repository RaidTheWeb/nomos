#include <fs/ustar.hpp>
#include <fs/vfs.hpp>
#include <lib/align.hpp>
#include <lib/string.hpp>
#include <util/kprint.hpp>

namespace NFS {
    namespace USTAR {

        int USTARFileSystem::mount(const char *path) {
            int super = this->RAMFS::RAMFileSystem::mount(path); // Super.
            if (super != 0) {
                return super;
            }

            NLib::ScopeSpinlock guard(&this->spin);

            size_t size = this->modinfo.size;
            uintptr_t loc = this->modinfo.loc;

            NUtil::printf("[fs/ustar]: Enumerating USTAR module `%s` at %p with length %lu.\n", this->modinfo.path, loc, size);

            struct info *current = (struct info *)loc; // First file is at the start of the archive.
            char *longpath = NULL; // Because a long path is set before the actual file is featured (in order), we'll store this between files, so we can set it on the next one (the intended target).

            // As long as we feature the USTAR magic value, it's "theoretically" a valid file.
            while (!NLib::strncmp(current->magic, "ustar", 5)) {
                char *name = current->name;
                char *lname = current->linkname;
                if (longpath != NULL) {
                    name = longpath; // Override name with previously defined long path.
                    longpath = NULL;
                }

                char nname[sizeof(current->name) + 1];
                NUtil::snprintf(nname, sizeof(current->name) + 1, "%s/%s", path, name);
                name = nname;

                if (!NLib::strcmp(name, "./")) {
                    continue; // We should skip the "current directory".
                }

                uint64_t fsize = oct2int(current->size, sizeof(current->size));
                uint64_t mtime = oct2int(current->mtime, sizeof(current->mtime));
                uint64_t mode = oct2int(current->mode, sizeof(current->mode));

                VFS::INode *node = NULL;
                switch (current->type) {
                    case type::FILE: {
                        struct VFS::stat attr;
                        attr.st_mode = mode | VFS::S_IFREG;
                        attr.st_mtime = mtime;
                        node = VFS::vfs.create(name, attr);
                        assert(node, "Failed to allocate VFS node.\n");

                        size_t count = node->write((void *)((uintptr_t)current + 512), fsize, 0);
                        assert(count == fsize, "Failed to write VFS node data.\n");
                        break;
                    }
                    case type::DIR: {
                        struct VFS::stat attr;
                        attr.st_mode = mode | VFS::S_IFDIR;
                        attr.st_mtime = mtime;
                        node = VFS::vfs.create(name, attr);
                        assert(node, "Failed to allocate VFS node.\n");
                        break;
                    }
                    case type::SYMLINK: {
                        struct VFS::stat attr;
                        attr.st_mode = mode | VFS::S_IFLNK;
                        attr.st_mtime = mtime;
                        node = VFS::vfs.create(name, attr);
                        assert(node, "Failed to allocate VFS node.\n");

                        size_t count = node->write(lname, sizeof(current->linkname), 0);
                        assert(count, "Failed to write link to VFS node.\n");
                        break;
                    }
                    case type::PATH: {
                        longpath = (char *)((uintptr_t)current + 512);
                        longpath[fsize] = '\0';
                        break;
                    }
                }

                current = (struct info *)((uintptr_t)current + 512 + NLib::alignup(fsize, 512));
            }
            return 0;
        }

    }
}
