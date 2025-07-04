#include <fs/ustar.hpp>
#include <fs/vfs.hpp>
#include <lib/string.hpp>
#include <util/kprint.hpp>

namespace NFS {
    namespace USTAR {

        ssize_t RAMNode::read(void *buf, size_t count, off_t offset) {
            assert(buf, "Reading into invalid buffer.\n");
            assert(count, "Invalid count.\n");

            NLib::ScopeSpinlock guard(&this->spin);

            if (offset >= this->attr.st_size) {
                return 0;
            }
            if ((off_t)(offset + count) > this->attr.st_size) {
                count = this->datasize - offset;
            }

            NLib::memcpy(buf, this->data + offset, count);
            return count;
        }

        ssize_t RAMNode::write(const void *buf, size_t count, off_t offset) {
            NLib::ScopeSpinlock guard(&this->spin);

            if ((off_t)(offset + count) > this->attr.st_size) {
                this->attr.st_size = offset + count;
                this->attr.st_blocks = (this->attr.st_size + this->attr.st_blksize - 1) / this->attr.st_blksize;

                this->data = (uint8_t *)NMem::allocator.realloc(this->data, this->attr.st_size);
            }

            NLib::memcpy(this->data + offset, (void *)buf, count);
            return count;
        }

        VFS::INode *RAMNode::lookup(const char *name) {
            NLib::ScopeSpinlock guard(&this->spin);

            if (!VFS::S_ISDIR(this->attr.st_mode)) {
                return NULL; // Non-directories possess no children.
            }

            RAMNode **node = this->children.find(name);
            if (node) {
                (*node)->ref();
                return (*node);
            }

            return NULL;
        }

        bool RAMNode::add(VFS::INode *node) {
            NLib::ScopeSpinlock guard(&this->spin);

            if (!VFS::S_ISDIR(this->attr.st_mode)) {
                return false; // Non-directories possess no children.
            }

            RAMNode *rnode = (RAMNode *)node;
            this->children.insert(rnode->name, rnode);
            return true;
        }

        bool RAMNode::remove(const char *name) {
            NLib::ScopeSpinlock guard(&this->spin);

            if (!VFS::S_ISDIR(this->attr.st_mode)) {
                return false; // Non-directories possess no children.
            }

            return this->children.remove(name);
        }

        VFS::INode *RAMFileSystem::create(const char *name, struct VFS::stat attr) {
            attr.st_blksize = 512;
            return new RAMNode(this, name, attr);
        }

        void enumerate(struct NArch::Module::modinfo info) {

            size_t size = info.size;
            uintptr_t loc = info.loc;
            NUtil::printf("[fs/ustar]: Enumerating USTAR module `%s` at %p with length %lu.\n", info.path, loc, size);

            RAMFileSystem *fs = new RAMFileSystem();

            VFS::VFS vfs;
            vfs.mount("/", fs);

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

                char nname[101];
                nname[0] = '/';
                NLib::strncpy(nname + 1, name, sizeof(current->name));
                name = nname;

                if (!NLib::strcmp(name, "./")) {
                    continue; // We should skip the "current directory".
                }

                NUtil::printf("[fs/ustar]: Discovered entry `%s`.\n", name);

                uint64_t fsize = oct2int(current->size, sizeof(current->size));
                uint64_t mtime = oct2int(current->mtime, sizeof(current->mtime));
                uint64_t mode = oct2int(current->mode, sizeof(current->mode));

                VFS::INode *node = NULL;
                switch (current->type) {
                    case type::FILE: {
                        struct VFS::stat attr;
                        attr.st_mode = mode | VFS::S_IFREG;
                        attr.st_mtime = mtime;
                        node = vfs.create(name, attr);
                        assert(node, "Failed to allocate VFS node.\n");

                        size_t count = node->write((void *)((uintptr_t)current + 512), fsize, 0);
                        assert(count, "Failed to write VFS node data.\n");
                        break;
                    }
                    case type::DIR: {
                        struct VFS::stat attr;
                        attr.st_mode = mode | VFS::S_IFDIR;
                        attr.st_mtime = mtime;
                        node = vfs.create(name, attr);
                        assert(node, "Failed to allocate VFS node.\n");
                        break;
                    }
                    case type::PATH: {
                        break;
                    }
                }

                current = (struct info *)((uintptr_t)current + 512 + ((fsize + 512 - 1) & ~(512 - 1)));
            }
        }
    }
}
