#ifndef _FS__USTAR_HPP
#define _FS__USTAR_HPP

#ifdef __x86_64__
#include <arch/limine/module.hpp>
#endif

#include <fs/vfs.hpp>

namespace NFS {
    namespace USTAR {

        enum type {
            FILE            = '0',
            HARDLINK        = '1',
            SYMLINK         = '2',
            CHARDEV         = '3',
            BLKDEV          = '4',
            DIR             = '5',
            FIFO            = '6',
            PATH            = 'L'
        };

        // USTAR stores file information as ASCII strings, instead of properly encoded values.
        struct info {
            char name[100];
            char mode[8];
            char uid[8];
            char gid[8];
            char size[12];
            char mtime[12];
            char csum[8];
            char type;
            char linkname[100];
            char magic[6];
            char ver[2];
            char uname[32];
            char gname[32];
            char major[8];
            char minor[8];
            char prefix[155];
        };

        class RAMNode : public VFS::INode {
            private:
                uint8_t *data = NULL;
                size_t datasize = 0;
                NLib::HashMap<RAMNode *> children;
            public:

                RAMNode(VFS::IFileSystem *fs, const char *name, struct VFS::stat attr) : VFS::INode(fs, name, attr) { }

                ssize_t read(void *buf, size_t count, off_t offset) override;
                ssize_t write(const void *buf, size_t count, off_t offset) override;
                VFS::INode *lookup(const char *name) override;
                bool add(VFS::INode *node) override;
                bool remove(const char *name) override;

                // Inherit the data directly from an existing address.
                void inherit(uint8_t *data, size_t size) {
                    this->data = data;
                    this->datasize = size;
                }
        };

        class RAMFileSystem : public VFS::IFileSystem {
            private:
            public:
                RAMFileSystem(void) {
                    struct VFS::stat attr = (struct VFS::stat) {
                        .st_mode = 0755 | VFS::S_IFDIR,
                    };
                    this->root = new RAMNode(this, "", attr);
                }

                int mount(void) override { return 0; }
                int unmount(void) override { return 0; }
                int sync(void) override { return 0; }

                VFS::INode *create(const char *name, struct VFS::stat attr) override;
        };

        // Convert octal to binary integer.
        static inline uint64_t oct2int(const char *str, size_t len) {
            uint64_t val = 0;
            while (*str && len > 0) {
                val = val * 8 + (*str++ - '0');
                len--;
            }
            return val;
        }

        void enumerate(struct NArch::Module::modinfo info);
    }
}

#endif
