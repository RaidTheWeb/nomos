#ifndef _FS__USTAR_HPP
#define _FS__USTAR_HPP

#ifdef __x86_64__
#include <arch/limine/module.hpp>
#endif

#include <fs/ramfs.hpp>
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

        class USTARFileSystem : public RAMFS::RAMFileSystem {
            private:
                struct NArch::Module::modinfo modinfo;
            public:
                USTARFileSystem(VFS::VFS *vfs, struct NArch::Module::modinfo mod) : RAMFS::RAMFileSystem(vfs) {
                    this->modinfo = mod;
                }

                int mount(const char *path) override;
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
    }
}

#endif
