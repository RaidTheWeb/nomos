#ifndef _FS__POSIXTAR_HPP
#define _FS__POSIXTAR_HPP

#ifdef __x86_64__
#include <arch/limine/module.hpp>
#endif

#include <fs/ramfs.hpp>
#include <fs/vfs.hpp>

namespace NFS {
    namespace POSIXTAR {

        enum type {
            FILE            = '0',
            HARDLINK        = '1',
            SYMLINK         = '2',
            CHARDEV         = '3',
            BLKDEV          = '4',
            DIR             = '5',
            FIFO            = '6',
            PATH            = 'L',
            LINK            = 'K'  // GNU tar long link name.
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

        class POSIXTARFileSystem : public RAMFS::RAMFileSystem {
            private:
                struct NArch::Module::modinfo modinfo;
            public:
                POSIXTARFileSystem(VFS::VFS *vfs, struct NArch::Module::modinfo mod) : RAMFS::RAMFileSystem(vfs) {
                    this->modinfo = mod;
                }

                int mount(const char *src, const char *path, VFS::INode *mntnode, uint64_t flags, const void *data) override;
                void reclaim(void); // Reclaim initramfs memory after mount completes.
        };

        // Convert octal to binary integer.
        static inline uint64_t oct2int(const char *str, size_t len) {
            uint64_t val = 0;
            // Skip leading spaces and zeros.
            while (len > 0 && (*str == ' ' || *str == '0')) {
                str++;
                len--;
            }
            while (len > 0 && *str >= '0' && *str <= '7') {
                val = val * 8 + (*str++ - '0');
                len--;
            }
            return val;
        }
    }
}

#endif
