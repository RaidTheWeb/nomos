#ifndef _FS__USTAR_HPP
#define _FS__USTAR_HPP

#ifdef __x86_64__
#include <arch/limine/module.hpp>
#endif

namespace NFS {
    namespace USTAR {

        enum type {
            FILE            = 0,
            HARDLINK        = 1,
            SYMLINK         = 2,
            CHARDEV         = 3,
            BLKDEV          = 4,
            DIR             = 5,
            FIFO            = 6
        };

        void enumerate(struct NArch::Module::modinfo info);
    }
}

#endif
