#include <fs/ustar.hpp>
#include <lib/string.hpp>
#include <util/kprint.hpp>

namespace NFS {
    namespace USTAR {
        void enumerate(struct NArch::Module::modinfo info) {

            size_t size = info.size;
            uintptr_t loc = info.loc;
            NUtil::printf("[fs/ustar]: Enumerating USTAR module `%s` at %p with length %lu.\n", info.path, loc, size);



        }
    }
}
