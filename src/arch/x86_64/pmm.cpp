#include <arch/x86_64/pmm.hpp>
#include <util/kprint.hpp>

namespace NArch {
    void PMM::setup(void) {
        NUtil::printf("[pmm]: PMM initialised.\n");
    }
}
