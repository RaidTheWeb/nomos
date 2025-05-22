#include <arch/x86_64/vmm.hpp>
#include <util/kprint.hpp>

namespace NArch {
    void VMM::setup(void) {
        NUtil::printf("[vmm]: VMM initialised.\n");
    }
}
