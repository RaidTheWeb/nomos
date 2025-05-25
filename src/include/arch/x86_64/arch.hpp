#ifndef _ARCH__X86_64__ARCH_HPP
#define _ARCH__X86_64__ARCH_HPP

#include <lib/cmdline.hpp>

namespace NArch {
    extern bool hypervisor_enabled;
    extern bool hypervisor_checked;
    extern NLib::CmdlineParser cmdline;
    void init(void);
}

#endif
