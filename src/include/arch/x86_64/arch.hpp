#ifndef _ARCH__X86_64__ARCH_HPP
#define _ARCH__X86_64__ARCH_HPP

namespace NArch {
    extern bool hypervisor_enabled;
    extern bool hypervisor_checked;
    void init(void);
}

#endif
