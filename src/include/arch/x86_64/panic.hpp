#ifndef _ARCH__X86_64__PANIC_HPP
#define _ARCH__X86_64__PANIC_HPP

#include <arch/x86_64/apic.hpp>
#include <arch/x86_64/cpu.hpp>
#include <util/kprint.hpp>

namespace NArch {
    void panic(const char *msg);
}

#endif
