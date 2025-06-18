#ifndef _ARCH__X86_64__SMP_HPP
#define _ARCH__X86_64__SMP_HPP

#include <arch/x86_64/cpu.hpp>

namespace NArch {
    namespace SMP {
        extern bool initialised;
        extern struct CPU::cpulocal **cpulist;
        extern uintptr_t phycpusaddr;
        extern size_t awakecpus;

        void setup(void);
    }
}

#endif
