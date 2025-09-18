#ifndef _ARCH__X86_64__E9_HPP
#define _ARCH__X86_64__E9_HPP

#include <arch/x86_64/io.hpp>

namespace NArch {
    namespace E9 {
        extern bool enabled;

        void puts(const char *str);
    }
}

#endif
