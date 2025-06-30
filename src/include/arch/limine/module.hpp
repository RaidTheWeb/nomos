#ifndef _ARCH__LIMINE__MODULE_HPP
#define _ARCH__LIMINE__MODULE_HPP

#include <arch/limine/requests.hpp>
#include <stddef.h>

namespace NArch {
    namespace Module {

        struct modinfo {
            const char *path;
            const char *cmdline; // Additional information passed in for the module.
            size_t size;
            uintptr_t loc;
        };

#define ISMODULE(MOD) ({ (MOD).path != NULL && (MOD).cmdline != NULL && (MOD).size != 0 && (MOD).loc != 0; })

        struct modinfo loadmodule(const char *path);
    }
}

#endif
