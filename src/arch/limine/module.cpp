#include <arch/limine/module.hpp>
#include <lib/string.hpp>
#include <stddef.h>
#include <stdint.h>
#include <util/kprint.hpp>

namespace NArch {
    namespace Module {

        struct modinfo loadmodule(const char *path) {

            if (NLimine::modreq.response == NULL || NLimine::modreq.response->module_count <= 0) {
                return { "", "", 0, 0 }; // Return invalid. No modules.
            }

            struct limine_file **modules = NLimine::modreq.response->modules;

            for (size_t i = 0; i < NLimine::modreq.response->module_count; i++) {
                struct limine_file *module = modules[i];

                if (!NLib::strcmp(path, module->path)) { // If this matches the requested file path.
                    return { module->path, module->string, module->size, (uintptr_t)module->address }; // Return our module information in a non-limine-specific format.
                }
            }

            return { "", "", 0, 0 };
        }

    }
}
