#include <arch/limine/module.hpp>
#include <lib/string.hpp>
#include <stddef.h>
#include <stdint.h>
#include <util/kprint.hpp>

namespace NArch {
    namespace Module {

        Module *loadmodule(const char *path) {

            if (NLimine::modreq.response == NULL || NLimine::modreq.response->module_count <= 0) {
                return NULL;
            }

            struct limine_file **modules = NLimine::modreq.response->modules;

            for (size_t i = 0; i < NLimine::modreq.response->module_count; i++) {
                struct limine_file *module = modules[i];

                if (!NLib::strcmp(path, module->path)) { // If this matches the requested file path.
                    // Check if it's LZ4 compressed.
                    bool islz4 = NLib::LZ4::isframe((void *)module->address, (size_t)module->size);

                    if (islz4) {
                        return new CompressedModule(module->path, module->string, (size_t)module->size, (uintptr_t)module->address);
                    } else {
                        return new Module(module->path, module->string, (size_t)module->size, (uintptr_t)module->address);
                    }
                }
            }

            return NULL;
        }

    }
}
