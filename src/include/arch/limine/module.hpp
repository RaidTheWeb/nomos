#ifndef _ARCH__LIMINE__MODULE_HPP
#define _ARCH__LIMINE__MODULE_HPP

#include <arch/limine/requests.hpp>
#include <arch/x86_64/pmm.hpp>
#include <lib/lz4.hpp>
#include <lib/string.hpp>
#include <stddef.h>

namespace NArch {
    namespace Module {

        // Reclamation callback for progressive memory freeing.
        static inline void reclaimcb(uintptr_t addr, size_t size) {
            NArch::PMM::newzone(addr, size);
        }

        class Module {
            public:
                const char *path;
                const char *cmdline; // Additional information passed in for the module.
                size_t size;
                uintptr_t loc;

                virtual bool valid() const {
                    return path != NULL && cmdline != NULL && size != 0 && loc != 0;
                }

                virtual ssize_t read(void *dst, size_t count, size_t offset) {
                    if (!path || size == 0 || loc == 0) {
                        return -1;
                    }

                    size_t toread = count;
                    if (offset + toread > size) {
                        toread = size - offset;
                    }

                    NLib::memcpy(dst, (void *)(loc + offset), toread);
                    return toread;
                }

                // Get the content size (decompressed size for compressed modules).
                virtual ssize_t contentsize() const {
                    return size;
                }

                // Check if this module is compressed.
                virtual bool iscompressed() const {
                    return false;
                }

                Module(const char *p, const char *c, size_t s, uintptr_t l) : path(p), cmdline(c), size(s), loc(l) { }

        };

        class CompressedModule : public Module {
            public:
                NLib::LZ4::LZ4Stream *lz4stream = NULL;

                bool valid() const override {
                    return lz4stream && lz4stream->isvalid();
                }

                ssize_t read(void *dst, size_t count, size_t offset) override {
                    if (!lz4stream || !lz4stream->isvalid()) {
                        return -1;
                    }
                    return lz4stream->read(dst, count, offset);
                }

                ssize_t contentsize() const override {
                    if (lz4stream) {
                        ssize_t len = lz4stream->contentlength();
                        if (len > 0) {
                            return len;
                        }
                    }
                    return size; // Fallback to compressed size.
                }

                bool iscompressed() const override {
                    return true;
                }

                // Reclaim any remaining unreclaimed input memory.
                void reclaimremaining(void) {
                    if (lz4stream) {
                        lz4stream->reclaimall();
                    }
                }

                CompressedModule(const char *p, const char *c, size_t s, uintptr_t l) : Module(p, c, s, l) {
                    this->lz4stream = new NLib::LZ4::LZ4Stream((void *)l, s, reclaimcb);
                }
        };

        Module *loadmodule(const char *path);
    }
}

#endif
