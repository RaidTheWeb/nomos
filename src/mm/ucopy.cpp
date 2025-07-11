#include <lib/errno.hpp>
#include <lib/string.hpp>
#include <mm/ucopy.hpp>
#include <stdint.h>

namespace NMem {
    namespace UserCopy {

        static inline bool valid(const void *ptr, size_t size) {
            uintptr_t addr = (uintptr_t)ptr;

            if (addr + size < addr) { // Wraps around.
                return false;
            }

            if (addr > 0x800000000000) { // Isn't userspace at start.
                return false;
            }

            if (addr + size > 0x800000000000) { // Isn't userspace at end.
                return false;
            }

            return true;
        }

        int strncpy(char *dest, const char *src, size_t size) {
            if (!valid(src, size)) {
                return -EFAULT;
            }

            NLib::strncpy(dest, (char *)src, size);
            return 0;
        }

        ssize_t strnlen(const char *src, size_t max) {
            if (!valid(src, max)) {
                return -EFAULT;
            }

            return NLib::strnlen(src, max);
        }

        int copyfrom(void *dest, const void *src, size_t size) {
            if (!valid(src, size)) {
                return -EFAULT;
            }

            NLib::memcpy(dest, (void *)src, size);
            return 0;
        }

        int copyto(void *dest, const void *src, size_t size) {
            if (!valid(dest, size)) {
                return -EFAULT;
            }

            NLib::memcpy(dest, (void *)src, size);
            return 0;
        }
    }
}
