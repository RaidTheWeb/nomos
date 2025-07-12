#include <lib/errno.hpp>
#include <lib/string.hpp>
#include <mm/ucopy.hpp>
#include <stdint.h>

namespace NMem {
    namespace UserCopy {

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
