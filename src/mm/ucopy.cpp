#include <lib/errno.hpp>
#include <lib/string.hpp>
#include <mm/ucopy.hpp>
#include <stdint.h>


// XXX: Usercopy only copies all data, or fails, without notifying user of partial copies.

// Import architecture-specific fault-handling ucopy implementations.
extern "C" ssize_t __ucopyfrom(void *dst, const void *src, size_t size);
extern "C" ssize_t __ucopyto(void *dst, const void *src, size_t size);
extern "C" ssize_t __ustrlen(const char *src, size_t max);
extern "C" ssize_t __umemset(void *dest, int c, size_t n);

namespace NMem {
    namespace UserCopy {

        int strncpyfrom(char *dest, const char *src, size_t size) {
            if (size == 0) {
                return 0;
            }

            if (!valid(src, size)) {
                return -EFAULT;
            }

            ssize_t len = __ustrlen(src, size);
            if (len < 0) {
                return -EFAULT;
            }

            size_t copylen = ((size_t)len < size) ? (size_t)len : size;

            if (copylen > 0) {
                int ret = __ucopyfrom(dest, src, copylen);
                if (ret < 0) {
                    return ret;
                }
            }

            // If source was shorter than size, pad remainder with null bytes.
            if ((size_t)len < size) {
                ssize_t ret = __umemset(dest + len, 0, size - len);
                if (ret < 0) {
                    return ret;
                }
            }

            return 0;
        }

        int strncpyto(char *dest, const char *src, size_t size) {
            if (size == 0) {
                return 0;
            }

            if (!valid(dest, size)) {
                return -EFAULT;
            }

            // Get length of source string (not including null terminator).
            size_t len = NLib::strnlen(src, size);

            // Copy min(len, size) bytes from source.
            size_t copylen = (len < size) ? len : size;

            if (copylen > 0) {
                int ret = __ucopyto(dest, src, copylen);
                if (ret < 0) {
                    return ret;
                }
            }

            // If source was shorter than size, pad remainder with null bytes.
            if (len < size) {
                ssize_t ret = __umemset(dest + len, 0, size - len);
                if (ret < 0) {
                    return ret;
                }
            }

            return 0;
        }

        ssize_t strnlen(const char *src, size_t max) {
            if (!valid(src, max)) {
                return -EFAULT;
            }

            return __ustrlen(src, max);
        }

        ssize_t memset(void *dest, int c, size_t n) {
            if (n == 0) {
                return 0;
            }

            if (!valid(dest, n)) {
                return -EFAULT;
            }

            return __umemset(dest, c, n);
        }

        int copyfrom(void *dest, const void *src, size_t size) {
            if (size == 0) {
                return 0;
            }

            if (!valid(src, size)) {
                return -EFAULT;
            }

            return __ucopyfrom(dest, src, size);
        }

        int copyto(void *dest, const void *src, size_t size) {
            if (size == 0) {
                return 0;
            }

            if (!valid(dest, size)) {
                return -EFAULT;
            }

            return __ucopyto(dest, src, size);
        }
    }
}
