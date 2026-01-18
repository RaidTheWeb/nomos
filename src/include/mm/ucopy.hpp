#ifndef _MM__UCOPY_HPP
#define _MM__UCOPY_HPP

#include <stddef.h>
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


        // Userspace safe copy of string to kernel buffer.
        int strncpyfrom(char *dest, const char *src, size_t size);
        // Userspace safe copy of string from kernel buffer to userspace.
        int strncpyto(char *dest, const char *src, size_t size);
        // Userspace safe string length of userspace buffer.
        ssize_t strnlen(const char *src, size_t max);
        // Userspace safe copy from userspace to kernel buffer.
        int copyfrom(void *dest, const void *src, size_t size);
        // Userspace safe copy from kernel to userspace buffer.
        int copyto(void *dest, const void *src, size_t size);
        ssize_t memset(void *dest, int c, size_t n);
    }
}

#endif
