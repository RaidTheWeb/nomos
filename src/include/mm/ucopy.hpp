#ifndef _MM__UCOPY_HPP
#define _MM__UCOPY_HPP

#include <stddef.h>

namespace NMem {
    namespace UserCopy {
        // Userspace safe copy of string to kernel buffer.
        int strncpy(char *dest, const char *src, size_t size);
        // Userspace safe string length of userspace buffer.
        ssize_t strnlen(const char *src, size_t max);
        // Userspace safe copy from userspace to kernel buffer.
        int copyfrom(void *dest, const void *src, size_t size);
        // Userspace safe copy from kernel to userspace buffer.
        int copyto(void *dest, const void *src, size_t size);
    }
}

#endif
