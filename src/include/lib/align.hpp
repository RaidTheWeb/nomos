#ifndef _LIB__ALIGN_HPP
#define _LIB__ALIGN_HPP

#include <stddef.h>
#include <stdint.h>

namespace NLib {
    static inline uint64_t alignup(uint64_t val, size_t align) {
        return (val + (align - 1)) & ~(align - 1);
    }

    static inline uint64_t aligndown(uint64_t val, size_t align) {
        return (val & ~(align - 1));
    }

    static inline uint64_t divroundup(uint64_t val, uint64_t div) {
        return ((val + div - 1) / div);
    }
}

#endif
