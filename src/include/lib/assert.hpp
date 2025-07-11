#ifndef _LIB__ASSERT_HPP
#define _LIB__ASSERT_HPP

#include <stdarg.h>
#include <lib/string.hpp>
#include <util/kprint.hpp>

namespace NArch {
    extern void panic(const char *buf);
}

namespace NLib {

    static inline void __assert(bool statement, const char *expr, const char *func, const char *file, int line, const char *msg, ...) {
        if (!statement) {
            va_list ap;
            va_start(ap, msg);
            char buffer[2048];
            NUtil::snprintf(buffer, sizeof(buffer), "Assertion (%s) in %s() at %s:%d failed:\n\t", expr, func, file, line);
            NUtil::vsnprintf(buffer + (NLib::strlen(buffer)), sizeof(buffer) - NLib::strlen(buffer), msg, ap);

            NArch::panic(buffer); // Dump buffer, and halt all CPUs.

            va_end(ap);
        }
    }

    #define assertarg(condition, msg, ...) ({ \
        NLib::__assert((condition), #condition, __FUNCTION__, __FILE__, __LINE__, msg, __VA_ARGS__); \
    })

    #define assert(condition, msg) ({ \
        NLib::__assert((condition), #condition, __FUNCTION__, __FILE__, __LINE__, msg); \
    })
}

#endif
