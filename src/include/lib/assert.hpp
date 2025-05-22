#ifndef _LIB__ASSERT_HPP
#define _LIB__ASSERT_HPP

#include <stdarg.h>
#include <util/kprint.hpp>

namespace NLib {
    static inline void __assert(bool statement, const char *expr, const char *func, const char *file, int line, const char *msg, ...) {
        if (!statement) {
            va_list ap;
            va_start(ap, msg);
            NUtil::printf("[\x1b[1;31mPANIC\x1b[0m]: Assertion (%s) in %s() at %s:%d failed:\n\t", expr, func, file, line);
            NUtil::vprintf(msg, ap);

            for (;;) {
                // Halt and catch fire (accept no interrupts).
                asm volatile ("cli");
                asm volatile ("hlt");
            }
            va_end(ap);
        }
    }

    #define GET_MACRO(_1, _2, _3, NAME, ...) NAME
    #define assert(...) GET_MACRO(__VA_ARGS__, __assert_fmt, __assert_no_fmt)(__VA_ARGS__)

    #define __assert_fmt(condition, msg, ...) ({ \
        NLib::__assert((condition), #condition, __FUNCTION__, __FILE__, __LINE__, msg, __VA_ARGS__); \
    })

    #define __assert_no_fmt(condition, msg) ({ \
        NLib::__assert((condition), #condition, __FUNCTION__, __FILE__, __LINE__, msg); \
    })
}

#endif
