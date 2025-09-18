#ifndef _LIB__KPRINT_HPP
#define _LIB__KPRINT_HPP

#include <stdarg.h>
#include <stddef.h>

namespace NUtil {
    int sprintf(char *dest, const char *format, ...);
    int snprintf(char *dest, size_t n, const char *format, ...);
    int vsprintf(char *dest, const char *format, va_list ap);
    int vsnprintf(char *dest, size_t n, const char *format, va_list ap);

    int printf(const char *format, ...);
    int vprintf(const char *format, va_list ap);

    extern bool canmutex;
    // Forcibly open print lock -> For use with panic().
    void oprintlock(void);
    // Drop writing to framebuffer console -> Pre-init.
    void dropwrite(void);
}

#endif
