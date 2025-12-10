#ifdef __x86_64__
#include <arch/limine/console.hpp>
#include <arch/x86_64/cpu.hpp>
#include <arch/x86_64/e9.hpp>
#include <arch/x86_64/serial.hpp>
#include <arch/x86_64/sync.hpp>
#endif
#include <ctype.h>
#include <lib/sync.hpp>
#include <sched/sched.hpp>
#include <util/kprint.hpp>

namespace NUtil {
    NArch::Spinlock printlock = NArch::Spinlock();

    void oprintlock(void) {
        printlock.release();
    }

    // Advance one character, while also ensuring an early exit can be done on NULL.
    #define ADVANCE(PTR) \
        { \
            (PTR)++; \
            if (!(*(PTR))) { \
                return *counter; \
            } \
        }

    int sprintf(char *dest, const char *format, ...) {
        va_list args;
        va_start(args, format);
        size_t len = vsprintf(dest, format, args);
        va_end(args);
        return len;
    }

    int snprintf(char *dest, size_t n, const char *format, ...) {
        va_list args;
        va_start(args, format);
        size_t len = vsnprintf(dest, n, format, args);
        va_end(args);
        return len;
    }

    static void putchar(char **buf, char chr, int *counter, int max) {
        if (*counter < max) {
            *(*buf)++ = chr;
            (*counter)++;
        }
    }

    static void putstr(char **buf, const char *str, int *counter, int max, int precision) {
        int prec = precision;
        while (*str && *counter < max && (precision >= 0 ? prec-- : true)) {
            *(*buf)++ = *str++;
            (*counter)++;
        }
    }

    enum {
        ZEROPAD = (1 << 0),
        LEFTJUST = (1 << 1),
        SIGN = (1 << 2), // Display + or - in front.
        SIGNED = (1 << 3), // Handle negative. Does not add +.
        SPACE = (1 << 4),
        HASH = (1 << 5),

        // Length modifiers:
        LONG = (1 << 6),
        LONGLONG = (1 << 7),

        // Uppercase digits.
        UPPER = (1 << 8)
    };

    static void putnum(char **buf, unsigned long long num, int base, int width, int flags, int *counter, int max) {
        const char *digits = flags & UPPER ? "0123456789ABCDEF" : "0123456789abcdef";

        int idx = 0;
        char temp[32];

        bool negative = false;
        if (flags & SIGN || flags & SIGNED) {
            long long snum = (long long)num;
            if (snum < 0) {
                negative = true;
                num = (unsigned long long)-snum;
            }
        }

        if (flags & HASH && base == 16) {
            putstr(buf, flags & UPPER ? "0X" : "0x", counter, max, -1);
            width = width > 2 ? width - 2 : 0;
        } else if (flags & HASH && base == 8 && num != 0) {
            putchar(buf, '0', counter, max);
            width = width > 1 ? width - 1 : 0;
        }

        if (negative) {
            putchar(buf, '-', counter, max);
            width--; // Counts towards width.
        } else if (flags & SIGN) {
            putchar(buf, '+', counter, max);
            width--; // Counts towards width.
        } else if (flags & SPACE) {
            putchar(buf, ' ', counter, max);
            width--; // Counts towards width.
        }

        // iota
        if (num == 0) {
            temp[idx++] = '0';
        } else {
            while (num != 0) {
                temp[idx++] = digits[num % base];
                num /= base;
            }
        }

        if (!(flags & LEFTJUST) && width > idx) {
            for (int i = idx; i < width; i++) {
                putchar(buf, flags & ZEROPAD ? '0' : ' ', counter, max);
            }
        }

        for (idx--; idx >= 0; idx--) {
            putchar(buf, temp[idx], counter, max);
        }

        if (flags & LEFTJUST && width > (idx + 1)) {
            for (int i = (idx + 1); i < width; i++) {
                putchar(buf, ' ', counter, max); // Left justification is spaces.
            }
        }
    }

    static int atoi(const char **str, int base) {
        int ret = 0;
        while (isdigit(**str)) {
            ret = ret * base + (**str - '0');
            (*str)++;
        }
        return ret;
    }

    static int formatloop(char **buf, const char *format, int *counter, int max, va_list ap) {
        while (*format) {
            if (*format != '%') {
                putchar(buf, *format, counter, max);
                format++;
                continue;
            }
            ADVANCE(format);

            // Format specifier:
            int flags = 0;

            while (true) {
                switch (*format) {
                    case '0': flags |= ZEROPAD; break;
                    case '-': flags |= LEFTJUST; break;
                    case '+': flags |= SIGN; break;
                    case '#': flags |= HASH; break;
                    case ' ': flags |= SPACE; break;
                    default: // Unknown
                        goto flagbreak;
                }
                ADVANCE(format);
            }

flagbreak:

            // Compute format width.
            int width = 0;
            if (isdigit(*format)) {
                width = atoi(&format, 10);
            } else if (*format == '*') { // Variable width -> depends on an argument.
                const int w = va_arg(ap, int);
                if (w < 0) { // Negative width means left justifcation.
                    flags |= LEFTJUST;
                    width = -w;
                } else {
                    width = w;
                }
                ADVANCE(format); // Next token.
            }

            int precision = -1;
            if (*format == '.') {
                ADVANCE(format);
                if (isdigit(*format)) {
                    precision = atoi(&format, 10); // Precision baked into format string.
                } else if (*format == '*') {
                    precision = va_arg(ap, int); // Variable precision.
                    ADVANCE(format);
                } else {
                    precision = 0; // Default to zero.
                }
            }

            // Integer length processing:
            switch (*format) {
                case 'l':
                    flags |= LONG; // Marks this as a long.
                    ADVANCE(format); // Move to next character.
                    if (*format == 'l') { // Is this now a long long?
                        flags |= LONGLONG;
                        ADVANCE(format);
                    }
                    break;
                default:
                    break;
            }

            switch (*format) {
                case 'd':
                case 'i': {
                    long long num;
                    if (flags & LONGLONG) { // Prioritise this flag, because otherwise we'd pick the wrong argument.
                        num = va_arg(ap, long long);
                    } else if (flags & LONG) {
                        num = va_arg(ap, long);
                    } else {
                        num = va_arg(ap, int);
                    }

                    flags |= SIGNED;
                    putnum(buf, num, 10, width, flags, counter, max);
                    break;
                }
                case 'u': {
                    unsigned long long num;
                    if (flags & LONGLONG) { // Prioritise this flag, because otherwise we'd pick the wrong argument.
                        num = va_arg(ap, unsigned long long);
                    } else if (flags & LONG) {
                        num = va_arg(ap, unsigned long);
                    } else {
                        num = va_arg(ap, unsigned int);
                    }

                    putnum(buf, num, 10, width, flags, counter, max);
                    break;
                }

                case 'x':
                case 'X': {
                    unsigned long long num;
                    if (flags & LONGLONG) { // Prioritise this flag, because otherwise we'd pick the wrong argument.
                        num = va_arg(ap, unsigned long long);
                    } else if (flags & LONG) {
                        num = va_arg(ap, unsigned long);
                    } else {
                        num = va_arg(ap, unsigned int);
                    }

                    if (*format == 'X') {
                        flags |= UPPER;
                    }

                    putnum(buf, num, 16, width, flags, counter, max);
                    break;
                }

                case 'o': {
                    unsigned long long num;
                    if (flags & LONGLONG) { // Prioritise this flag, because otherwise we'd pick the wrong argument.
                        num = va_arg(ap, unsigned long long);
                    } else if (flags & LONG) {
                        num = va_arg(ap, unsigned long);
                    } else {
                        num = va_arg(ap, unsigned int);
                    }

                    putnum(buf, num, 8, width, flags, counter, max);
                    break;
                }

                case 'c':
                    putchar(buf, va_arg(ap, int), counter, max);
                    break;
                case '%':
                    putchar(buf, *format, counter, max);
                    break;
                case 's': {
                    const char *p = va_arg(ap, char *);
                    if (p == NULL) {
                        putstr(buf, "(null)", counter, max, precision);
                    } else {
                        putstr(buf, p, counter, max, precision);
                    }
                    break;
                }
                case 'p': {
                    void *ptr = va_arg(ap, void *);
                    putchar(buf, '0', counter, max);
                    putchar(buf, 'x', counter, max);
                    flags |= ZEROPAD;
                    putnum(buf, (unsigned long)ptr, 16, sizeof(void *) * 2, flags, counter, max);
                    break;
                }
                default:
                    putchar(buf, '%', counter, max);
                    putchar(buf, *format, counter, max);
                    break;
            }
            format++;
        }

        // End.
        putchar(buf, '\0', counter, max); // Zero terminate.
        return *counter;
    }

    int vsprintf(char *dest, const char *format, va_list ap) {
        int counter = 0;
        formatloop(&dest, format, &counter, __INT32_MAX__, ap);
        return counter;
    }

    int vsnprintf(char *dest, size_t n, const char *format, va_list ap) {
        int counter = 0;
        formatloop(&dest, format, &counter, n, ap);
        return counter;
    }

    int printf(const char *format, ...) {
        va_list args;
        va_start(args, format);
        size_t len = vprintf(format, args);
        va_end(args);
        return len;
    }

    static NSched::Mutex mutex;
    bool canmutex = false;
    static bool consolewrite = true;

    void dropwrite(void) {
        consolewrite = false;
    }

    void undropwrite(void) {
        consolewrite = true;
    }

    int vprintf(const char *format, va_list ap) {
        char buffer[1024];
        size_t len = vsnprintf(buffer, sizeof(buffer), format, ap);
        len -= 1; // Back out on null termination for this.
        bool writestatus = consolewrite;

        // if (canmutex && NArch::CPU::get()->currthread) {
            // mutex.acquire();
        // } else {
        bool state = false;
        if (writestatus) {
            printlock.acquire();
        } else {
            state = NArch::CPU::get()->setint(false);
            printlock.acquire();
        }

#ifdef __x86_64__
        if (writestatus) {
            NLimine::console_write(buffer, len);
        }

        // for (size_t i = 0; i < len; i++) {
            // NArch::Serial::ports[0].write(buffer[i]);
        // }

        NArch::E9::puts(buffer);
#endif
        // if (canmutex && NArch::CPU::get()->currthread) {
            // mutex.release();
        // } else {
        if (writestatus) {
            printlock.release();
        } else {
            printlock.release();
            NArch::CPU::get()->setint(state);
        }
        // }
        return len;
    }
}
