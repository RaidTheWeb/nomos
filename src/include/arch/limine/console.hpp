#ifndef _ARCH__LIMINE__CONSOLE_HPP
#define _ARCH__LIMINE__CONSOLE_HPP

#include <stddef.h>

namespace NLimine {
    extern bool console_initialised;
    void console_write(const char *buf, size_t len);
    void console_init(void);
}

#endif
