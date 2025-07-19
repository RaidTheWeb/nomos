#ifndef _ARCH__LIMINE__CONSOLE_HPP
#define _ARCH__LIMINE__CONSOLE_HPP

#include <flanterm.h>
#include <stddef.h>

namespace NLimine {

    extern struct flanterm_context *flanctx;
    extern bool console_initialised;
    void console_write(const char *buf, size_t len);
    void console_init(void);
}

#endif
