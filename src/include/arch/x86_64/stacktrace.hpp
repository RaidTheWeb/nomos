#ifndef _ARCH__X86_64__STACKTRACE_HPP
#define _ARCH__X86_64__STACKTRACE_HPP

#include <stdint.h>
#include <stddef.h>

namespace NArch {
    // Maximum number of stack frames to walk.
    static const size_t STACKTRACEMAXFRAMES = 32;

    // Stack frame structure for x86_64 (frame pointer chain).
    struct stackframe {
        struct stackframe *rbp; // Previous frame pointer.
        uint64_t rip;           // Return address.
    };

    // Print a stack trace starting from the current RBP.
    void printstacktrace(void);

    // Print a stack trace starting from a specific RBP.
    void printstacktrace(uint64_t rbp);

    // Print a stack trace starting from a specific RBP and RIP.
    void printstacktrace(uint64_t rbp, uint64_t rip);
}

#endif
