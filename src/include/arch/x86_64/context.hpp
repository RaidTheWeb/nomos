#ifndef _ARCH__X86_64__CONTEXT_HPP
#define _ARCH__X86_64__CONTEXT_HPP

#include <stddef.h>
#include <stdint.h>

namespace NArch {
    namespace CPU {
        // CPU context, reverse order of how it'll be added to by pushing registers to the stack in interrupts and context switches.
        struct context {
            uint64_t cr2;
            uint64_t gs;
            uint64_t fs;
            uint64_t es;
            uint64_t ds;
            uint64_t rax;
            uint64_t rbx;
            uint64_t rcx;
            uint64_t rdx;
            uint64_t r8;
            uint64_t r9;
            uint64_t r10;
            uint64_t r11;
            uint64_t r12;
            uint64_t r13;
            uint64_t r14;
            uint64_t r15;
            uint64_t rdi;
            uint64_t rsi;
            uint64_t irq;
            uint64_t rbp;
            uint64_t err;
            uint64_t rip;
            uint64_t cs;
            uint64_t rflags;
            uint64_t rsp;
            uint64_t ss;
        } __attribute__((packed));

        // Architecture-specific extra context.
        struct extracontext {
            uintptr_t fsbase = 0;
            void *fpustorage = NULL; // FPU state storage (variable size). Only allocated when needed.
            bool mathused = false; // Did the thread use math at all? Determines how fpu context is saved.
        };

        void savexctx(struct extracontext *ctx);
        void restorexctx(struct extracontext *ctx);

        extern "C" void ctx_swap(struct context *ctx);
    }
}

#endif
