#ifndef _ARCH__X86_64__IO_HPP
#define _ARCH__X86_64__IO_HPP

#include <stdint.h>

// Standard x86 I/O instructions inlined for usage.

namespace NArch {

    static inline void outb(uint16_t port, uint8_t val) {
        asm volatile("outb %b0, %w1" : /* no outputs */ : "a"(val), "Nd"(port) : "memory");
    }

    static inline void outw(uint16_t port, uint16_t val) {
        asm volatile("outw %w0, %w1" : /* no outputs */ : "a"(val), "Nd"(port) : "memory");
    }

    static inline void outl(uint16_t port, uint32_t val) {
        asm volatile("outl %0, %w1" : /* no outputs */ : "a"(val), "Nd"(port) : "memory");
    }

    static inline uint8_t inb(uint16_t port) {
        uint8_t ret = 0;
        asm volatile("inb %w1, %b0" : "=a"(ret) : "Nd"(port) : "memory");
        return ret;
    }

    static inline uint16_t inw(uint16_t port) {
        uint16_t ret = 0;
        asm volatile("inw %w1, %w0" : "=a"(ret) : "Nd"(port) : "memory");
        return ret;
    }

    static inline uint32_t inl(uint16_t port) {
        uint32_t ret = 0;
        asm volatile("inl %w1, %0" : "=a"(ret) : "Nd"(port) : "memory");
        return ret;
    }
}

#endif
