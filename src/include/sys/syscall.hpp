#ifndef _SYS__SYSCALL_HPP
#define _SYS__SYSCALL_HPP

#include <std/stddef.h>
#include <util/kprint.hpp>

// System call logging macro.
#ifdef SYSCALL_DEBUG
    #define SYSCALL_LOG(fmt, ...) NUtil::printf("[sys/syscall]: (%lu) " fmt, NArch::CPU::get()->currthread->process->id,  ##__VA_ARGS__)
    #ifdef SYSCALL_DEBUGRET
        #define SYSCALL_RET(ret) \
            if ((long)(ret) < 0) { \
                NUtil::printf("[sys/syscall]: (%lu) => %ld (%s)\n", NArch::CPU::get()->currthread->process->id, (long)(ret), strerror(-(long)(ret))); \
            } else { \
                NUtil::printf("[sys/syscall]: (%lu) => %ld\n", NArch::CPU::get()->currthread->process->id, (long)(ret)); \
            } \
            return (ret);
    #else
        #define SYSCALL_RET(ret) return (ret);
    #endif
#else
    #define SYSCALL_LOG(fmt, ...) do { } while (0)
    #define SYSCALL_RET(ret) return (ret);
#endif

#endif