#ifndef __SYS__SYSCALL_HPP
#define __SYS__SYSCALL_HPP

#include <std/stddef.h>
#include <util/kprint.hpp>

// System call logging macro.
#ifdef SYSCALL_DEBUG
    #define SYSCALL_LOG(fmt, ...) NUtil::printf("[sys/syscall]: (%lu) " fmt, NArch::CPU::get()->currthread->process->id,  ##__VA_ARGS__)
#else
    #define SYSCALL_LOG(fmt, ...) do { } while (0)
#endif

#endif