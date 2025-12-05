#ifndef __MM__VMALLOC_HPP
#define __MM__VMALLOC_HPP

#ifdef __x86_64__
#include <arch/x86_64/sync.hpp>
#include <arch/x86_64/vmm.hpp>
#endif

#include <mm/virt.hpp>
#include <stddef.h>
#include <stdint.h>

// Large virtual-memory based allocator, cobbles together scraps of physical memory into larger contiguous virtual regions.

namespace NMem {
    namespace VMalloc {
        // Allocate a vmalloc region. Do NOT use for DMA or hardware access, this is sometimes non-contiguous memory.
        // Flags are PMM flags for the underlying pages.
        // Returned memory is mapped WRITEABLE, with no additional flags.
        void *alloc(size_t size, uint8_t flags);
        void free(void *ptr, size_t size);

        // Map a vmalloc region into a specific address space.
        void mapintospace(struct NArch::VMM::addrspace *space, uintptr_t virt, size_t size, uint8_t vmaflags);
    }
}

#endif