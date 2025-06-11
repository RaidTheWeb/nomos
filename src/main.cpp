#ifdef __x86_64__
#include <arch/limine/arch.hpp>
#include <arch/limine/console.hpp>
#include <arch/limine/requests.hpp>
#include <arch/x86_64/arch.hpp>
#include <arch/x86_64/serial.hpp>
#include <backends/fb.h>
#include <flanterm.h>
#include <limine.h>
#endif

#include <dev/dev.hpp>

#include <cxxruntime.hpp>

#include <lib/assert.hpp>
#include <lib/cmdline.hpp>
#include <util/kprint.hpp>
#include <stddef.h>

#include <mm/slab.hpp>

static void hcf(void) {
    for (;;) {
        asm ("hlt");
    }
}

namespace NMem {
    bool sanitisefreed = false;
}

// These operators must be defined here, or else they won't apply everywhere.

void *operator new(size_t size) {
    return NMem::allocator.alloc(size);
}

void operator delete(void *ptr) {
    NMem::allocator.free(ptr);
}

void *operator new(size_t size, size_t align) {
    (void)align;
    return NMem::allocator.alloc(size);
}

void *operator new[](size_t size) {
    return operator new(size);
}

void operator delete[](void *ptr) {
    operator delete(ptr);
}

void operator delete(void *ptr, size_t align) {
    (void)align;
    NMem::allocator.free(ptr);
}

void operator delete[](void *ptr, size_t size) {
    (void)size;
    operator delete(ptr);
}

// Called within the architecture-specific initialisation thread. Stage 1 (early).
void kinit1(void) {
    // Command line argument enables memory sanitisation upon slab allocator free. Helps highlight memory management issues, and protect against freed memory inspection.
    if (NArch::cmdline.get("mmsan")) {
        NMem::sanitisefreed = true;
    }

    for (NDev::regentry *entry = (NDev::regentry *)NDev::__drivers_start; (uintptr_t)entry < (uintptr_t)NDev::__drivers_end; entry++) {
        if (entry->magic == NDev::MAGIC) {
            NUtil::printf("Discovered driver: %s of type %s.\n", entry->info->name, entry->info->type == NDev::reginfo::GENERIC ? "GENERIC" : "MATCHED");
        }
    }
}

extern "C" void kernel_main(void) {
    NUtil::printf("Nomos %s, built %s\n", VERSION, BUILDDATE);

    // Initialise freestanding C++ "runtime" support.
    NCxx::init();

    // Initialise architecture-specific.
    NArch::init();

    hcf();
}
