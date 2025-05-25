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

void *operator new[](size_t size) {
    return operator new(size);
}

void operator delete[](void *ptr) {
    operator delete(ptr);
}

extern "C" void kernel_main(void) {
    NUtil::printf("Nomos %s, built %s\n", VERSION, BUILDDATE);

    // Initialise freestanding C++ "runtime" support.
    NCxx::init();

    // Initialise architecture-specific.
    NArch::init();

    // Command line argument enables memory sanitisation upon slab allocator free.
    if (NArch::cmdline.get("mmsan")) {
        NMem::sanitisefreed = true;
    }

    hcf();
}
