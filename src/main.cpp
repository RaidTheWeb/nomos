#include <arch/limine/arch.hpp>
#include <arch/limine/console.hpp>
#include <arch/limine/requests.hpp>
#include <arch/x86_64/arch.hpp>
#include <arch/x86_64/serial.hpp>
#include <flanterm.h>
#include <backends/fb.h>
#include <lib/assert.hpp>
#include <util/kprint.hpp>
#include <limine.h>
#include <stddef.h>

#include <mm/slab.hpp>

static void hcf(void) {
    for (;;) {
        asm ("hlt");
    }
}

// C++ Global Constructors.
extern void (*__init_array[])();
extern void (*__init_array_end[])();

extern "C" void kernel_main(void) {
    NUtil::printf("Nomos %s, built %s\n", VERSION, BUILDDATE);

    // Initialise global constructors.
    // Required to let us initialise classes outside of stack-based scopes like functions.
    for (size_t i = 0; &__init_array[i] != __init_array_end; i++) {
        // Call the constructor for every globally defined class variable.
        __init_array[i]();
    }

    // Initialise architecture-specific.
    NArch::init();

    NMem::allocator.setup();


    void *test = NMem::allocator.alloc(48);
    //  NMem::allocator.free(test);
    void *test2 = NMem::allocator.alloc(64);
    //    NMem::allocator.free(test2);

    // assert(test == test2, "Sanity check failed.\n");

    NUtil::printf("Allocated 0x%016lx.\n", (uintptr_t)test);

    hcf();
}
