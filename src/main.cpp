#include <arch/limine/arch.hpp>
#include <arch/limine/console.hpp>
#include <arch/limine/requests.hpp>
#include <arch/x86_64/arch.hpp>
#include <arch/x86_64/serial.hpp>
#include <flanterm.h>
#include <backends/fb.h>
#include <util/kprint.hpp>
#include <limine.h>
#include <stddef.h>

static void hcf(void) {
    for (;;) {
        asm ("hlt");
    }
}

// C++ Global Constructors.
extern void (*__init_array[])();
extern void (*__init_array_end[])();

extern "C" void kernel_main(void) {
    NUtil::printf("Nomos 0dev\n");
    // Initialise architecture-specific.
    NArch::init();

    hcf();
}
