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

extern "C" {
    void *memcpy(void *dest, void *src, size_t n) {
        // Reinterpret as individual bytes to copy.
        uint8_t *pdest = (uint8_t *)dest;
        const uint8_t *psrc = (const uint8_t *)src;

        for (size_t i = 0; i < n; i++) {
            // Not the fastest memcpy in the world.
            pdest[i] = psrc[i];
        }

        return dest;
    }

    void *memset(void *dest, int c, size_t n) {
        uint8_t *pdest = (uint8_t *)dest;
        for (size_t i = 0; i < n; i++) {
            pdest[i] = c;
        }
        return dest;
    }
}


extern void (*__init_array[])();
extern void (*__init_array_end[])();

extern "C" void kernel_main(void) {
    NUtil::printf("Nomos 0dev\n");
    // Initialise architecture-specific.
    NArch::init();

    asm volatile("int $0x03");

    hcf();
}
