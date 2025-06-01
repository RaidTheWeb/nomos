#include <arch/limine/arch.hpp>
#include <arch/limine/console.hpp>
#include <arch/limine/requests.hpp>
#include <lib/assert.hpp>
#include <lib/cmdline.hpp>
#include <util/kprint.hpp>

namespace NLimine {
    void init(void) {
        {
            using namespace NLimine;
            assert(LIMINE_BASE_REVISION_SUPPORTED, "Limine base revision not supported.\n");
        }

        assert(fbreq.response && fbreq.response->framebuffer_count >= 1, "Limine framebuffer request did not respond with a framebuffer.\n");

        assert(bireq.response, "Limine bootloader info request did not respond with bootloader info.\n");
        assert(mmreq.response, "Limine bootloader memory map request did not respond with memory map info.\n");
        assert(hhdmreq.response, "Limine bootloader HHDM request did not respond with HHDM info.\n");
        assert(eareq.response, "Limine bootloader executable address request did not respond with executable address.\n");
        assert(rsdpreq.response, "Limine bootloader RSDP address request did not respond with RSDP address.\n");

        NUtil::printf("[limine]: %s %s init().\n", bireq.response->name, bireq.response->version);
        NUtil::printf("[limine]: Command Line: '%s'.\n", ecreq.response->cmdline);
        NLimine::console_init();
    }
}
