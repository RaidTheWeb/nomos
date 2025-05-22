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

        NUtil::printf("[limine]: %s %s init()\n", bireq.response->name, bireq.response->version);
        NUtil::printf("[limine]: Command Line: \"%s\"\n", ecreq.response->cmdline);
        NLimine::console_init();

        NLib::CmdlineParser parser = NLib::CmdlineParser(ecreq.response->cmdline);
    }
}
