#include <arch/limine/arch.hpp>
#include <arch/limine/console.hpp>
#include <arch/limine/requests.hpp>
#include <lib/cmdline.hpp>
#include <util/kprint.hpp>

namespace NLimine {
    void init(void) {
        {
            using namespace NLimine;
            if (!LIMINE_BASE_REVISION_SUPPORTED) {
                for (;;) {
                    asm ("hlt");
                }
            }
        }

        if (fbreq.response == NULL || fbreq.response->framebuffer_count < 1) {
            for (;;) {
                asm ("hlt");
            }
        }

        if (bireq.response == NULL) {
            for (;;) {
                asm ("hlt");
            }
        }

        NUtil::printf("[limine]: %s %s init()\n", bireq.response->name, bireq.response->version);
        NUtil::printf("[limine]: Command Line: \"%s\"\n", ecreq.response->cmdline);
        NLimine::console_init();

        NLib::CmdlineParser parser = NLib::CmdlineParser(ecreq.response->cmdline);
    }
}
