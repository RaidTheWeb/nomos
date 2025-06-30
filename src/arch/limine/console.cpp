#include <arch/limine/console.hpp>
#include <arch/limine/requests.hpp>
#include <flanterm.h>
#include <backends/fb.h>
#include <util/kprint.hpp>

namespace NLimine {
    struct flanterm_context *flanctx = NULL;
    bool console_initialised = false;
    char backbuffer[2048];
    size_t backbufferidx = 0;

    void console_write(const char *buf, size_t len) {
        if (console_initialised) {
            flanterm_write(flanctx, buf, len);
        } else {
            for (size_t i = 0; i < len; i++) {
                // Copy to backbuffer.
                backbuffer[backbufferidx++] = buf[i];
            }
        }
    }

    void console_init(void) {
        struct limine_framebuffer *fb = NLimine::fbreq.response->framebuffers[0];
        flanctx = flanterm_fb_init(
            NULL, NULL, (uint32_t *)fb->address,
            fb->width, fb->height, fb->pitch,
            fb->red_mask_size, fb->red_mask_shift,
            fb->green_mask_size, fb->green_mask_shift,
            fb->blue_mask_size, fb->blue_mask_shift,
            NULL, NULL, NULL, NULL, NULL, NULL, NULL,
            NULL, 0, 0, 1, 0, 0, 0);
        console_initialised = true;

        if (backbufferidx > 0) {
            // Restore backbuffer.
            console_write(backbuffer, backbufferidx);
        }

        NUtil::printf("[arch/limine/console]: Flanterm initialised.\n");
    }

}
