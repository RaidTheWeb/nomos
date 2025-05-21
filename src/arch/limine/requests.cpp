#include <arch/limine/requests.hpp>
#include <stddef.h>

namespace NLimine {

    volatile LIMINE_BASE_REVISION(3);

    __attribute__((unused))
    static volatile LIMINE_REQUESTS_START_MARKER;

    volatile struct limine_framebuffer_request fbreq = {
        .id = LIMINE_FRAMEBUFFER_REQUEST,
        .revision = 0,
        .response = NULL
    };

    volatile struct limine_bootloader_info_request bireq = {
        .id = LIMINE_BOOTLOADER_INFO_REQUEST,
        .revision = 0,
        .response = NULL
    };

    volatile struct limine_executable_cmdline_request ecreq = {
        .id = LIMINE_EXECUTABLE_CMDLINE_REQUEST,
        .revision = 0,
        .response = NULL
    };

    __attribute__((unused))
    static volatile LIMINE_REQUESTS_END_MARKER;
}
