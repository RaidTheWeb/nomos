#include <arch/limine/requests.hpp>
#include <stddef.h>

namespace NLimine {

    volatile LIMINE_BASE_REVISION(3);

    __attribute__((used))
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

    volatile struct limine_memmap_request mmreq = {
        .id = LIMINE_MEMMAP_REQUEST,
        .revision = 0,
        .response = NULL
    };

    volatile struct limine_hhdm_request hhdmreq = {
        .id = LIMINE_HHDM_REQUEST,
        .revision = 0,
        .response = NULL
    };

    volatile struct limine_executable_address_request eareq = {
        .id = LIMINE_EXECUTABLE_ADDRESS_REQUEST,
        .revision = 0,
        .response = NULL
    };

    volatile struct limine_rsdp_request rsdpreq = {
        .id = LIMINE_RSDP_REQUEST,
        .revision = 0,
        .response = NULL
    };

    volatile struct limine_mp_request mpreq = {
        .id = LIMINE_MP_REQUEST,
        .revision = 0,
        .response = NULL,
        .flags = 0
    };

    volatile struct limine_date_at_boot_request btreq = {
        .id = LIMINE_DATE_AT_BOOT_REQUEST,
        .revision = 0,
        .response = NULL
    };

    volatile struct limine_module_request modreq = {
        .id = LIMINE_MODULE_REQUEST,
        .revision = 0,
        .response = NULL,
        .internal_module_count = 0,
        .internal_modules = NULL
    };

    __attribute__((used))
    static volatile LIMINE_REQUESTS_END_MARKER;
}
