#ifndef _ARCH__LIMINE__REQUESTS_HPP
#define _ARCH__LIMINE__REQUESTS_HPP

#include <limine.h>

namespace NLimine {

    extern volatile uint64_t limine_base_revision[3];
    extern volatile struct limine_framebuffer_request fbreq;
    extern volatile struct limine_bootloader_info_request bireq;
    extern volatile struct limine_executable_cmdline_request ecreq;
    extern volatile struct limine_stack_size_request ssreq;
    extern volatile struct limine_hhdm_request hhdmreq;
    extern volatile struct limine_mp_request mpreq;
    extern volatile struct limine_rsdp_request rsdpreq;
    extern volatile struct limine_memmap_request mmreq;
    extern volatile struct limine_executable_address_request eareq;
}

#endif
