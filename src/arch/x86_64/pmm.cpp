#include <arch/limine/requests.hpp>
#include <arch/x86_64/pmm.hpp>
#include <util/kprint.hpp>

namespace NArch {
    void PMM::setup(void) {
        for (size_t i = 0; i < NLimine::mmreq.response->entry_count; i++) {
            struct limine_memmap_entry *entry = NLimine::mmreq.response->entries[i];
            NUtil::printf("[pmm]: 0x%016x->0x%016x %s.\n", entry->base, entry->base + entry->length, entry->type == LIMINE_MEMMAP_USABLE ? "FREE" : "NOT FREE");
        }

        NUtil::printf("[pmm]: PMM initialised.\n");
    }
}
