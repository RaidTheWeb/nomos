#include <arch/limine/requests.hpp>
#include <arch/x86_64/acpi.hpp>
#include <arch/x86_64/vmm.hpp>
#include <lib/assert.hpp>
#include <lib/string.hpp>
#include <uacpi/acpi.h>
#include <uacpi/kernel_api.h>
#include <uacpi/tables.h>
#include <uacpi/uacpi.h>
#include <util/kprint.hpp>

uacpi_status uacpi_kernel_get_rsdp(uacpi_phys_addr *out) {
    *out = (uintptr_t)NLimine::rsdpreq.response->address;
    return UACPI_STATUS_OK;
}

void uacpi_kernel_log(uacpi_log_level level, const uacpi_char *str, ...) {
    (void)level;
    va_list ap;
    va_start(ap, str);
    NUtil::printf("[acpi]: ");
    NUtil::vprintf(str, ap);
    va_end(ap);
}

void *uacpi_kernel_map(uacpi_phys_addr phys, uacpi_size length) {
    // Identity maps range.
    NArch::VMM::maprange(&NArch::VMM::kspace, phys + NLimine::hhdmreq.response->offset, phys, NArch::VMM::PRESENT | NArch::VMM::WRITEABLE | NArch::VMM::NOEXEC, length);
    return (void *)(phys + NLimine::hhdmreq.response->offset);
}

void uacpi_kernel_unmap(void *ptr, uacpi_size length) {
    // NArch::VMM::unmaprange(&NArch::VMM::kspace, (uintptr_t)ptr, length);
}

namespace NArch {
    namespace ACPI {
        struct table madt = { NULL, NULL, false };

        size_t countentries(struct table *table, uint8_t type) {
            assert(table->initialised, "Call before ACPI table initialised.\n");

            size_t idx = 0;
            struct acpi_entry_hdr *hdr = table->start;

            // Headers are contiguous, so a less than condition works.
            while (hdr < table->end) {
                if (hdr->type == type) {
                    idx++; // Increase count when we identify an instance of this entry.
                }

                // Move to next header.
                hdr = (struct acpi_entry_hdr *)((uintptr_t)hdr + hdr->length);
            }

            return idx;
        }

        struct acpi_entry_hdr *getentry(struct table *table, uint8_t type, size_t i) {
            assert(table->initialised, "Call before ACPI table initialised.\n");

            struct acpi_entry_hdr *hdr = table->start;
            size_t counter = 0;

            while (hdr < table->end) {
                if (hdr->type == type) {

                    if (counter == i) { // This is the specific entry we're looking for, return.
                        return hdr; // Return reference to header.
                    }
                    counter++; // We found one of the types, so we increment the counter regardless.
                }

                hdr = (struct acpi_entry_hdr *)((uintptr_t)hdr + hdr->length);
            }

            return NULL;
        }

        void setup(void) {
            uacpi_setup_early_table_access(PMM::alloc(32 * PAGESIZE), 32 * PAGESIZE);

            uacpi_table apic;
            assert(uacpi_table_find_by_signature(ACPI_MADT_SIGNATURE, &apic) == UACPI_STATUS_OK, "Failed to find APIC table from ACPI.\n");

            struct acpi_madt *madtptr = (struct acpi_madt *)apic.ptr;

            // Initialise MADT start and end.
            madt.start = (struct acpi_entry_hdr *)((uintptr_t)madtptr + sizeof(struct acpi_madt));
            madt.end = (struct acpi_entry_hdr *)((uintptr_t)madtptr + madtptr->hdr.length);
            madt.initialised = true; // Mark as initialised.
            NUtil::printf("[acpi]: MADT initialised.\n");
        }
    }
}
