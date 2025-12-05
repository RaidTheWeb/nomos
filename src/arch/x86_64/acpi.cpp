#include <arch/limine/requests.hpp>
#include <arch/x86_64/acpi.hpp>
#include <arch/x86_64/vmm.hpp>
#include <lib/align.hpp>
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
    NUtil::printf("[arch/x86_64/acpi]: ");
    NUtil::vprintf(str, ap);
    va_end(ap);
}

void *uacpi_kernel_map(uacpi_phys_addr phys, uacpi_size length) {
    using namespace NArch::VMM;
    using namespace NMem::Virt;

    NLib::ScopeIRQSpinlock guard(&kspace.lock);
    uintptr_t virt = (uintptr_t)kspace.vmaspace->alloc(length, VIRT_RW | VIRT_NX);
    NArch::VMM::_maprange(&kspace, virt, phys, PRESENT | WRITEABLE | NOEXEC, NLib::alignup(length, NArch::PAGESIZE));
    size_t offset = phys - NLib::aligndown(phys, NArch::PAGESIZE);
    return (void *)(virt + offset);
}

void uacpi_kernel_unmap(void *ptr, uacpi_size length) {
    using namespace NArch::VMM;
    NLib::ScopeIRQSpinlock guard(&kspace.lock);

    NArch::VMM::_unmaprange(&kspace, (uintptr_t)ptr, NLib::alignup(length, NArch::PAGESIZE));
    kspace.vmaspace->free(ptr, length);
}

namespace NArch {
    namespace ACPI {
        struct table madt = { NULL, NULL, false };
        struct table mcfg = { NULL, NULL, false };
        struct acpi_hpet *hpet = NULL;

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
            uacpi_setup_early_table_access((void *)((uintptr_t)PMM::alloc(32 * PAGESIZE, PMM::FLAGS_DEVICE) + NLimine::hhdmreq.response->offset), 32 * PAGESIZE);
            NUtil::printf("[arch/x86_64/acpi]: Initialised uACPI.\n");

            uacpi_table apic;
            assert(uacpi_table_find_by_signature(ACPI_MADT_SIGNATURE, &apic) == UACPI_STATUS_OK, "Failed to find APIC table from ACPI.\n");

            struct acpi_madt *madtptr = (struct acpi_madt *)apic.ptr;

            // Initialise MADT start and end.
            madt.start = (struct acpi_entry_hdr *)((uintptr_t)madtptr + sizeof(struct acpi_madt));

            madt.end = (struct acpi_entry_hdr *)((uintptr_t)madtptr + madtptr->hdr.length);
            madt.initialised = true; // Mark as initialised.
            NUtil::printf("[arch/x86_64/acpi]: MADT initialised.\n");

            uacpi_table timer;
            uacpi_status res = uacpi_table_find_by_signature(ACPI_HPET_SIGNATURE, &timer);

            if (res == UACPI_STATUS_OK) {
                hpet = (struct acpi_hpet *)timer.ptr;
                NUtil::printf("[arch/x86_64/acpi]: HPET initialised.\n");
            } else {
                NUtil::printf("[arch/x86_64/acpi]: HPET not present.\n");
                hpet = NULL;
            }

            uacpi_table pci;
            res = uacpi_table_find_by_signature(ACPI_MCFG_SIGNATURE, &pci);

            if (res == UACPI_STATUS_OK) {
                mcfg.start = (struct acpi_entry_hdr *)((uintptr_t)pci.ptr + sizeof(struct acpi_mcfg));
                mcfg.end = (struct acpi_entry_hdr *)((uintptr_t)pci.ptr + ((struct acpi_mcfg *)pci.ptr)->hdr.length);
                mcfg.initialised = true;
                NUtil::printf("[arch/x86_64/acpi]: MCFG initialised.\n");
            } else {
                NUtil::printf("[arch/x86_64/acpi]: MCFG not present.\n");
            }
        }
    }
}
