#ifndef _ARCH__X86_64__ACPI_HPP
#define _ARCH__X86_64__ACPI_HPP

#include <stddef.h>
#include <stdint.h>
#include <uacpi/acpi.h>

namespace NArch {
    namespace ACPI {
        struct table {
            struct acpi_entry_hdr *start;
            struct acpi_entry_hdr *end;
            bool initialised;
        };

        extern struct table madt;

        // Count the number of entries of a specific type, that exist in an ACPI table.
        size_t countentries(struct table *table, uint8_t type);

        // Get an entry by index, of a specific type, from an ACPI table.
        struct acpi_entry_hdr *getentry(struct table *table, uint8_t type, size_t i);

        void setup(void);
    }
}

#endif
