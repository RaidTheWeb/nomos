#ifndef _LIB__CRC32C_HPP
#define _LIB__CRC32C_HPP

#include <stdint.h>
#include <stddef.h>

namespace NLib {

    void crc32cinit(void);

    // Compute CRC32C checksum.
    uint32_t crc32c(uint32_t crc, const void *data, size_t len);

    // Finalize CRC32C computation.
    uint32_t crc32cfinal(const void *data, size_t len);

    // Compute CRC32C with a seed.
    uint32_t crc32cseeded(uint32_t seed, const void *data, size_t len);

}

#endif
