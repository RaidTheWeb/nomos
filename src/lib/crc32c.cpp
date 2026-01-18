#include <lib/crc32c.hpp>

namespace NLib {

    static constexpr uint32_t CRC32C_POLY = 0x82F63B78;

    static uint32_t crc32ctable[256]; // Lookup table. Basically just a singleton type deal.
    static bool crc32ctableinit = false;

    void crc32cinit(void) {
        if (crc32ctableinit) {
            return;
        }

        for (uint32_t i = 0; i < 256; i++) { // First, initialise the table.
            uint32_t crc = i;
            for (int j = 0; j < 8; j++) {
                if (crc & 1) {
                    crc = (crc >> 1) ^ CRC32C_POLY;
                } else {
                    crc >>= 1;
                }
            }
            crc32ctable[i] = crc;
        }

        crc32ctableinit = true;
    }

    uint32_t crc32c(uint32_t crc, const void *data, size_t len) {
        // Ensure table is initialised.
        if (!crc32ctableinit) {
            crc32cinit(); // Initialise the table for the first time.
        }

        const uint8_t *buf = (const uint8_t *)data;

        while (len--) {
            crc = crc32ctable[(crc ^ *buf++) & 0xFF] ^ (crc >> 8);
        }

        return crc;
    }

    uint32_t crc32cfinal(const void *data, size_t len) {
        return ~crc32c(~0U, data, len);
    }

    uint32_t crc32cseeded(uint32_t seed, const void *data, size_t len) {
        // Start with the seed as the initial CRC (pre-inverted).
        uint32_t crc = crc32c(~seed, data, len);
        return ~crc;
    }

}
