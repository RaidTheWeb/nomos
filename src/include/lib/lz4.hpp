#ifndef _LIB__LZ4_HPP
#define _LIB__LZ4_HPP

#include <std/stddef.h>
#include <stdint.h>

// Small LZ4 implementation for general use in the kernel.

// XXX: Implement compression.

namespace NLib {
    namespace LZ4 {

        static constexpr uint32_t MAGIC = 0x184D2204; // LZ4 frame magic number.

        // Maximum LZ4 block size (4MB).
        static constexpr size_t MAXBLOCKSIZE = 4 * 1024 * 1024;

        // Check if data is an LZ4 frame.
        bool isframe(const void *data, size_t size);

        // Determine the uncompressed size of an LZ4 frame.
        ssize_t getframesize(const void *data, size_t size);

        // Decompress an entire LZ4 frame (including its blocks).
        ssize_t decompressframe(const void *src, size_t srcsize, void *dst, size_t dstsize);
        // Decompress a single LZ4 block (without frame headers).
        ssize_t decompressblock(const void *src, size_t srcsize, void *dst, size_t dstsize);

        // Callback type for progressive memory reclamation. Called when input pages become fully consumed.
        typedef void (*reclaimcallback_t)(uintptr_t addr, size_t size);

        class LZ4Stream {
            private:
                uint8_t *input = NULL;
                size_t inputsize = 0;
                size_t inputoffset = 0; // Current offset into input.
                uintptr_t inputbase = 0; // Base address for reclamation.
                size_t reclaimoffset = 0; // Bytes already reclaimed (page-aligned).
                reclaimcallback_t reclaimcb = NULL;

                bool valid = false;
                bool hascontentsize = false;
                size_t contentsize = 0;
                bool blockindep = false;
                bool blockcsum = false;
                size_t blockmax = 0;

                uint8_t *buffer = NULL;
                size_t bufcap = 0;
                size_t bufstart = 0; // Logical offset of buffer[0].
                size_t buflen = 0; // Valid bytes in buffer.

                size_t readoff = 0;
                bool eof = false;
                int parseheader(void);
                ssize_t decompressnext(void);
                void tryreclaim(void);
            public:
                LZ4Stream(const void *data, size_t size, reclaimcallback_t cb = NULL);
                ~LZ4Stream();

                bool isvalid(void) const {
                    return valid && buffer != NULL;
                }

                ssize_t contentlength(void) const {
                    return hascontentsize ? (ssize_t)contentsize : -1;
                }

                // Read decompressed data.
                // XXX: Does not support random access yet.
                ssize_t read(void *dst, size_t count, size_t offset);

                size_t tell(void) const {
                    return readoff;
                }

                size_t consumed(void) const {
                    return inputoffset;
                }

                // Reclaim all remaining input memory (call when done reading).
                void reclaimall(void);

                // Release the decompression buffer early (called automatically by reclaimall).
                void releasebuffer(void);

                // Get amount of input not yet reclaimed.
                size_t unreclaimed(void) const {
                    return inputsize - reclaimoffset;
                }
        };
    }
}

#endif