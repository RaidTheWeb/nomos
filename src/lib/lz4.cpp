#include <lib/lz4.hpp>
#include <lib/string.hpp>

namespace NLib {
    namespace LZ4 {

        // https://github.com/lz4/lz4/blob/dev/doc/lz4_Block_format.md
        // https://github.com/lz4/lz4/blob/dev/doc/lz4_Frame_format.md

        // Check if data is an LZ4 frame.
        bool isframe(const void *data, size_t size) {
            if (size < 4) {
                return false;
            }

            uint32_t magic = *(const uint32_t *)data;
            return magic == MAGIC;
        }

        ssize_t getframesize(const void *data, size_t size) {
            if (!isframe(data, size)) { // Check for magic number.
                return -1;
            }

            // Minimal frame header is 7 bytes (magic number + FLG + BD).
            if (size < 7) {
                return -1;
            }

            const uint8_t *ptr = (const uint8_t *)data;
            uint8_t flg = ptr[4];
            uint8_t bd = ptr[5];
            (void)bd; // Unused for now.

            size_t index = 6;

            // Check for content size flag (bit 3).
            if (flg & (1 << 3)) {
                if (size < index + 8) { // We also want to make sure we have enough space for the content size field.
                    return -1;
                }

                uint64_t contentsize = *(const uint64_t *)(ptr + index); // Found it? Wonderful.
                return (ssize_t)contentsize;
            } else {
                // No content size field. There is not much we can do here.
                return -1;
            }
        }

        // Decompress a single LZ4 block (raw block data, no frame headers).
        ssize_t decompressblock(const void *src, size_t srcsize, void *dst, size_t dstsize) {
            const uint8_t *ip = (const uint8_t *)src;
            const uint8_t *iend = ip + srcsize;
            uint8_t *op = (uint8_t *)dst;
            uint8_t *oend = op + dstsize;
            uint8_t *ostart = op;

            while (ip < iend) {
                // Read token byte.
                uint8_t token = *ip++;
                size_t litlen = token >> 4;
                size_t matchlen = (token & 0x0F) + 4; // Minimum match length is 4.

                // Extended literal length.
                if (litlen == 15) {
                    uint8_t s;
                    do {
                        if (ip >= iend) {
                            return -1; // Truncated input.
                        }
                        s = *ip++;
                        litlen += s;
                    } while (s == 255);
                }

                // Copy literals.
                if (op + litlen > oend) {
                    return -1; // Output buffer overflow.
                }
                if (ip + litlen > iend) {
                    return -1; // Truncated input.
                }
                NLib::memcpy(op, (void *)ip, litlen);
                ip += litlen;
                op += litlen;

                // Check for end of block (last sequence has no match).
                if (ip >= iend) {
                    break;
                }

                // Read match offset (2 bytes, little-endian).
                if (ip + 2 > iend) {
                    return -1;
                }
                size_t offset = ip[0] | ((size_t)ip[1] << 8);
                ip += 2;

                if (offset == 0) {
                    return -1; // Invalid offset.
                }

                // Extended match length.
                if ((token & 0x0F) == 15) {
                    uint8_t s;
                    do {
                        if (ip >= iend) {
                            return -1;
                        }
                        s = *ip++;
                        matchlen += s;
                    } while (s == 255);
                }

                // Validate match source.
                uint8_t *match = op - offset;
                if (match < ostart) {
                    return -1; // Invalid match offset.
                }
                if (op + matchlen > oend) {
                    return -1; // Output buffer overflow.
                }

                // Copy match. Must handle overlapping copies byte-by-byte when offset < matchlen.
                if (offset >= matchlen) {
                    // Non-overlapping, use memcpy.
                    NLib::memcpy(op, match, matchlen);
                    op += matchlen;
                } else {
                    // Overlapping copy, byte-by-byte.
                    for (size_t i = 0; i < matchlen; i++) {
                        *op++ = *match++;
                    }
                }
            }

            return op - ostart;
        }

        // Decompress an entire LZ4 frame.
        ssize_t decompressframe(const void *src, size_t srcsize, void *dst, size_t dstsize) {
            const uint8_t *ip = (const uint8_t *)src;
            const uint8_t *iend = ip + srcsize;
            uint8_t *op = (uint8_t *)dst;
            uint8_t *oend = op + dstsize;
            uint8_t *ostart = op;

            // Validate magic number.
            if (srcsize < 7) {
                return -1;
            }
            uint32_t magic = *(const uint32_t *)ip;
            if (magic != MAGIC) {
                return -1;
            }
            ip += 4;

            // Parse frame descriptor.
            uint8_t flg = *ip++;
            uint8_t bd = *ip++;

            // Extract flags.
            // uint8_t version = (flg >> 6) & 0x03; // Should be 01.
            bool blockindep = (flg >> 5) & 0x01;
            bool blockcsum = (flg >> 4) & 0x01;
            bool contentsize = (flg >> 3) & 0x01;
            bool contentcsum = (flg >> 2) & 0x01;
            bool dictid = flg & 0x01;
            (void)blockindep; // Not needed for decompression.
            (void)contentcsum; // We skip checksum validation for now.

            // Extract block max size from BD byte (bits 4-6).
            uint8_t blockmaxid = (bd >> 4) & 0x07;
            static const size_t blockmaxsizes[] = {0, 0, 0, 0, 64*1024, 256*1024, 1024*1024, 4*1024*1024};
            if (blockmaxid < 4 || blockmaxid > 7) {
                return -1;
            }
            size_t blockmax = blockmaxsizes[blockmaxid];
            (void)blockmax; // Could be used for validation.

            // Skip content size field if present (8 bytes).
            if (contentsize) {
                if (ip + 8 > iend) {
                    return -1;
                }
                ip += 8;
            }

            // Skip dictionary ID if present (4 bytes).
            if (dictid) {
                if (ip + 4 > iend) {
                    return -1;
                }
                ip += 4;
            }

            // Skip header checksum (1 byte).
            if (ip >= iend) {
                return -1;
            }
            ip++;

            // Process data blocks.
            while (ip + 4 <= iend) {
                // Read block size.
                uint32_t blockhdr = *(const uint32_t *)ip;
                ip += 4;

                // End mark.
                if (blockhdr == 0) {
                    break;
                }

                // Extract uncompressed flag (bit 31) and size.
                bool uncompressed = (blockhdr >> 31) & 1;
                size_t blocksize = blockhdr & 0x7FFFFFFF;

                if (ip + blocksize > iend) {
                    return -1;
                }

                if (uncompressed) {
                    // Copy uncompressed block directly.
                    if (op + blocksize > oend) {
                        return -1;
                    }
                    NLib::memcpy(op, (void *)ip, blocksize);
                    op += blocksize;
                } else {
                    // Decompress block.
                    ssize_t decompsize = decompressblock(ip, blocksize, op, oend - op);
                    if (decompsize < 0) {
                        return -1;
                    }
                    op += decompsize;
                }

                ip += blocksize;

                // Skip block checksum if present (4 bytes).
                if (blockcsum) {
                    if (ip + 4 > iend) {
                        return -1;
                    }
                    ip += 4;
                }
            }

            return op - ostart;
        }

        LZ4Stream::LZ4Stream(const void *data, size_t size, reclaimcallback_t cb) {
            this->input = (uint8_t *)data;
            this->inputsize = size;
            this->inputbase = (uintptr_t)data;
            this->reclaimoffset = 0;
            this->reclaimcb = cb;

            if (this->parseheader() < 0) {
                return;
            }

            this->valid = true;

            // For block-independent streams, we only need a single-block buffer.
            // For dependent streams, we need a double buffer to handle back-references.
            this->bufcap = this->blockindep ? this->blockmax : (this->blockmax * 2);
            this->buffer = new uint8_t[this->bufcap];
            if (!this->buffer) {
                this->valid = false;
            }
        }

        LZ4Stream::~LZ4Stream() {
            if (this->buffer) {
                delete[] this->buffer;
                this->buffer = nullptr;
            }
        }

        int LZ4Stream::parseheader(void) {
            if (this->inputsize < 7) {
                return -1;
            }

            uint32_t magic = *(const uint32_t *)this->input;
            if (magic != MAGIC) {
                return -1;
            }
            this->inputoffset = 4;

            uint8_t flg = this->input[this->inputoffset++];
            uint8_t version = (flg >> 6) & 0x03;
            if (version != 1) {
                return -1; // Only version 01 is supported.
            }

            this->blockindep = (flg & (1 << 5)) != 0;
            this->blockcsum = (flg & (1 << 4)) != 0;
            this->hascontentsize = (flg & (1 << 3)) != 0;
            bool dictid = (flg & (1 << 0)) != 0;

            uint8_t bd = this->input[this->inputoffset++];
            uint8_t blockmaxid = (bd >> 4) & 0x07;

            static const size_t blockmaxsizes[] = {0, 0, 0, 0, 64*1024, 256*1024, 1024*1024, 4*1024*1024};
            if (blockmaxid < 4 || blockmaxid > 7) {
                return -1; // Invalid block max id.
            }
            this->blockmax = blockmaxsizes[blockmaxid];

            if (this->hascontentsize) {
                if (this->inputoffset + 8 > this->inputsize) {
                    return -1;
                }
                this->contentsize = *(const uint64_t *)(this->input + this->inputoffset);
                this->inputoffset += 8;
            }

            if (dictid) { // Skip dictionary ID (4 bytes).
                if (this->inputoffset + 4 > this->inputsize) {
                    return -1;
                }
                this->inputoffset += 4;
            }

            if (this->inputoffset >= this->inputsize) {
                return -1;
            }
            this->inputoffset++; // Skip header checksum.
            return 0;
        }

        ssize_t LZ4Stream::decompressnext(void) {
            if (this->eof || this->inputoffset + 4 > this->inputsize) {
                this->eof = true;
                return 0;
            }

            // Read block header.
            uint32_t blockhdr = *(const uint32_t *)(this->input + this->inputoffset);
            this->inputoffset += 4;

            // End mark. Zero header means end of frame.
            if (blockhdr == 0) {
                this->eof = true;
                return 0;
            }

            bool uncompressed = (blockhdr >> 31) & 1;
            size_t blocksize = blockhdr & 0x7FFFFFFF;

            if (this->inputoffset + blocksize > this->inputsize) {
                this->eof = true;
                return -1; // Truncated input.
            }

            // Make room in buffer if needed.
            if (this->blockindep) { // Independent blocks can discard all prior data.
                // Discard any fully-consumed data (where readoff has advanced past).
                if (this->readoff > this->bufstart) {
                    size_t consumed = this->readoff - this->bufstart;
                    if (consumed >= this->buflen) {
                        // All data consumed, reset buffer.
                        this->bufstart += this->buflen;
                        this->buflen = 0;
                    } else if (consumed > 0) {
                        // Shift remaining data to start.
                        NLib::memmove(this->buffer, this->buffer + consumed, this->buflen - consumed);
                        this->bufstart += consumed;
                        this->buflen -= consumed;
                    }
                }
            } else {
                // For dependent streams, keep at most one blockmax of history.
                if (this->buflen > this->blockmax) {
                    size_t shift = this->buflen - this->blockmax;
                    NLib::memmove(this->buffer, this->buffer + shift, this->blockmax);
                    this->bufstart += shift;
                    this->buflen = this->blockmax;
                }
            }

            // Decompress or copy into buffer.
            uint8_t *dst = this->buffer + this->buflen;
            size_t dstcap = this->bufcap - this->buflen;
            ssize_t outsize;

            if (uncompressed) {
                if (blocksize > dstcap) {
                    this->eof = true;
                    return -1; // Output buffer overflow.
                }
                NLib::memcpy(dst, (void *)(this->input + this->inputoffset), blocksize);
                outsize = blocksize;
            } else {
                outsize = decompressblock(this->input + this->inputoffset, blocksize, dst, dstcap);
                if (outsize < 0) {
                    this->eof = true;
                    return outsize; // Decompression error.
                }
            }

            this->inputoffset += blocksize;

            // Skip block checksum if present.
            if (this->blockcsum) {
                if (this->inputoffset + 4 > this->inputsize) {
                    this->eof = true;
                    return -1;
                }
                this->inputoffset += 4;
            }

            this->buflen += outsize;
            return outsize;
        }

        // Progressively reclaim consumed input memory.
        void LZ4Stream::tryreclaim(void) {
            if (!this->reclaimcb) {
                return;
            }

            // Only reclaim complete pages that are fully consumed.
            constexpr size_t PAGESIZE = 4096;
            size_t safeoffset;
            if (this->blockindep) {
                // Independent blocks can discard all prior data.
                safeoffset = this->inputoffset;
            } else {
                // Keep safety margin of one block for back-references.
                safeoffset = this->inputoffset > this->blockmax ? this->inputoffset - this->blockmax : 0;
            }
            size_t reclaimable = (safeoffset / PAGESIZE) * PAGESIZE;

            if (reclaimable > this->reclaimoffset) {
                size_t toreclaim = reclaimable - this->reclaimoffset;
                uintptr_t addr = this->inputbase + this->reclaimoffset;
                this->reclaimcb(addr, toreclaim);
                this->reclaimoffset = reclaimable;
            }
        }

        // Reclaim all remaining input memory.
        void LZ4Stream::reclaimall(void) {
            if (!this->reclaimcb) {
                return;
            }

            constexpr size_t PAGESIZE = 4096;
            size_t remaining = this->inputsize - this->reclaimoffset;
            size_t reclaimable = (remaining / PAGESIZE) * PAGESIZE;

            if (reclaimable > 0) {
                uintptr_t addr = this->inputbase + this->reclaimoffset;
                this->reclaimcb(addr, reclaimable);
                this->reclaimoffset += reclaimable;
            }

            // Release the decompression buffer early since we're done.
            this->releasebuffer();
        }

        void LZ4Stream::releasebuffer(void) {
            if (this->buffer) {
                delete[] this->buffer;
                this->buffer = nullptr;
                this->bufcap = 0;
                this->buflen = 0;
            }
        }

        ssize_t LZ4Stream::read(void *dst, size_t count, size_t offset) {
            if (!this->valid || !this->buffer) {
                return -1;
            }

            uint8_t *out = (uint8_t *)dst;
            size_t remaining = count;

            while (remaining > 0) {
                // Check if requested offset is within our buffer.
                if (offset >= this->bufstart && offset < this->bufstart + this->buflen) {
                    size_t bufoff = offset - this->bufstart;
                    size_t avail = this->buflen - bufoff;
                    size_t tocopy = (remaining < avail) ? remaining : avail;

                    NLib::memcpy(out, this->buffer + bufoff, tocopy);
                    out += tocopy;
                    offset += tocopy;
                    remaining -= tocopy;
                    // Update readoff so decompressnext() knows what's consumed.
                    this->readoff = offset;
                } else if (offset >= this->bufstart + this->buflen) {
                    // Need more data, decompress next block.
                    if (this->eof) {
                        break;
                    }
                    ssize_t res = this->decompressnext();
                    if (res < 0) {
                        return -1;
                    }
                    if (res == 0) {
                        break; // EOF.
                    }
                    // Try to reclaim consumed input pages.
                    this->tryreclaim();
                } else {
                    // Trying to read before buffer start (backward seek).
                    // XXX: Required for random access support.
                    return -1;
                }
            }

            return count - remaining;
        }
    }
}