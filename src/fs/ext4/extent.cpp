#include <fs/ext4/defs.hpp>
#include <fs/ext4/ext4fs.hpp>

namespace NFS {
    namespace Ext4FS {
        // Grow extent tree from depth 0 to depth 1.
        // XXX: Depth > 1 isn't exactly supported yet.
        bool Ext4Node::growextenttree(void) {
            struct extenthdr *hdr = (struct extenthdr *)this->diskino.block;
            if (hdr->depth != 0) {
                // Already has depth, use different growth path.
                return false;
            }

            // Allocate a new block for the leaf node.
            uint32_t inogroup = (this->attr.st_ino - 1) / this->ext4fs->sb.inodespergroup;
            this->metalock.release();
            uint64_t leafblk = this->ext4fs->allocblock(inogroup);
            this->metalock.acquire();

            if (leafblk == 0) {
                return false;
            }

            // Prepare the new leaf block with copied extents.
            uint8_t *leafbuf = new uint8_t[this->ext4fs->blksize];
            NLib::memset(leafbuf, 0, this->ext4fs->blksize);

            struct extenthdr *leafhdr = (struct extenthdr *)leafbuf;
            leafhdr->magic = EXT4_EXTMAGIC;
            leafhdr->entries = hdr->entries;
            // Max extents that fit in a full block (minus header and tail for checksum).
            size_t usable = this->ext4fs->blksize - sizeof(struct extenthdr);
            if (this->ext4fs->haschecksums) {
                usable -= sizeof(struct extenttail);
            }
            leafhdr->max = usable / sizeof(struct extent);
            leafhdr->depth = 0;
            leafhdr->generation = hdr->generation;

            // Copy existing extents to the new leaf.
            struct extent *srcextents = (struct extent *)((uint8_t *)this->diskino.block + sizeof(struct extenthdr));
            struct extent *dstextents = (struct extent *)(leafbuf + sizeof(struct extenthdr));
            NLib::memcpy(dstextents, srcextents, hdr->entries * sizeof(struct extent));

            // Add extent block checksum if checksums are enabled.
            if (this->ext4fs->haschecksums) {
                struct extenttail *tail = (struct extenttail *)(leafbuf + this->ext4fs->blksize - sizeof(struct extenttail));
                tail->checksum = this->ext4fs->extentblockchecksum(this->attr.st_ino, this->diskino.generation, leafbuf, this->ext4fs->blksize);
            }

            // Write the new leaf block to disk.
            this->metalock.release();
            ssize_t res = this->ext4fs->writeblock(leafblk, leafbuf);
            this->metalock.acquire();

            delete[] leafbuf;

            if (res < 0) {
                this->metalock.release();
                this->ext4fs->freeblock(leafblk);
                this->metalock.acquire();
                return false;
            }

            // Convert the inode's extent area into an index node.
            uint32_t firstlogical = 0;
            if (hdr->entries > 0) {
                firstlogical = srcextents[0].fileblk;
            }

            // Clear the block array and set up as index node.
            NLib::memset(this->diskino.block, 0, sizeof(this->diskino.block));

            hdr = (struct extenthdr *)this->diskino.block;
            hdr->magic = EXT4_EXTMAGIC;
            hdr->entries = 1;
            hdr->max = (sizeof(this->diskino.block) - sizeof(struct extenthdr)) / sizeof(struct extentidx);
            hdr->depth = 1;
            hdr->generation++;

            // Add index entry pointing to the new leaf.
            struct extentidx *idx = (struct extentidx *)((uint8_t *)this->diskino.block + sizeof(struct extenthdr));
            idx->fileblk = firstlogical;
            idx->leaflo = leafblk & 0xFFFFFFFF;
            idx->leafhi = (leafblk >> 32) & 0xFFFF;
            idx->unused = 0;

            return true;
        }

        // Find the leaf block that should contain the given logical block in a deep extent tree.
        uint64_t Ext4Node::findextentleaf(uint64_t logicalblk, uint8_t **leafbufout) {
            struct extenthdr *hdr = (struct extenthdr *)this->diskino.block;

            if (hdr->depth == 0) {
                *leafbufout = NULL;
                return 0;
            }

            uint8_t *node = (uint8_t *)this->diskino.block;
            uint8_t *allocbuf = NULL;
            uint64_t leafblk = 0;

            while (true) {
                hdr = (struct extenthdr *)node;

                if (hdr->depth == 0) {
                    // Found the leaf.
                    *leafbufout = allocbuf;
                    return leafblk;
                }

                struct extentidx *indices = (struct extentidx *)(node + sizeof(struct extenthdr));
                struct extentidx *found = NULL;

                // Find the appropriate child node.
                for (uint16_t i = 0; i < hdr->entries; i++) {
                    if (logicalblk >= indices[i].fileblk) {
                        found = &indices[i];
                    } else {
                        break;
                    }
                }

                if (!found) {
                    // Use first index if logicalblk is before all entries.
                    if (hdr->entries > 0) {
                        found = &indices[0];
                    } else {
                        if (allocbuf) delete[] allocbuf;
                        *leafbufout = NULL;
                        return 0;
                    }
                }

                leafblk = ((uint64_t)found->leafhi << 32) | found->leaflo;

                if (allocbuf) delete[] allocbuf;
                allocbuf = new uint8_t[this->ext4fs->blksize];

                this->metalock.release();
                ssize_t res = this->ext4fs->readblock(leafblk, allocbuf);
                this->metalock.acquire();

                if (res < 0) {
                    delete[] allocbuf;
                    *leafbufout = NULL;
                    return 0;
                }

                node = allocbuf;
            }
        }

        // Add an extent to a deep extent tree (depth >= 1).
        uint64_t Ext4Node::allocextentdeep(uint64_t logicalblk, uint16_t len, uint64_t physblk) {
            uint8_t *leafbuf = NULL;
            uint64_t leafblk = this->findextentleaf(logicalblk, &leafbuf);

            if (leafblk == 0 || leafbuf == NULL) {
                if (leafbuf) delete[] leafbuf;
                return 0;
            }

            struct extenthdr *leafhdr = (struct extenthdr *)leafbuf;
            struct extent *extents = (struct extent *)(leafbuf + sizeof(struct extenthdr));

            // Try to extend an existing extent.
            for (uint16_t i = 0; i < leafhdr->entries; i++) {
                uint32_t extstart = extents[i].fileblk;
                uint16_t extlen = extents[i].len & 0x7FFF;
                uint64_t extphys = ((uint64_t)extents[i].starthi << 32) | extents[i].startlo;

                if (logicalblk == extstart + extlen && physblk == extphys + extlen) {
                    extents[i].len = (extents[i].len & 0x8000) | ((extlen + len) & 0x7FFF);

                    // Update extent block checksum if checksums are enabled.
                    if (this->ext4fs->haschecksums) {
                        struct extenttail *tail = (struct extenttail *)(leafbuf + this->ext4fs->blksize - sizeof(struct extenttail));
                        tail->checksum = this->ext4fs->extentblockchecksum(this->attr.st_ino, this->diskino.generation, leafbuf, this->ext4fs->blksize);
                    }

                    this->metalock.release();
                    ssize_t res = this->ext4fs->writeblock(leafblk, leafbuf);
                    this->metalock.acquire();

                    delete[] leafbuf;
                    return (res >= 0) ? physblk : 0;
                }
            }

            // Check if there's room for a new extent.
            if (leafhdr->entries < leafhdr->max) {
                // Find insertion point to keep extents sorted.
                uint16_t insertpos = leafhdr->entries;
                for (uint16_t i = 0; i < leafhdr->entries; i++) {
                    if (extents[i].fileblk > logicalblk) {
                        insertpos = i;
                        break;
                    }
                }

                // Shift extents to make room.
                for (uint16_t i = leafhdr->entries; i > insertpos; i--) {
                    extents[i] = extents[i - 1];
                }

                // Insert new extent.
                extents[insertpos].fileblk = logicalblk;
                extents[insertpos].len = len;
                extents[insertpos].starthi = (physblk >> 32) & 0xFFFF;
                extents[insertpos].startlo = physblk & 0xFFFFFFFF;
                leafhdr->entries++;

                // Update extent block checksum if checksums are enabled.
                if (this->ext4fs->haschecksums) {
                    struct extenttail *tail = (struct extenttail *)(leafbuf + this->ext4fs->blksize - sizeof(struct extenttail));
                    tail->checksum = this->ext4fs->extentblockchecksum(this->attr.st_ino, this->diskino.generation, leafbuf, this->ext4fs->blksize);
                }

                this->metalock.release();
                ssize_t res = this->ext4fs->writeblock(leafblk, leafbuf);
                this->metalock.acquire();

                delete[] leafbuf;
                return (res >= 0) ? physblk : 0;
            }

            // Leaf is full, and now we need to split.
            // XXX: Implement splitting of extent leaf nodes.
            delete[] leafbuf;
            NUtil::printf("[fs/ext4fs]: Extent leaf full (inode %lu, logblk %lu), splitting not yet implemented\n", (unsigned long)this->attr.st_ino, (unsigned long)logicalblk);
            return 0;
        }

        // Allocate a new extent for the file.
        uint64_t Ext4Node::allocextent(uint64_t logicalblk, uint16_t len) {
            NLib::ScopeIRQSpinlock guard(&this->metalock);

            if (!(this->diskino.flags & EXT4_EXTENTSFL)) {
                // Handle legacy indirect blocks.
                return this->allocindirect(logicalblk);
            }

            struct extenthdr *hdr = (struct extenthdr *)this->diskino.block;
            if (hdr->magic != EXT4_EXTMAGIC) {
                return 0;
            }

            // Try to allocate from the same group as the inode for locality.
            uint32_t inogroup = (this->attr.st_ino - 1) / this->ext4fs->sb.inodespergroup;
            uint64_t physblk = 0;

            // Use batch allocation for contiguous blocks.
            uint32_t allocated = 0;
            this->metalock.release();
            physblk = this->ext4fs->allocblocks(inogroup, len, &allocated);
            this->metalock.acquire();

            if (physblk == 0 || allocated == 0) {
                return 0;
            }

            // Update len to reflect what we actually got.
            len = (uint16_t)allocated;

            // Handle deep extent trees (depth >= 1).
            if (hdr->depth != 0) {
                uint64_t result = this->allocextentdeep(logicalblk, len, physblk);
                if (result == 0) {
                    // allocextentdeep failed (e.g., leaf full), free the allocated blocks.
                    for (uint16_t i = 0; i < len; i++) {
                        this->metalock.release();
                        this->ext4fs->freeblock(physblk + i);
                        this->metalock.acquire();
                    }
                    return 0;
                }
                return result;
            }

            // Depth 0 is inline extents.
            struct extent *extents = (struct extent *)((uint8_t *)this->diskino.block + sizeof(struct extenthdr));

            // Try to extend an existing extent if possible.
            for (uint16_t i = 0; i < hdr->entries; i++) {
                uint32_t extstart = extents[i].fileblk;
                uint16_t extlen = extents[i].len & 0x7FFF;
                uint64_t extphys = ((uint64_t)extents[i].starthi << 32) | extents[i].startlo;

                // Check if we can extend this extent.
                if (logicalblk == extstart + extlen && physblk == extphys + extlen) {
                    // Extend the extent.
                    extents[i].len = (extents[i].len & 0x8000) | ((extlen + len) & 0x7FFF);
                    return physblk;
                }
            }

            // Check if we can add another extent.
            if (hdr->entries >= hdr->max) {
                // Extent array is full, grow the array.
                if (!this->growextenttree()) {
                    // Failed to grow tree, free allocated blocks.
                    for (uint16_t i = 0; i < len; i++) {
                        this->metalock.release();
                        this->ext4fs->freeblock(physblk + i);
                        this->metalock.acquire();
                    }
                    return 0;
                }

                return this->allocextentdeep(logicalblk, len, physblk);
            }

            // Add a new extent entry.
            struct extent *newext = &extents[hdr->entries];
            newext->fileblk = logicalblk;
            newext->len = len;
            newext->starthi = (physblk >> 32) & 0xFFFF;
            newext->startlo = physblk & 0xFFFFFFFF;
            hdr->entries++;

            return physblk;
        }

        // Free all blocks referenced by an extent tree node, recursively.
        void Ext4FileSystem::freeextentblocks(uint32_t *node, uint64_t blknum) {
            struct extenthdr *hdr = (struct extenthdr *)node;

            if (hdr->magic != EXT4_EXTMAGIC) {
                return;
            }

            if (hdr->depth == 0) {
                struct extent *extents = (struct extent *)((uint8_t *)node + sizeof(struct extenthdr));
                for (uint16_t i = 0; i < hdr->entries; i++) {
                    uint64_t physblk = ((uint64_t)extents[i].starthi << 32) | extents[i].startlo;
                    uint16_t len = extents[i].len & 0x7FFF;
                    for (uint16_t j = 0; j < len; j++) {
                        this->freeblock(physblk + j);
                    }
                }
            } else {
                struct extentidx *indices = (struct extentidx *)((uint8_t *)node + sizeof(struct extenthdr));
                uint8_t *childbuf = new uint8_t[this->blksize];

                for (uint16_t i = 0; i < hdr->entries; i++) {
                    uint64_t childblk = ((uint64_t)indices[i].leafhi << 32) | indices[i].leaflo;
                    if (childblk != 0) {
                        if (this->readblock(childblk, childbuf) >= 0) {
                            this->freeextentblocks((uint32_t *)childbuf, childblk);
                        }
                        this->freeblock(childblk);
                    }
                }

                delete[] childbuf;
            }

            // Free the extent tree node itself (if not inline).
            if (blknum != 0) {
                this->freeblock(blknum);
            }
        }
    }
}