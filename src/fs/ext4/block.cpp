#include <fs/ext4/defs.hpp>
#include <fs/ext4/ext4fs.hpp>

namespace NFS {
    namespace Ext4FS {
        uint64_t Ext4FileSystem::allocblock(uint32_t prefgroup) {
            for (uint32_t i = 0; i < this->numgroups; i++) { // Loop all groups.
                uint32_t group = (prefgroup + i) % this->numgroups;
                struct groupdesc *gd = &this->groupdescs[group];

                // Check if this group has free blocks.
                uint32_t freeblks = ((uint32_t)gd->freeblkcounthi << 16) | gd->freeblkcountlo;
                if (freeblks == 0) {
                    continue;
                }

                // Read the block bitmap.
                uint64_t bitmapblk = ((uint64_t)gd->blockbitmaphi << 32) | gd->blockbitmaplo;
                uint8_t *bitmap = new uint8_t[this->blksize];
                ssize_t res = this->readblock(bitmapblk, bitmap);
                if (res < 0) {
                    delete[] bitmap;
                    continue;
                }

                for (uint32_t byte = 0; byte < this->blksize; byte++) { // Loop bytes in bitmap.
                    if (bitmap[byte] == 0xFF) {
                        continue; // All bits set.
                    }
                    for (uint8_t bit = 0; bit < 8; bit++) {
                        if (!(bitmap[byte] & (1 << bit))) {
                            // Found a free block.
                            uint32_t blockindex = byte * 8 + bit;
                            if (blockindex >= this->sb.blockspergroup) {
                                break; // Beyond group boundary.
                            }

                            bitmap[byte] |= (1 << bit); // Mark as allocated.

                            // Ensure block bitmap padding is set.
                            this->setblockbitmappadding(bitmap);

                            res = this->writeblock(bitmapblk, bitmap);
                            delete[] bitmap;

                            if (res < 0) {
                                return 0;
                            }

                            freeblks--;
                            // Let group descriptor know we have one less free block.
                            gd->freeblkcountlo = freeblks & 0xFFFF;
                            gd->freeblkcounthi = (freeblks >> 16) & 0xFFFF;
                            this->writegroupdesc(group);

                            uint64_t sbfree = ((uint64_t)this->sb.freeblkcnthi << 32) | this->sb.freeblkcntlo;
                            sbfree--;
                            this->sb.freeblkcntlo = sbfree & 0xFFFFFFFF;
                            this->sb.freeblkcnthi = (sbfree >> 32) & 0xFFFFFFFF;
                            this->writesuperblock();

                            // Calculate and return the absolute block number.
                            uint64_t absblock = (uint64_t)group * this->sb.blockspergroup + blockindex + this->sb.firstdatablk;
                            return absblock;
                        }
                    }
                }

                delete[] bitmap;
            }

            return 0; // No free blocks found.
        }

        // Allocate multiple contiguous blocks from a block group.
        uint64_t Ext4FileSystem::allocblocks(uint32_t prefgroup, uint32_t count, uint32_t *allocated) {
            if (count == 0) {
                *allocated = 0;
                return 0;
            }

            for (uint32_t i = 0; i < this->numgroups; i++) {
                uint32_t group = (prefgroup + i) % this->numgroups;
                struct groupdesc *gd = &this->groupdescs[group];

                // Check if this group has enough free blocks.
                uint32_t freeblks = ((uint32_t)gd->freeblkcounthi << 16) | gd->freeblkcountlo;
                if (freeblks == 0) {
                    continue;
                }

                // Read the block bitmap.
                uint64_t bitmapblk = ((uint64_t)gd->blockbitmaphi << 32) | gd->blockbitmaplo;
                uint8_t *bitmap = new uint8_t[this->blksize];
                ssize_t res = this->readblock(bitmapblk, bitmap);
                if (res < 0) {
                    delete[] bitmap;
                    continue;
                }

                // Scan for a run of contiguous free blocks.
                uint32_t runstart = 0;
                uint32_t runlen = 0;
                uint32_t beststart = 0;
                uint32_t bestlen = 0;

                for (uint32_t blockindex = 0; blockindex < this->sb.blockspergroup; blockindex++) {
                    uint32_t byte = blockindex / 8;
                    uint8_t bit = blockindex % 8;

                    if (!(bitmap[byte] & (1 << bit))) {
                        // Free block found.
                        if (runlen == 0) {
                            runstart = blockindex;
                        }
                        runlen++;

                        // Check if we have enough.
                        if (runlen >= count) {
                            beststart = runstart;
                            bestlen = runlen;
                            break;
                        }
                    } else {
                        // Block is allocated, check if this run is best so far.
                        if (runlen > bestlen) {
                            beststart = runstart;
                            bestlen = runlen;
                        }
                        runlen = 0;
                    }
                }

                // Check final run.
                if (runlen > bestlen) {
                    beststart = runstart;
                    bestlen = runlen;
                }

                if (bestlen == 0) {
                    delete[] bitmap;
                    continue;
                }

                // Cap to requested count.
                if (bestlen > count) {
                    bestlen = count;
                }

                // Mark all blocks in the run as allocated.
                for (uint32_t j = 0; j < bestlen; j++) {
                    uint32_t blockindex = beststart + j;
                    uint32_t byte = blockindex / 8;
                    uint8_t bit = blockindex % 8;
                    bitmap[byte] |= (1 << bit);
                }

                // Ensure block bitmap padding is set.
                this->setblockbitmappadding(bitmap);

                res = this->writeblock(bitmapblk, bitmap);
                delete[] bitmap;

                if (res < 0) {
                    *allocated = 0;
                    return 0;
                }

                // Update group descriptor free count.
                freeblks -= bestlen;
                gd->freeblkcountlo = freeblks & 0xFFFF;
                gd->freeblkcounthi = (freeblks >> 16) & 0xFFFF;
                this->writegroupdesc(group);

                // Update superblock free count.
                uint64_t sbfree = ((uint64_t)this->sb.freeblkcnthi << 32) | this->sb.freeblkcntlo;
                sbfree -= bestlen;
                this->sb.freeblkcntlo = sbfree & 0xFFFFFFFF;
                this->sb.freeblkcnthi = (sbfree >> 32) & 0xFFFFFFFF;
                this->writesuperblock();

                // Calculate and return the first absolute block number.
                uint64_t absblock = (uint64_t)group * this->sb.blockspergroup + beststart + this->sb.firstdatablk;
                *allocated = bestlen;
                return absblock;
            }

            *allocated = 0;
            return 0;
        }

        int Ext4FileSystem::freeblock(uint64_t blknum) {
            if (blknum < this->sb.firstdatablk) {
                return -EINVAL;
            }

            // Calculate which group this block belongs to.
            uint64_t relblock = blknum - this->sb.firstdatablk;
            uint32_t group = relblock / this->sb.blockspergroup;
            uint32_t blockindex = relblock % this->sb.blockspergroup;

            if (group >= this->numgroups) {
                return -EINVAL;
            }

            struct groupdesc *gd = &this->groupdescs[group];

            // Read the block bitmap.
            uint64_t bitmapblk = ((uint64_t)gd->blockbitmaphi << 32) | gd->blockbitmaplo;
            uint8_t *bitmap = new uint8_t[this->blksize];
            ssize_t res = this->readblock(bitmapblk, bitmap);
            if (res < 0) {
                delete[] bitmap;
                return res;
            }

            // Clear the bit in the bitmap.
            uint32_t byte = blockindex / 8;
            uint8_t bit = blockindex % 8;
            if (!(bitmap[byte] & (1 << bit))) {
                delete[] bitmap;
                return -EINVAL; // Block was not allocated.
            }

            bitmap[byte] &= ~(1 << bit);

            // Ensure block bitmap padding is set.
            this->setblockbitmappadding(bitmap);

            res = this->writeblock(bitmapblk, bitmap);
            delete[] bitmap;

            if (res < 0) {
                return res;
            }

            // Update group descriptor free count.
            uint32_t freeblks = ((uint32_t)gd->freeblkcounthi << 16) | gd->freeblkcountlo;
            freeblks++;
            gd->freeblkcountlo = freeblks & 0xFFFF;
            gd->freeblkcounthi = (freeblks >> 16) & 0xFFFF;
            this->writegroupdesc(group);

            // Update superblock free count.
            uint64_t sbfree = ((uint64_t)this->sb.freeblkcnthi << 32) | this->sb.freeblkcntlo;
            sbfree++;
            this->sb.freeblkcntlo = sbfree & 0xFFFFFFFF;
            this->sb.freeblkcnthi = (sbfree >> 32) & 0xFFFFFFFF;
            this->writesuperblock();

            return 0;
        }

        // Allocate a block for indirect block mapping (legacy non-extent inodes).
        uint64_t Ext4Node::allocindirect(uint64_t logicalblk) {
            // Lock is already held by caller (allocextent).
            uint32_t ptrsperblk = this->ext4fs->blksize / sizeof(uint32_t);
            uint64_t singlemax = EXT4_NDIRBLOCKS + ptrsperblk;
            uint64_t doublemax = singlemax + (uint64_t)ptrsperblk * ptrsperblk;
            uint64_t triplemax = doublemax + (uint64_t)ptrsperblk * ptrsperblk * ptrsperblk;

            uint32_t inogroup = (this->attr.st_ino - 1) / this->ext4fs->sb.inodespergroup;

            if (logicalblk >= triplemax) {
                NUtil::printf("[fs/ext4fs]: Block %lu exceeds maximum indirect addressing\n", logicalblk);
                return 0;
            }

            // Allocate the data block first.
            this->metalock.release();
            uint64_t datablk = this->ext4fs->allocblock(inogroup);
            this->metalock.acquire();

            if (datablk == 0) {
                return 0;
            }

            uint8_t *blkbuf = new uint8_t[this->ext4fs->blksize];

            if (logicalblk < EXT4_NDIRBLOCKS) {
                // Direct block.
                this->diskino.block[logicalblk] = datablk;
                delete[] blkbuf;
                return datablk;
            }

            if (logicalblk < singlemax) {
                // Single indirect block.
                uint64_t indblk = this->diskino.block[EXT4_INDBLOCK];
                if (indblk == 0) {
                    // Allocate indirect block.
                    this->metalock.release();
                    indblk = this->ext4fs->allocblock(inogroup);
                    this->metalock.acquire();

                    if (indblk == 0) {
                        this->metalock.release();
                        this->ext4fs->freeblock(datablk);
                        this->metalock.acquire();
                        delete[] blkbuf;
                        return 0;
                    }

                    // Zero the new indirect block.
                    NLib::memset(blkbuf, 0, this->ext4fs->blksize);
                    this->metalock.release();
                    this->ext4fs->writeblock(indblk, blkbuf);
                    this->metalock.acquire();

                    this->diskino.block[EXT4_INDBLOCK] = indblk;
                }

                // Read, update, and write the indirect block.
                this->metalock.release();
                this->ext4fs->readblock(indblk, blkbuf);
                this->metalock.acquire();

                uint32_t *ptrs = (uint32_t *)blkbuf;
                uint32_t idx = logicalblk - EXT4_NDIRBLOCKS;
                ptrs[idx] = datablk;

                this->metalock.release();
                this->ext4fs->writeblock(indblk, blkbuf);
                this->metalock.acquire();

                delete[] blkbuf;
                return datablk;
            }

            if (logicalblk < doublemax) {
                // Double indirect block.
                uint64_t dindblk = this->diskino.block[EXT4_DINDBLOCK];
                if (dindblk == 0) {
                    // Allocate double indirect block.
                    this->metalock.release();
                    dindblk = this->ext4fs->allocblock(inogroup);
                    this->metalock.acquire();

                    if (dindblk == 0) {
                        this->metalock.release();
                        this->ext4fs->freeblock(datablk);
                        this->metalock.acquire();
                        delete[] blkbuf;
                        return 0;
                    }

                    NLib::memset(blkbuf, 0, this->ext4fs->blksize);
                    this->metalock.release();
                    this->ext4fs->writeblock(dindblk, blkbuf);
                    this->metalock.acquire();

                    this->diskino.block[EXT4_DINDBLOCK] = dindblk;
                }

                uint64_t offset = logicalblk - singlemax;
                uint32_t idx1 = offset / ptrsperblk;
                uint32_t idx2 = offset % ptrsperblk;

                // Read double indirect block.
                this->metalock.release();
                this->ext4fs->readblock(dindblk, blkbuf);
                this->metalock.acquire();

                uint32_t *ptrs = (uint32_t *)blkbuf;
                uint64_t indblk = ptrs[idx1];

                if (indblk == 0) {
                    // Allocate single indirect block.
                    this->metalock.release();
                    indblk = this->ext4fs->allocblock(inogroup);
                    this->metalock.acquire();

                    if (indblk == 0) {
                        this->metalock.release();
                        this->ext4fs->freeblock(datablk);
                        this->metalock.acquire();
                        delete[] blkbuf;
                        return 0;
                    }

                    // Zero and write new indirect block.
                    uint8_t *indbuf = new uint8_t[this->ext4fs->blksize];
                    NLib::memset(indbuf, 0, this->ext4fs->blksize);
                    this->metalock.release();
                    this->ext4fs->writeblock(indblk, indbuf);
                    this->metalock.acquire();
                    delete[] indbuf;

                    // Update double indirect block.
                    ptrs[idx1] = indblk;
                    this->metalock.release();
                    this->ext4fs->writeblock(dindblk, blkbuf);
                    this->metalock.acquire();
                }

                // Read and update single indirect block.
                this->metalock.release();
                this->ext4fs->readblock(indblk, blkbuf);
                this->metalock.acquire();

                ptrs = (uint32_t *)blkbuf;
                ptrs[idx2] = datablk;

                this->metalock.release();
                this->ext4fs->writeblock(indblk, blkbuf);
                this->metalock.acquire();

                delete[] blkbuf;
                return datablk;
            }

            // Triple indirect block.
            uint64_t tindblk = this->diskino.block[EXT4_TINDBLOCK];
            if (tindblk == 0) {
                this->metalock.release();
                tindblk = this->ext4fs->allocblock(inogroup);
                this->metalock.acquire();

                if (tindblk == 0) {
                    this->metalock.release();
                    this->ext4fs->freeblock(datablk);
                    this->metalock.acquire();
                    delete[] blkbuf;
                    return 0;
                }

                NLib::memset(blkbuf, 0, this->ext4fs->blksize);
                this->metalock.release();
                this->ext4fs->writeblock(tindblk, blkbuf);
                this->metalock.acquire();

                this->diskino.block[EXT4_TINDBLOCK] = tindblk;
            }

            uint64_t offset = logicalblk - doublemax;
            uint64_t blocksper2 = (uint64_t)ptrsperblk * ptrsperblk;
            uint32_t idx1 = offset / blocksper2;
            uint64_t rem = offset % blocksper2;
            uint32_t idx2 = rem / ptrsperblk;
            uint32_t idx3 = rem % ptrsperblk;

            // Read triple indirect block.
            this->metalock.release();
            this->ext4fs->readblock(tindblk, blkbuf);
            this->metalock.acquire();

            uint32_t *ptrs = (uint32_t *)blkbuf;
            uint64_t dindblk = ptrs[idx1];

            if (dindblk == 0) {
                this->metalock.release();
                dindblk = this->ext4fs->allocblock(inogroup);
                this->metalock.acquire();

                if (dindblk == 0) {
                    this->metalock.release();
                    this->ext4fs->freeblock(datablk);
                    this->metalock.acquire();
                    delete[] blkbuf;
                    return 0;
                }

                uint8_t *dindbuf = new uint8_t[this->ext4fs->blksize];
                NLib::memset(dindbuf, 0, this->ext4fs->blksize);
                this->metalock.release();
                this->ext4fs->writeblock(dindblk, dindbuf);
                this->metalock.acquire();
                delete[] dindbuf;

                ptrs[idx1] = dindblk;
                this->metalock.release();
                this->ext4fs->writeblock(tindblk, blkbuf);
                this->metalock.acquire();
            }

            // Read double indirect block.
            this->metalock.release();
            this->ext4fs->readblock(dindblk, blkbuf);
            this->metalock.acquire();

            ptrs = (uint32_t *)blkbuf;
            uint64_t indblk = ptrs[idx2];

            if (indblk == 0) {
                this->metalock.release();
                indblk = this->ext4fs->allocblock(inogroup);
                this->metalock.acquire();

                if (indblk == 0) {
                    this->metalock.release();
                    this->ext4fs->freeblock(datablk);
                    this->metalock.acquire();
                    delete[] blkbuf;
                    return 0;
                }

                uint8_t *indbuf = new uint8_t[this->ext4fs->blksize];
                NLib::memset(indbuf, 0, this->ext4fs->blksize);
                this->metalock.release();
                this->ext4fs->writeblock(indblk, indbuf);
                this->metalock.acquire();
                delete[] indbuf;

                ptrs[idx2] = indblk;
                this->metalock.release();
                this->ext4fs->writeblock(dindblk, blkbuf);
                this->metalock.acquire();
            }

            // Read and update single indirect block.
            this->metalock.release();
            this->ext4fs->readblock(indblk, blkbuf);
            this->metalock.acquire();

            ptrs = (uint32_t *)blkbuf;
            ptrs[idx3] = datablk;

            this->metalock.release();
            this->ext4fs->writeblock(indblk, blkbuf);
            this->metalock.acquire();

            delete[] blkbuf;
            return datablk;
        }


        // Resolve the physical block (the actual stuff on the disk) for a logical (filesystem) block.
        uint64_t Ext4Node::getphysblock(uint64_t logicalblk) {
            if (!(this->diskino.flags & EXT4_EXTENTSFL)) { // Legacy indirect blocks.
                if (logicalblk < EXT4_NDIRBLOCKS) {
                    return this->diskino.block[logicalblk];
                }

                // Handle single/double/triple indirect blocks.
                return this->getindirectblock(logicalblk);
            }

            // Extent-mapped inode. The block[] array contains the extent tree.
            struct extenthdr *hdr = (struct extenthdr *)this->diskino.block;

            if (hdr->magic != EXT4_EXTMAGIC) {
                NUtil::printf("[fs/ext4fs]: Invalid extent magic: 0x%x\n", hdr->magic);
                return 0;
            }

            // Walk the extent tree.
            uint8_t *node = (uint8_t *)this->diskino.block;
            uint8_t *allocbuf = NULL;

            while (true) {
                hdr = (struct extenthdr *)node;

                if (hdr->depth == 0) { // "Leaf node".

                    // Contains the actual extents records.
                    struct extent *extents = (struct extent *)(node + sizeof(struct extenthdr));
                    for (uint16_t i = 0; i < hdr->entries; i++) {
                        uint32_t startblk = extents[i].fileblk;
                        uint16_t len = extents[i].len & 0x7FFF; // Mask out uninitialized flag.
                        if (logicalblk >= startblk && logicalblk < startblk + len) {

                            uint64_t physblk = ((uint64_t)extents[i].starthi << 32) | extents[i].startlo;
                            physblk += (logicalblk - startblk);

                            if (allocbuf) {
                                delete[] allocbuf;
                            }
                            return physblk; // Ultimately return the physical block.
                        }
                    }
                    // Block not found in any extent (hole).
                    if (allocbuf) {
                        delete[] allocbuf;
                    }
                    return 0;
                } else {
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
                        if (allocbuf) {
                            delete[] allocbuf;
                        }
                        return 0;
                    }

                    // Read the next level of the extent tree.
                    uint64_t childblk = ((uint64_t)found->leafhi << 32) | found->leaflo;

                    if (allocbuf) {
                        delete[] allocbuf;
                    }
                    allocbuf = new uint8_t[this->ext4fs->blksize]; // Allocate buffer for reading block.
                    if (this->ext4fs->readblock(childblk, allocbuf) < 0) {
                        delete[] allocbuf;
                        return 0;
                    }
                    node = allocbuf;
                }
            }
        }

        // Resolve the physical block for a logical block AND return the contiguous run length.
        uint64_t Ext4Node::getextentrun(uint64_t logicalblk, uint64_t *runlen) {
            uint64_t localrunlen = 1; // Default to single block.

            // Check extent cache first.
            uint64_t cachedphys = 0;
            if (this->lookupcachedextent(logicalblk, &cachedphys, &localrunlen)) {
                if (runlen) *runlen = localrunlen;
                return cachedphys;
            }

            if (!(this->diskino.flags & EXT4_EXTENTSFL)) {
                // Legacy indirect blocks. Stays at 1.
                if (runlen) {
                    *runlen = localrunlen;
                }
                if (logicalblk < EXT4_NDIRBLOCKS) {
                    return this->diskino.block[logicalblk];
                }
                return this->getindirectblock(logicalblk);
            }

            // Extent-mapped inode.
            struct extenthdr *hdr = (struct extenthdr *)this->diskino.block;

            if (hdr->magic != EXT4_EXTMAGIC) {
                NUtil::printf("[fs/ext4fs]: Invalid extent magic: 0x%x\n", hdr->magic);
                return 0;
            }

            // Walk the extent tree.
            uint8_t *node = (uint8_t *)this->diskino.block;
            uint8_t *allocbuf = NULL;

            while (true) {
                hdr = (struct extenthdr *)node;

                if (hdr->depth == 0) { // Leaf node with extent records.
                    struct extent *extents = (struct extent *)(node + sizeof(struct extenthdr));
                    for (uint16_t i = 0; i < hdr->entries; i++) {
                        uint32_t startblk = extents[i].fileblk;
                        uint16_t len = extents[i].len & 0x7FFF; // Mask out uninitialized flag.
                        if (logicalblk >= startblk && logicalblk < startblk + len) {
                            uint64_t offset = logicalblk - startblk;
                            uint64_t extphysstart = ((uint64_t)extents[i].starthi << 32) | extents[i].startlo;
                            uint64_t physblk = extphysstart + offset;

                            // Cache this extent for future lookups.
                            this->cacheextent(startblk, extphysstart, len);

                            // Return remaining blocks in this extent.
                            localrunlen = len - offset;
                            if (runlen) {
                                *runlen = localrunlen;
                            }

                            if (allocbuf) {
                                delete[] allocbuf;
                            }
                            return physblk;
                        }
                    }
                    // Block not found (hole).
                    if (allocbuf) {
                        delete[] allocbuf;
                    }
                    if (runlen) {
                        *runlen = 1; // Holes are single-block by default.
                    }
                    return 0;
                } else {
                    struct extentidx *indices = (struct extentidx *)(node + sizeof(struct extenthdr));
                    struct extentidx *found = NULL;

                    for (uint16_t i = 0; i < hdr->entries; i++) {
                        if (logicalblk >= indices[i].fileblk) {
                            found = &indices[i];
                        } else {
                            break;
                        }
                    }

                    if (!found) {
                        if (allocbuf) {
                            delete[] allocbuf;
                        }
                        return 0;
                    }

                    uint64_t childblk = ((uint64_t)found->leafhi << 32) | found->leaflo;

                    if (allocbuf) {
                        delete[] allocbuf;
                    }
                    allocbuf = new uint8_t[this->ext4fs->blksize];
                    if (this->ext4fs->readblock(childblk, allocbuf) < 0) {
                        delete[] allocbuf;
                        return 0;
                    }
                    node = allocbuf;
                }
            }
        }

        // Check extent cache for a cached mapping.
        bool Ext4Node::lookupcachedextent(uint64_t logicalblk, uint64_t *physblk, uint64_t *runlen) {
            NLib::ScopeSpinlock guard(&this->extentcachelock);
            for (size_t i = 0; i < EXTENT_CACHESIZE; i++) {
                struct extentcacheentry &e = this->extentcache[i];
                if (e.valid &&
                    logicalblk >= e.logicalstart &&
                    logicalblk < e.logicalstart + e.len) {
                    uint64_t off = logicalblk - e.logicalstart;
                    *physblk = e.physstart + off;
                    *runlen = e.len - off;
                    return true;
                }
            }
            return false;
        }

        // Cache an extent mapping.
        void Ext4Node::cacheextent(uint64_t logicalstart, uint64_t physstart, uint32_t len) {
            NLib::ScopeSpinlock guard(&this->extentcachelock);
            // Check if this extent is already cached.
            for (size_t i = 0; i < EXTENT_CACHESIZE; i++) {
                struct extentcacheentry &e = this->extentcache[i];
                if (e.valid && e.logicalstart == logicalstart) {
                    // Update existing entry.
                    e.physstart = physstart;
                    e.len = len;
                    return;
                }
            }

            // Insert at round-robin position.
            struct extentcacheentry &e = this->extentcache[this->extentcacheidx];
            e.logicalstart = logicalstart;
            e.physstart = physstart;
            e.len = len;
            e.valid = true;
            this->extentcacheidx = (this->extentcacheidx + 1) % EXTENT_CACHESIZE;
        }

        // Invalidate all cached extents.
        void Ext4Node::invalidateextentcache(void) {
            NLib::ScopeSpinlock guard(&this->extentcachelock);
            for (size_t i = 0; i < EXTENT_CACHESIZE; i++) {
                this->extentcache[i].valid = false;
            }
        }
    }
}