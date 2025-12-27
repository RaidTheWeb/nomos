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

                            // Update bitmap checksum in group descriptor before writing.
                            this->updateblockbitmapcsum(group, bitmap);

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

            // Update bitmap checksum in group descriptor before writing.
            this->updateblockbitmapcsum(group, bitmap);

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
    }
}