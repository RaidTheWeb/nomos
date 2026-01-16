#include <dev/block.hpp>
#include <fs/ext4/defs.hpp>
#include <fs/ext4/ext4fs.hpp>
#include <lib/string.hpp>
#include <mm/slab.hpp>
#include <std/stdatomic.h>
#include <stddef.h>
#include <sys/clock.hpp>
#include <util/kprint.hpp>

namespace NFS {
    namespace Ext4FS {

        // Convert EXT4 inode mode to VFS mode.
        static uint32_t inotomode(uint16_t mode) {
            uint32_t vfsmode = mode & 07777; // Permission bits.
            uint16_t type = mode & 0xF000;
            switch (type) {
                case 0x1000: vfsmode |= VFS::S_IFIFO; break;
                case 0x2000: vfsmode |= VFS::S_IFCHR; break;
                case 0x4000: vfsmode |= VFS::S_IFDIR; break;
                case 0x6000: vfsmode |= VFS::S_IFBLK; break;
                case 0x8000: vfsmode |= VFS::S_IFREG; break;
                case 0xA000: vfsmode |= VFS::S_IFLNK; break;
                case 0xC000: vfsmode |= VFS::S_IFSOCK; break;
            }
            return vfsmode;
        }

        ssize_t Ext4FileSystem::readblock(uint64_t blknum, void *buf) {
            off_t offset = blknum * this->blksize;
            // Use IO_METADATA to enable caching for filesystem metadata.
            return this->blkdev->readbytes(buf, this->blksize, offset, 0, NDev::IO_METADATA);
        }

        ssize_t Ext4FileSystem::writeblock(uint64_t blknum, const void *buf) {
            off_t offset = blknum * this->blksize;
            // Use IO_METADATA to enable caching for filesystem metadata.
            return this->blkdev->writebytes(buf, this->blksize, offset, 0, NDev::IO_METADATA);
        }

        void Ext4FileSystem::setinodebitmappadding(void *bitmap) {
            // Bits beyond inodespergroup should be set to 1.
            uint32_t inodespergroup = this->sb.inodespergroup;
            uint32_t lastbyte = inodespergroup / 8;
            uint8_t lastbitindex = inodespergroup % 8;
            uint8_t *bmp = (uint8_t *)bitmap;

            // Set remaining bits in the partial byte.
            if (lastbitindex != 0) {
                uint8_t mask = 0xFF << lastbitindex;
                bmp[lastbyte] |= mask;
                lastbyte++;
            }

            // Set all remaining bytes to 0xFF.
            for (uint32_t i = lastbyte; i < this->blksize; i++) {
                bmp[i] = 0xFF;
            }
        }

        void Ext4FileSystem::setblockbitmappadding(void *bitmap) {
            // Bits beyond blockspergroup should be set to 1.
            uint32_t blockspergroup = this->sb.blockspergroup;
            uint32_t lastbyte = blockspergroup / 8;
            uint8_t lastbitindex = blockspergroup % 8;
            uint8_t *bmp = (uint8_t *)bitmap;

            // Set remaining bits in the partial byte.
            if (lastbitindex != 0) {
                uint8_t mask = 0xFF << lastbitindex;
                bmp[lastbyte] |= mask;
                lastbyte++;
            }

            // Set all remaining bytes to 0xFF.
            for (uint32_t i = lastbyte; i < this->blksize; i++) {
                bmp[i] = 0xFF;
            }
        }

        uint32_t Ext4FileSystem::countfreeblocks(uint32_t group, const void *bitmap) {
            uint32_t count = 0;
            const uint8_t *bmp = (const uint8_t *)bitmap;
            uint32_t blockspergroup = this->sb.blockspergroup;

            for (uint32_t i = 0; i < blockspergroup; i++) {
                uint32_t byte = i / 8;
                uint8_t bit = i % 8;
                if (!(bmp[byte] & (1 << bit))) {
                    count++;
                }
            }
            return count;
        }

        uint32_t Ext4FileSystem::countfreeinodes(uint32_t group, const void *bitmap) {
            uint32_t count = 0;
            const uint8_t *bmp = (const uint8_t *)bitmap;
            uint32_t inodespergroup = this->sb.inodespergroup;

            for (uint32_t i = 0; i < inodespergroup; i++) {
                uint32_t byte = i / 8;
                uint8_t bit = i % 8;
                if (!(bmp[byte] & (1 << bit))) {
                    count++;
                }
            }
            return count;
        }

        int Ext4FileSystem::writeinode(uint32_t ino, struct inode *diskino) {
            if (ino == 0) {
                return -EINVAL;
            }

            // Calculate which block group contains this inode.
            uint32_t group = (ino - 1) / this->sb.inodespergroup;
            uint32_t index = (ino - 1) % this->sb.inodespergroup;

            if (group >= this->numgroups) {
                NUtil::printf("[fs/ext4fs]: Inode %u is in invalid group %u.\n", ino, group);
                return -EINVAL;
            }

            // Get the inode table location from the block group descriptor.
            struct groupdesc *gd = &this->groupdescs[group];
            uint64_t inodetable = ((uint64_t)gd->inodetablehi << 32) | gd->inodetablelo;

            // Calculate the offset of this inode within the inode table.
            uint64_t inodeoff = inodetable * this->blksize + index * this->sb.inodesize;

            // Allocate a buffer for the full on-disk inode size.
            uint8_t *inodebuf = new uint8_t[this->sb.inodesize];
            if (!inodebuf) {
                return -ENOMEM;
            }

            // Read the existing on-disk inode to preserve extra fields.
            ssize_t res = this->blkdev->readbytes(inodebuf, this->sb.inodesize, inodeoff, 0, NDev::IO_METADATA);
            if (res < 0) {
                delete[] inodebuf;
                NUtil::printf("[fs/ext4fs]: Failed to read inode %u for update: %d.\n", ino, (int)res);
                return res;
            }

            // Copy our modified inode struct into the buffer.
            size_t copysize = this->sb.inodesize < sizeof(struct inode) ? this->sb.inodesize : sizeof(struct inode);
            NLib::memcpy(inodebuf, diskino, copysize);

            // Write the full inode buffer back to disk.
            res = this->blkdev->writebytes(inodebuf, this->sb.inodesize, inodeoff, 0, NDev::IO_METADATA);
            delete[] inodebuf;
            if (res < 0) {
                NUtil::printf("[fs/ext4fs]: Failed to write inode %u: %d.\n", ino, (int)res);
                return res;
            }

            return 0;
        }

        int Ext4FileSystem::writesuperblock(void) {
            ssize_t res = this->blkdev->writebytes(&this->sb, sizeof(struct superblock), 1024, 0, NDev::IO_METADATA);
            if (res < 0) {
                NUtil::printf("[fs/ext4fs]: Failed to write superblock: %d\n", (int)res);
                return res;
            }
            return 0;
        }

        int Ext4FileSystem::writegroupdesc(uint32_t group) {
            if (group >= this->numgroups) {
                return -EINVAL;
            }

            uint64_t bgdtblock = (this->blksize == 1024) ? 2 : 1;
            uint16_t descsize = this->sb.descsize ? this->sb.descsize : 32;
            uint64_t offset = bgdtblock * this->blksize + group * descsize;

            ssize_t res = this->blkdev->writebytes(&this->groupdescs[group], descsize, offset, 0, NDev::IO_METADATA);
            if (res < 0) {
                NUtil::printf("[fs/ext4fs]: Failed to write group descriptor %u: %d\n", group, (int)res);
                return res;
            }
            return 0;
        }

        uint32_t Ext4FileSystem::allocinode(uint32_t prefgroup, bool isdir) {
            for (uint32_t i = 0; i < this->numgroups; i++) { // Loop all groups.
                uint32_t group = (prefgroup + i) % this->numgroups;
                struct groupdesc *gd = &this->groupdescs[group];

                // Check if this group has free inodes.
                uint32_t freeinodes = ((uint32_t)gd->freeinodecounthi << 16) | gd->freeinodecountlo;
                if (freeinodes == 0) {
                    continue;
                }

                // Read the inode bitmap.
                uint64_t bitmapblk = ((uint64_t)gd->inodebitmaphi << 32) | gd->inodebitmaplo;
                uint8_t *bitmap = new uint8_t[this->blksize];
                ssize_t res = this->readblock(bitmapblk, bitmap);
                if (res < 0) {
                    delete[] bitmap;
                    continue;
                }

                // Search for a free bit in the bitmap.
                for (uint32_t byte = 0; byte < this->blksize; byte++) { // Loop bytes in bitmap.
                    if (bitmap[byte] == 0xFF) {
                        continue; // All bits set.
                    }
                    for (uint8_t bit = 0; bit < 8; bit++) {
                        if (!(bitmap[byte] & (1 << bit))) {
                            // Found a free inode.
                            uint32_t inodeindex = byte * 8 + bit;
                            if (inodeindex >= this->sb.inodespergroup) {
                                break; // Beyond group boundary.
                            }

                            // Mark the inode as allocated.
                            bitmap[byte] |= (1 << bit);

                            // Ensure inode bitmap padding is set.
                            this->setinodebitmappadding(bitmap);

                            res = this->writeblock(bitmapblk, bitmap);
                            delete[] bitmap;

                            if (res < 0) {
                                return 0;
                            }

                            // Update group descriptor free count.
                            freeinodes--;
                            gd->freeinodecountlo = freeinodes & 0xFFFF;
                            gd->freeinodecounthi = (freeinodes >> 16) & 0xFFFF;

                            // Update directory count if allocating for a directory.
                            if (isdir) {
                                uint32_t useddirs = ((uint32_t)gd->usedircounthi << 16) | gd->usedircountlo;
                                useddirs++;
                                gd->usedircountlo = useddirs & 0xFFFF;
                                gd->usedircounthi = (useddirs >> 16) & 0xFFFF;
                            }

                            this->writegroupdesc(group);

                            // Update superblock free count.
                            this->sb.freeinodecnt--;
                            this->writesuperblock();

                            // Calculate and return the inode number (1-based).
                            uint32_t ino = group * this->sb.inodespergroup + inodeindex + 1;
                            return ino;
                        }
                    }
                }

                delete[] bitmap;
            }

            return 0; // No free inodes found.
        }

        int Ext4FileSystem::freeinode(uint32_t ino, bool isdir) {
            if (ino == 0) {
                return -EINVAL;
            }

            // Calculate which group this inode belongs to.
            uint32_t group = (ino - 1) / this->sb.inodespergroup;
            uint32_t inodeindex = (ino - 1) % this->sb.inodespergroup;

            if (group >= this->numgroups) {
                return -EINVAL;
            }

            struct groupdesc *gd = &this->groupdescs[group];

            // Read the inode bitmap.
            uint64_t bitmapblk = ((uint64_t)gd->inodebitmaphi << 32) | gd->inodebitmaplo;
            uint8_t *bitmap = new uint8_t[this->blksize];
            ssize_t res = this->readblock(bitmapblk, bitmap);
            if (res < 0) {
                delete[] bitmap;
                return res;
            }

            // Clear the bit in the bitmap.
            uint32_t byte = inodeindex / 8;
            uint8_t bit = inodeindex % 8;
            if (!(bitmap[byte] & (1 << bit))) {
                delete[] bitmap;
                return -EINVAL; // Inode was not allocated.
            }

            bitmap[byte] &= ~(1 << bit);

            // Ensure inode bitmap padding is set.
            this->setinodebitmappadding(bitmap);

            res = this->writeblock(bitmapblk, bitmap);
            delete[] bitmap;

            if (res < 0) {
                return res;
            }

            // Update group descriptor free count.
            uint32_t freeinodes = ((uint32_t)gd->freeinodecounthi << 16) | gd->freeinodecountlo;
            freeinodes++;
            gd->freeinodecountlo = freeinodes & 0xFFFF;
            gd->freeinodecounthi = (freeinodes >> 16) & 0xFFFF;

            // Update directory count if freeing a directory.
            if (isdir) {
                uint32_t useddirs = ((uint32_t)gd->usedircounthi << 16) | gd->usedircountlo;
                if (useddirs > 0) {
                    useddirs--;
                    gd->usedircountlo = useddirs & 0xFFFF;
                    gd->usedircounthi = (useddirs >> 16) & 0xFFFF;
                }
            }

            this->writegroupdesc(group);

            // Update superblock free count.
            this->sb.freeinodecnt++;
            this->writesuperblock();

            return 0;
        }

        int Ext4FileSystem::umount(int flags) {
            (void)flags;

            if (!this->mounted) {
                return -EINVAL; // Not mounted.
            }

            // Sync all dirty data to disk before unmounting.
            this->sync();

            // Mark as unmounted.
            this->mounted = false;

            if (this->root) {
                delete this->root;
                this->root = NULL;
            }

            // Free group descriptors.
            if (this->groupdescs) {
                delete[] this->groupdescs;
                this->groupdescs = NULL;
            }

            NUtil::printf("[fs/ext4fs]: Unmounted ext4 filesystem\n");

            return 0;
        }

        int Ext4FileSystem::sync(void) {
            // Sync cached data to disk via page cache.
            if (this->blkdev) {
                NUtil::printf("[fs/ext4fs]: Syncing filesystem...\n");
                this->blkdev->syncdevice();
                NUtil::printf("[fs/ext4fs]: Sync complete\n");
            }
            return 0;
        }

        ssize_t Ext4FileSystem::create(const char *name, VFS::INode **nodeout, struct VFS::stat attr) {
            bool isdir = VFS::S_ISDIR(attr.st_mode);

            // Allocate a new inode.
            uint32_t ino = this->allocinode(0, isdir);
            if (ino == 0) {
                return -ENOSPC;
            }

            // Initialize the on-disk inode structure.
            struct inode diskino;
            NLib::memset(&diskino, 0, sizeof(struct inode));

            // Convert VFS mode to ext4 mode.
            uint16_t ext4mode = attr.st_mode & 07777; // Permission bits.
            uint32_t type = attr.st_mode & VFS::S_IFMT;
            switch (type) {
                case VFS::S_IFIFO: ext4mode |= 0x1000; break;
                case VFS::S_IFCHR: ext4mode |= 0x2000; break;
                case VFS::S_IFDIR: ext4mode |= 0x4000; break;
                case VFS::S_IFBLK: ext4mode |= 0x6000; break;
                case VFS::S_IFREG: ext4mode |= 0x8000; break;
                case VFS::S_IFLNK: ext4mode |= 0xA000; break;
                case VFS::S_IFSOCK: ext4mode |= 0xC000; break;
            }
            diskino.mode = ext4mode;

            diskino.uid = attr.st_uid & 0xFFFF;
            diskino.uidhi = (attr.st_uid >> 16) & 0xFFFF;
            diskino.gid = attr.st_gid & 0xFFFF;
            diskino.gidhi = (attr.st_gid >> 16) & 0xFFFF;

            // Set link count.
            if (isdir) {
                diskino.linkscount = 2; // . and parent's link to us.
            } else {
                diskino.linkscount = 1;
            }

            // Set timestamps.
            NSys::Clock::Clock *realtime = NSys::Clock::getclock(NSys::Clock::CLOCK_REALTIME);
            struct NSys::Clock::timespec ts;
            realtime->gettime(&ts);

            diskino.atime = ts.tv_sec;
            diskino.ctime = ts.tv_sec;
            diskino.mtime = ts.tv_sec;
            diskino.dtime = 0;

            // Set up extent tree for new files.
            diskino.flags = EXT4_EXTENTSFL;
            struct extenthdr *hdr = (struct extenthdr *)diskino.block;
            hdr->magic = EXT4_EXTMAGIC;
            hdr->entries = 0;
            hdr->max = (sizeof(diskino.block) - sizeof(struct extenthdr)) / sizeof(struct extent);
            hdr->depth = 0;
            hdr->generation = 0;

            // Write the inode to disk.
            int res = this->writeinode(ino, &diskino);
            if (res < 0) {
                this->freeinode(ino, isdir);
                return res;
            }

            // Build VFS stat structure.
            attr.st_ino = ino;
            attr.st_blksize = this->blksize;
            attr.st_blocks = 0;
            attr.st_nlink = diskino.linkscount;

            // Create the node.
            Ext4Node *node = new Ext4Node(this, name, attr, &diskino);
            *nodeout = node;

            return 0;
        }

        int Ext4FileSystem::unlink(VFS::INode *node, VFS::INode *parent) {
            Ext4Node *ext4node = (Ext4Node *)node;
            uint32_t ino = node->getattr().st_ino;
            bool isdir = VFS::S_ISDIR(node->getattr().st_mode);

            // Remove from parent directory.
            bool worked = parent->remove(node->getname());
            parent->unref();
            node->unref();

            if (!worked) {
                return -EINVAL;
            }

            // Decrement link count.
            uint64_t nlink = 0;
            ssize_t res = node->unlink(&nlink);

            if (res == 0) {
                // Free all associated blocks.
                if (ext4node->diskino.flags & EXT4_EXTENTSFL) {
                    // Free extent-based blocks recursively.
                    this->freeextentblocks(ext4node->diskino.block, 0);
                } else {
                    // Free indirect-based blocks.
                    this->freeindirectblocks(&ext4node->diskino);
                }

                // Free the inode.
                this->freeinode(ino, isdir);

                // Delete in-memory node.
                delete node;
            }

            return 0;
        }

        int Ext4FileSystem::rename(VFS::INode *oldparent, VFS::INode *node, VFS::INode *newparent, const char *newname, VFS::INode *target) {
            Ext4Node *ext4oldparent = (Ext4Node *)oldparent;
            Ext4Node *ext4node = (Ext4Node *)node;

            // If target exists, we need to unlink it first.
            if (target) {
                Ext4Node *ext4target = (Ext4Node *)target;

                // If target is a directory, it must be empty.
                if (VFS::S_ISDIR(target->getattr().st_mode)) {
                    if (!target->empty()) {
                        oldparent->unref();
                        node->unref();
                        newparent->unref();
                        target->unref();
                        return -ENOTEMPTY;
                    }
                }

                // Remove target from newparent directory.
                bool worked = newparent->remove(target->getname());
                if (!worked) {
                    oldparent->unref();
                    node->unref();
                    newparent->unref();
                    target->unref();
                    return -EINVAL;
                }

                // Unlink target and free its resources if link count reaches zero.
                uint32_t targetino = target->getattr().st_ino;
                bool targetisdir = VFS::S_ISDIR(target->getattr().st_mode);
                uint64_t nlink = 0;
                ssize_t res = target->unlink(&nlink);
                if (res == 0) {
                    // Free all associated blocks.
                    if (ext4target->diskino.flags & EXT4_EXTENTSFL) {
                        this->freeextentblocks(ext4target->diskino.block, 0);
                    } else {
                        this->freeindirectblocks(&ext4target->diskino);
                    }
                    this->freeinode(targetino, targetisdir);
                    delete target;
                } else {
                    target->unref();
                }
            }

            // Remove node from old parent directory.
            const char *oldname = node->getname();
            bool worked = oldparent->remove(oldname);
            if (!worked) {
                oldparent->unref();
                node->unref();
                newparent->unref();
                return -EINVAL;
            }

            // Remove from old parent's children cache.
            ext4oldparent->_removechild(oldname);

            // Set new name on the node.
            node->setname(newname);

            // Add to new parent directory with the new name.
            if (!newparent->add(node)) {
                // Orphaned, try to rollback. NOTE: If we can't, it's lost.
                node->setname(oldname);
                oldparent->add(node);
                oldparent->unref();
                node->unref();
                newparent->unref();
                return -EIO;
            }

            // New creation time for moved node.
            ext4node->commitmetadata(false, true, false);

            oldparent->unref();
            newparent->unref();
            node->unref();

            return 0;
        }

        // Free all blocks referenced by indirect block pointers, recursively.
        void Ext4FileSystem::freeindirectblocks(struct inode *diskino) {
            // Free direct blocks.
            for (int i = 0; i < EXT4_NDIRBLOCKS; i++) {
                if (diskino->block[i] != 0) {
                    this->freeblock(diskino->block[i]);
                }
            }

            uint32_t ptrsperblk = this->blksize / sizeof(uint32_t);
            uint8_t *blkbuf = new uint8_t[this->blksize];

            // Free single indirect blocks.
            if (diskino->block[EXT4_INDBLOCK] != 0) {
                uint64_t indblk = diskino->block[EXT4_INDBLOCK];
                if (this->readblock(indblk, blkbuf) >= 0) {
                    uint32_t *ptrs = (uint32_t *)blkbuf;
                    for (uint32_t i = 0; i < ptrsperblk; i++) {
                        if (ptrs[i] != 0) {
                            this->freeblock(ptrs[i]);
                        }
                    }
                }
                this->freeblock(indblk);
            }

            // Free double indirect blocks.
            if (diskino->block[EXT4_DINDBLOCK] != 0) {
                uint64_t dindblk = diskino->block[EXT4_DINDBLOCK];
                uint8_t *indbuf = new uint8_t[this->blksize];

                if (this->readblock(dindblk, blkbuf) >= 0) {
                    uint32_t *dptrs = (uint32_t *)blkbuf;
                    for (uint32_t i = 0; i < ptrsperblk; i++) {
                        if (dptrs[i] != 0) {
                            if (this->readblock(dptrs[i], indbuf) >= 0) {
                                uint32_t *ptrs = (uint32_t *)indbuf;
                                for (uint32_t j = 0; j < ptrsperblk; j++) {
                                    if (ptrs[j] != 0) {
                                        this->freeblock(ptrs[j]);
                                    }
                                }
                            }
                            this->freeblock(dptrs[i]);
                        }
                    }
                }
                delete[] indbuf;
                this->freeblock(dindblk);
            }

            // Free triple indirect blocks.
            if (diskino->block[EXT4_TINDBLOCK] != 0) {
                uint64_t tindblk = diskino->block[EXT4_TINDBLOCK];
                uint8_t *dindbuf = new uint8_t[this->blksize];
                uint8_t *indbuf = new uint8_t[this->blksize];

                // XXX: This is horrific. I'm sorry.
                // Genuinely considering unimplementing it because of how rare it even is.
                if (this->readblock(tindblk, blkbuf) >= 0) {
                    uint32_t *tptrs = (uint32_t *)blkbuf;
                    for (uint32_t i = 0; i < ptrsperblk; i++) {
                        if (tptrs[i] != 0) {
                            if (this->readblock(tptrs[i], dindbuf) >= 0) {
                                uint32_t *dptrs = (uint32_t *)dindbuf;
                                for (uint32_t j = 0; j < ptrsperblk; j++) {
                                    if (dptrs[j] != 0) {
                                        if (this->readblock(dptrs[j], indbuf) >= 0) {
                                            uint32_t *ptrs = (uint32_t *)indbuf;
                                            for (uint32_t k = 0; k < ptrsperblk; k++) {
                                                if (ptrs[k] != 0) {
                                                    this->freeblock(ptrs[k]);
                                                }
                                            }
                                        }
                                        this->freeblock(dptrs[j]);
                                    }
                                }
                            }
                            this->freeblock(tptrs[i]);
                        }
                    }
                }
                delete[] indbuf;
                delete[] dindbuf;
                this->freeblock(tindblk);
            }

            delete[] blkbuf;
        }

        Ext4Node *Ext4FileSystem::loadinode(uint32_t ino, const char *name) {
            if (ino == 0) {
                return NULL;
            }

            // Calculate which block group contains this inode.
            uint32_t group = (ino - 1) / this->sb.inodespergroup;
            uint32_t index = (ino - 1) % this->sb.inodespergroup;

            if (group >= this->numgroups) {
                NUtil::printf("[fs/ext4fs]: Inode %u is in invalid group %u\n", ino, group);
                return NULL;
            }

            // Get the inode table location from the block group descriptor.
            struct groupdesc *gd = &this->groupdescs[group];
            uint64_t inodetable = ((uint64_t)gd->inodetablehi << 32) | gd->inodetablelo;

            // Calculate the offset of this inode within the inode table.
            uint64_t inodeoff = inodetable * this->blksize + index * this->sb.inodesize;

            // Read the inode.
            struct inode diskino;
            ssize_t res = this->blkdev->readbytes(&diskino, sizeof(struct inode), inodeoff, 0, NDev::IO_METADATA);
            if (res < 0) {
                NUtil::printf("[fs/ext4fs]: Failed to read inode %u: %d\n", ino, (int)res);
                return NULL;
            }

            // Build VFS stat structure.
            struct VFS::stat attr = {};
            attr.st_ino = ino;
            attr.st_mode = inotomode(diskino.mode);
            attr.st_nlink = diskino.linkscount;
            attr.st_uid = diskino.uid | ((uint32_t)diskino.uidhi << 16);
            attr.st_gid = diskino.gid | ((uint32_t)diskino.gidhi << 16);
            attr.st_size = ((uint64_t)diskino.sizethi << 32) | diskino.sizelo;
            attr.st_blksize = this->blksize;
            attr.st_blocks = ((uint64_t)diskino.blkshi << 32) | diskino.blockslo;
            attr.st_atime = diskino.atime;
            attr.st_mtime = diskino.mtime;
            attr.st_ctime = diskino.ctime;

            Ext4Node *node = new Ext4Node(this, name, attr, &diskino);
            return node;
        }

        int Ext4FileSystem::mount(const char *src, const char *path, VFS::INode *mntnode, uint64_t flags, const void *data) {
            (void)flags;
            (void)data;

            // Resolve the block device from the source path.
            VFS::INode *devnode = NULL;
            ssize_t res = this->vfs->resolve(src, &devnode);
            if (res < 0) {
                return res;
            }

            if (!VFS::S_ISBLK(devnode->getattr().st_mode)) {
                devnode->unref();
                return -ENOTBLK;
            }

            NDev::Device *dev = NDev::registry->get(devnode->getattr().st_rdev);
            if (!dev) {
                devnode->unref();
                return -ENODEV;
            }

            // Acquire underlying block device (should generally be the partition device).
            // XXX: Try to figure out if the device is an instance of BlockDevice.
            NDev::BlockDevice *blkdev = (NDev::BlockDevice *)dev;
            this->blkdev = blkdev;

            res = blkdev->readbytes(&this->sb, sizeof(struct superblock), 1024, 0, NDev::IO_METADATA);
            if (res < 0) {
                devnode->unref();
                return res;
            }

            // Verify magic number.
            if (this->sb.magic != 0xEF53) {
                NUtil::printf("[fs/ext4fs]: Invalid magic number: 0x%x\n", this->sb.magic);
                devnode->unref();
                return -EINVAL;
            }

            // Calculate block size.
            this->blksize = 1024 << this->sb.logblocksize;

            // Calculate number of block groups.
            uint64_t totalblocks = ((uint64_t)this->sb.blkcnthi << 32) | this->sb.blkcntlo;
            this->numgroups = (totalblocks + this->sb.blockspergroup - 1) / this->sb.blockspergroup;

            NUtil::printf("[fs/ext4fs]: Mounting %s at %s\n", src, path);
            NUtil::printf("[fs/ext4fs]: Block size: %u, Groups: %u, Inodes/group: %u\n", this->blksize, this->numgroups, this->sb.inodespergroup);

            // Read block group descriptor table.
            uint64_t bgdtblock = (this->blksize == 1024) ? 2 : 1;
            uint16_t descsize = this->sb.descsize ? this->sb.descsize : 32;
            size_t bgdtsize = this->numgroups * descsize;

            this->groupdescs = new struct groupdesc[this->numgroups];
            res = blkdev->readbytes(this->groupdescs, bgdtsize, bgdtblock * this->blksize, 0, NDev::IO_METADATA);
            if (res < 0) {
                NUtil::printf("[fs/ext4fs]: Failed to read block group descriptors\n");
                delete[] this->groupdescs;
                this->groupdescs = NULL;
                devnode->unref();
                return res;
            }

            // Disables metadata checksums if they are enabled, for fsck passing (XXX: Implement checksums properly).
            if (this->sb.featrocompat & EXT4_FEATUREROCOMPATMETADATACSUM) {
                NUtil::printf("[fs/ext4fs]: Disabling metadata checksums\n");
                this->sb.featrocompat &= ~EXT4_FEATUREROCOMPATMETADATACSUM;
                // Also clear the GDT checksum feature.
                this->sb.featrocompat &= ~EXT4_FEATUREROCOMPATGDTCSUM;
                // Clear the checksum seed feature if present.
                this->sb.featincompat &= ~EXT4_FEATUREINCOMPATCSUMSEED;
                // Write back the modified superblock.
                this->writesuperblock();

                // Clear UNINIT flags from all group descriptors (only valid with GDT_CSUM).
                uint64_t totalfreeblocks = 0;
                uint32_t totalfreeinodes = 0;

                for (uint32_t i = 0; i < this->numgroups; i++) {
                    struct groupdesc *gd = &this->groupdescs[i];
                    uint16_t oldflags = gd->flags;

                    gd->flags &= ~0x0003; // Clear INODE_UNINIT and BLOCK_UNINIT

                    // If group had UNINIT flags, recalculate free counts from actual bitmaps.
                    if (oldflags & 0x0002) { // Had BLOCK_UNINIT
                        uint64_t bitmapblk = ((uint64_t)gd->blockbitmaphi << 32) | gd->blockbitmaplo;
                        uint8_t *bitmap = new uint8_t[this->blksize];
                        if (this->readblock(bitmapblk, bitmap) >= 0) {
                            uint32_t freecount = this->countfreeblocks(i, bitmap);
                            gd->freeblkcountlo = freecount & 0xFFFF;
                            gd->freeblkcounthi = (freecount >> 16) & 0xFFFF;
                        }
                        delete[] bitmap;
                    }

                    if (oldflags & 0x0001) { // Had INODE_UNINIT
                        uint64_t bitmapblk = ((uint64_t)gd->inodebitmaphi << 32) | gd->inodebitmaplo;
                        uint8_t *bitmap = new uint8_t[this->blksize];
                        if (this->readblock(bitmapblk, bitmap) >= 0) {
                            uint32_t freecount = this->countfreeinodes(i, bitmap);
                            gd->freeinodecountlo = freecount & 0xFFFF;
                            gd->freeinodecounthi = (freecount >> 16) & 0xFFFF;
                        }
                        delete[] bitmap;
                    }

                    // Accumulate totals for superblock update.
                    uint32_t grpfreeblocks = ((uint32_t)gd->freeblkcounthi << 16) | gd->freeblkcountlo;
                    uint32_t grpfreeinodes = ((uint32_t)gd->freeinodecounthi << 16) | gd->freeinodecountlo;
                    totalfreeblocks += grpfreeblocks;
                    totalfreeinodes += grpfreeinodes;

                    this->writegroupdesc(i);
                }

                // Update superblock with recalculated totals.
                this->sb.freeblkcntlo = totalfreeblocks & 0xFFFFFFFF;
                this->sb.freeblkcnthi = (totalfreeblocks >> 32) & 0xFFFFFFFF;
                this->sb.freeinodecnt = totalfreeinodes;
                this->writesuperblock();
            }

            // XXX: Loading the root inode means we don't really have backward compatibility with ext3/ext2.
            // Probably some screwed up structs or something. Needs investigation.

            // Load root inode (inode 2).
            this->root = this->loadinode(EXT4_ROOTINO, "");
            if (!this->root) {
                NUtil::printf("[fs/ext4fs]: Failed to load root inode\n");
                delete[] this->groupdescs;
                this->groupdescs = NULL;
                devnode->unref();
                return -EIO;
            }

            // Set up mount relationship.
            if (mntnode) {
                this->root->setparent(mntnode);
            }

            this->mounted = true;

            // Print UUID.
            NUtil::printf("[fs/ext4fs]: UUID: %02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x\n",
                this->sb.uuid[0], this->sb.uuid[1], this->sb.uuid[2], this->sb.uuid[3],
                this->sb.uuid[4], this->sb.uuid[5],
                this->sb.uuid[6], this->sb.uuid[7],
                this->sb.uuid[8], this->sb.uuid[9],
                this->sb.uuid[10], this->sb.uuid[11], this->sb.uuid[12], this->sb.uuid[13], this->sb.uuid[14], this->sb.uuid[15]
            );

            devnode->unref();
            return 0;
        }

        static struct VFS::fsreginfo ext4fsinfo = {
            .name = "ext4"
        };

        REGFS(ext4, Ext4FileSystem::instance, &ext4fsinfo);
    }
}