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

        // Convert EXT4 file type to VFS mode.
        static uint32_t dttomode(uint8_t filetype) {
            switch (filetype) {
                case FT_REG_FILE: return VFS::S_IFREG;
                case FT_DIR: return VFS::S_IFDIR;
                case FT_CHRDEV: return VFS::S_IFCHR;
                case FT_BLKDEV: return VFS::S_IFBLK;
                case FT_FIFO: return VFS::S_IFIFO;
                case FT_SOCK: return VFS::S_IFSOCK;
                case FT_SYMLINK: return VFS::S_IFLNK;
                default: return 0;
            }
        }

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

        Ext4Node::Ext4Node(Ext4FileSystem *fs, const char *name, struct VFS::stat attr, struct inode *diskino) : VFS::INode((VFS::IFileSystem *)fs, name, attr) {
            this->ext4fs = fs;
            if (diskino) {
                NLib::memcpy(&this->diskino, diskino, sizeof(struct inode));
            }
        }

        // Read an indirect block pointer from disk.
        uint64_t Ext4Node::getindirectblock(uint64_t logicalblk) {
            uint32_t ptrsperblk = this->ext4fs->blksize / sizeof(uint32_t);
            uint64_t singlemax = EXT4_NDIRBLOCKS + ptrsperblk;
            uint64_t doublemax = singlemax + (uint64_t)ptrsperblk * ptrsperblk;
            uint64_t triplemax = doublemax + (uint64_t)ptrsperblk * ptrsperblk * ptrsperblk;

            uint8_t *blkbuf = new uint8_t[this->ext4fs->blksize];
            uint64_t physblk = 0;

            if (logicalblk < singlemax) {
                // Single indirect block.
                uint64_t indblk = this->diskino.block[EXT4_INDBLOCK];
                if (indblk == 0) {
                    delete[] blkbuf;
                    return 0;
                }

                if (this->ext4fs->readblock(indblk, blkbuf) < 0) {
                    delete[] blkbuf;
                    return 0;
                }

                uint32_t *ptrs = (uint32_t *)blkbuf;
                uint32_t idx = logicalblk - EXT4_NDIRBLOCKS;
                physblk = ptrs[idx];

            } else if (logicalblk < doublemax) {
                // Double indirect block.
                uint64_t dindblk = this->diskino.block[EXT4_DINDBLOCK];
                if (dindblk == 0) {
                    delete[] blkbuf;
                    return 0;
                }

                if (this->ext4fs->readblock(dindblk, blkbuf) < 0) {
                    delete[] blkbuf;
                    return 0;
                }

                uint64_t offset = logicalblk - singlemax;
                uint32_t idx1 = offset / ptrsperblk;
                uint32_t idx2 = offset % ptrsperblk;

                uint32_t *ptrs = (uint32_t *)blkbuf;
                uint64_t indblk = ptrs[idx1];
                if (indblk == 0) {
                    delete[] blkbuf;
                    return 0;
                }

                if (this->ext4fs->readblock(indblk, blkbuf) < 0) {
                    delete[] blkbuf;
                    return 0;
                }

                ptrs = (uint32_t *)blkbuf;
                physblk = ptrs[idx2];

            } else if (logicalblk < triplemax) {
                // Triple indirect block.
                uint64_t tindblk = this->diskino.block[EXT4_TINDBLOCK];
                if (tindblk == 0) {
                    delete[] blkbuf;
                    return 0;
                }

                if (this->ext4fs->readblock(tindblk, blkbuf) < 0) {
                    delete[] blkbuf;
                    return 0;
                }

                uint64_t offset = logicalblk - doublemax;
                uint64_t blocksper2 = (uint64_t)ptrsperblk * ptrsperblk;
                uint32_t idx1 = offset / blocksper2;
                uint64_t rem = offset % blocksper2;
                uint32_t idx2 = rem / ptrsperblk;
                uint32_t idx3 = rem % ptrsperblk;

                uint32_t *ptrs = (uint32_t *)blkbuf;
                uint64_t dindblk = ptrs[idx1];
                if (dindblk == 0) {
                    delete[] blkbuf;
                    return 0;
                }

                if (this->ext4fs->readblock(dindblk, blkbuf) < 0) {
                    delete[] blkbuf;
                    return 0;
                }

                ptrs = (uint32_t *)blkbuf;
                uint64_t indblk = ptrs[idx2];
                if (indblk == 0) {
                    delete[] blkbuf;
                    return 0;
                }

                if (this->ext4fs->readblock(indblk, blkbuf) < 0) {
                    delete[] blkbuf;
                    return 0;
                }

                ptrs = (uint32_t *)blkbuf;
                physblk = ptrs[idx3];
            }

            delete[] blkbuf;
            return physblk;
        }

        ssize_t Ext4Node::read(void *buf, size_t count, off_t offset, int fdflags) {
            (void)fdflags;

            // For regular files, use the page cache.
            if (VFS::S_ISREG(this->attr.st_mode)) {
                return this->readcached(buf, count, offset);
            }

            NLib::ScopeSpinlock guard(&this->metalock);

            // Get file size (64-bit).
            uint64_t filesize = ((uint64_t)this->diskino.sizethi << 32) | this->diskino.sizelo;

            if ((uint64_t)offset >= filesize) {
                return 0;
            }

            if (offset + count > filesize) {
                count = filesize - offset;
            }

            uint32_t blksize = this->ext4fs->blksize;
            uint8_t *blkbuf = new uint8_t[blksize];
            size_t bytesread = 0;

            while (bytesread < count) { // Read block-wise.
                uint64_t logicalblk = (offset + bytesread) / blksize;
                size_t blkoff = (offset + bytesread) % blksize;
                size_t toread = blksize - blkoff;
                if (toread > count - bytesread) {
                    toread = count - bytesread;
                }

                // Release lock during potentially blocking I/O operations.
                this->metalock.release();
                uint64_t physblk = this->getphysblock(logicalblk);
                if (physblk == 0) { // Unallocated block (hole).
                    this->metalock.acquire();
                    // Fill holes with zeroes.
                    NLib::memset((uint8_t *)buf + bytesread, 0, toread);
                } else { // Actual data!!! Read it and shove it into the user buffer.
                    ssize_t res = this->ext4fs->readblock(physblk, blkbuf);
                    this->metalock.acquire();
                    if (res < 0) {
                        delete[] blkbuf;
                        return res;
                    }
                    NLib::memcpy((uint8_t *)buf + bytesread, blkbuf + blkoff, toread);
                }

                bytesread += toread;
            }

            delete[] blkbuf;
            return bytesread;
        }

        ssize_t Ext4Node::readdir(void *buf, size_t count, off_t offset) {
            NLib::ScopeSpinlock guard(&this->metalock);

            if (!VFS::S_ISDIR(this->attr.st_mode)) {
                return -ENOTDIR;
            }

            // Get directory size.
            uint64_t dirsize = ((uint64_t)this->diskino.sizethi << 32) | this->diskino.sizelo;

            size_t byteswritten = 0;
            size_t curroffset = 0;
            size_t reclen = sizeof(struct VFS::dirent);

            // Add "." entry.
            if (curroffset >= (size_t)offset) {
                if (byteswritten + reclen > count) {
                    return byteswritten;
                }
                struct VFS::dirent *dentry = (struct VFS::dirent *)((uint8_t *)buf + byteswritten);
                dentry->d_ino = this->attr.st_ino;
                dentry->d_off = byteswritten + reclen;
                dentry->d_reclen = (uint16_t)reclen;
                dentry->d_type = VFS::S_IFDIR >> 12;
                NLib::memset(dentry->d_name, 0, sizeof(dentry->d_name));
                dentry->d_name[0] = '.';
                byteswritten += reclen;
            }
            curroffset += reclen;

            // Add ".." entry.
            if (curroffset >= (size_t)offset) {
                if (byteswritten + reclen > count) {
                    return byteswritten;
                }
                struct VFS::dirent *dentry = (struct VFS::dirent *)((uint8_t *)buf + byteswritten);

                // Determine parent inode without holding lock to avoid deadlock.
                // Release lock temporarily to call getroot() and getattr() safely.
                uint64_t parent_ino;
                VFS::INode *root = this->fs->getroot();
                if (root == this) {
                    parent_ino = this->attr.st_ino;
                    root->unref();
                } else if (this->parent) {
                    this->metalock.release();
                    parent_ino = this->parent->getattr().st_ino;
                    this->metalock.acquire();
                    root->unref();
                } else {
                    parent_ino = this->attr.st_ino;
                    root->unref();
                }

                dentry->d_ino = parent_ino;
                dentry->d_off = byteswritten + reclen;
                dentry->d_reclen = (uint16_t)reclen;
                dentry->d_type = VFS::S_IFDIR >> 12;
                NLib::memset(dentry->d_name, 0, sizeof(dentry->d_name));
                dentry->d_name[0] = '.';
                dentry->d_name[1] = '.';
                byteswritten += reclen;
            }
            curroffset += reclen;

            // Read directory blocks and parse entries.
            uint32_t blksize = this->ext4fs->blksize;
            uint8_t *blkbuf = new uint8_t[blksize];
            uint64_t diroff = 0;

            while (diroff < dirsize) { // While we have directory entries.
                uint64_t logicalblk = diroff / blksize;

                // Release lock during potentially blocking I/O operations.
                this->metalock.release();
                uint64_t physblk = this->getphysblock(logicalblk);

                if (physblk == 0) {
                    this->metalock.acquire();
                    diroff += blksize;
                    continue;
                }

                ssize_t res = this->ext4fs->readblock(physblk, blkbuf);
                this->metalock.acquire();

                if (res < 0) {
                    delete[] blkbuf;
                    return res;
                }

                // Parse directory entries in this block.
                size_t blockoff = 0;
                while (blockoff < blksize && diroff + blockoff < dirsize) {
                    struct direntry2 *de = (struct direntry2 *)(blkbuf + blockoff);

                    if (de->reclen == 0) {
                        break; // Invalid entry.
                    }

                    // Stop if we hit the directory tail (checksum entry).
                    if (de->filetype == EXT4_FTDIRCSUM) {
                        break;
                    }

                    // Skip empty entries.
                    if (de->inode != 0 && de->namelen > 0) {
                        bool isdot = (de->namelen == 1 && de->name[0] == '.');
                        bool isdotdot = (de->namelen == 2 && de->name[0] == '.' && de->name[1] == '.');

                        if (!isdot && !isdotdot) { // Only really add entries that aren't the directory link ones.
                            if (curroffset >= (size_t)offset) {
                                if (byteswritten + reclen > count) {
                                    delete[] blkbuf;
                                    return byteswritten;
                                }

                                struct VFS::dirent *vfsde = (struct VFS::dirent *)((uint8_t *)buf + byteswritten);
                                vfsde->d_ino = de->inode;
                                vfsde->d_off = byteswritten + reclen;
                                vfsde->d_reclen = (uint16_t)reclen;
                                vfsde->d_type = dttomode(de->filetype) >> 12;
                                NLib::memset(vfsde->d_name, 0, sizeof(vfsde->d_name));
                                size_t namelen = de->namelen;
                                if (namelen > sizeof(vfsde->d_name) - 1) {
                                    namelen = sizeof(vfsde->d_name) - 1;
                                }
                                NLib::memcpy(vfsde->d_name, de->name, namelen);

                                byteswritten += reclen;
                            }
                            curroffset += reclen;
                        }
                    }

                    blockoff += de->reclen;
                }

                diroff += blksize;
            }

            delete[] blkbuf;
            return byteswritten;
        }

        ssize_t Ext4Node::readlink(char *buf, size_t bufsiz) {
            NLib::ScopeSpinlock guard(&this->metalock);

            if (!VFS::S_ISLNK(this->attr.st_mode)) {
                return -EINVAL;
            }

            uint64_t linksize = ((uint64_t)this->diskino.sizethi << 32) | this->diskino.sizelo;

            if (linksize < sizeof(this->diskino.block)) {
                size_t tocopy = linksize;
                if (tocopy > bufsiz) {
                    tocopy = bufsiz;
                }
                NLib::memcpy(buf, this->diskino.block, tocopy); // We can read shorter symlinks right out of the block array.
                return tocopy;
            }

            // Otherwise, we'd need to read the file itself.
            size_t tocopy = linksize;
            if (tocopy > bufsiz) {
                tocopy = bufsiz;
            }

            this->metalock.release();
            ssize_t result = this->read(buf, tocopy, 0, 0);
            this->metalock.acquire();
            return result;
        }

        VFS::INode *Ext4Node::lookup(const char *name) {
            NLib::ScopeSpinlock guard(&this->metalock);

            if (!VFS::S_ISDIR(this->attr.st_mode)) {
                return NULL;
            }

            // Check if child is already cached.
            Ext4Node **cached = this->children.find(name);
            if (cached && *cached) {
                (*cached)->ref(); // Increment refcount before returning (lookup() contract).
                return *cached;
            }

            // Get directory size.
            uint64_t dirsize = ((uint64_t)this->diskino.sizethi << 32) | this->diskino.sizelo;

            uint32_t blksize = this->ext4fs->blksize;
            uint8_t *blkbuf = new uint8_t[blksize];
            uint64_t diroff = 0;
            size_t namelen = NLib::strlen(name);

            while (diroff < dirsize) { // Iterate over directory entries.
                uint64_t logicalblk = diroff / blksize;

                // Release lock during potentially blocking I/O operations.
                this->metalock.release();
                uint64_t physblk = this->getphysblock(logicalblk);

                if (physblk == 0) {
                    this->metalock.acquire();
                    diroff += blksize;
                    continue;
                }

                ssize_t res = this->ext4fs->readblock(physblk, blkbuf);
                this->metalock.acquire();

                if (res < 0) {
                    delete[] blkbuf;
                    return NULL;
                }

                // Parse directory entries in this block.
                size_t blockoff = 0;
                while (blockoff < blksize && diroff + blockoff < dirsize) {
                    struct direntry2 *de = (struct direntry2 *)(blkbuf + blockoff);

                    if (de->reclen == 0) {
                        break;
                    }

                    // Stop if we hit the directory tail (checksum entry).
                    if (de->filetype == EXT4_FTDIRCSUM) {
                        break;
                    }

                    if (de->inode != 0 && de->namelen == namelen) {
                        if (NLib::strncmp(name, de->name, namelen) == 0) {
                            uint32_t childino = de->inode;
                            delete[] blkbuf;

                            // Need to release lock before loading inode.
                            this->metalock.release();
                            // Create a VFS node on demand.
                            Ext4Node *child = this->ext4fs->loadinode(childino, name);
                            this->metalock.acquire();

                            if (child) {
                                child->setparent(this);
                                this->_addchild(child); // Link into parent for cleanup on umount.
                                child->ref(); // Increment refcount before returning (lookup() contract).
                            }
                            return child;
                        }
                    }

                    blockoff += de->reclen;
                }

                diroff += blksize;
            }

            delete[] blkbuf;
            return NULL;
        }

        bool Ext4Node::empty(void) {
            if (!VFS::S_ISDIR(this->attr.st_mode)) {
                return true;
            }

            // Get directory size.
            uint64_t dirsize = ((uint64_t)this->diskino.sizethi << 32) | this->diskino.sizelo;

            uint32_t blksize = this->ext4fs->blksize;
            uint8_t *blkbuf = new uint8_t[blksize];
            uint64_t diroff = 0;

            while (diroff < dirsize) {
                uint64_t logicalblk = diroff / blksize;
                uint64_t physblk = this->getphysblock(logicalblk);

                if (physblk == 0) {
                    diroff += blksize;
                    continue;
                }

                ssize_t res = this->ext4fs->readblock(physblk, blkbuf);
                if (res < 0) {
                    delete[] blkbuf;
                    return true;
                }

                size_t blockoff = 0;
                while (blockoff < blksize && diroff + blockoff < dirsize) {
                    struct direntry2 *de = (struct direntry2 *)(blkbuf + blockoff);

                    if (de->reclen == 0) {
                        break;
                    }

                    // Stop if we hit the directory tail (checksum entry).
                    if (de->filetype == EXT4_FTDIRCSUM) {
                        break;
                    }

                    if (de->inode != 0 && de->namelen > 0) {
                        bool isdot = (de->namelen == 1 && de->name[0] == '.');
                        bool isdotdot = (de->namelen == 2 && de->name[0] == '.' && de->name[1] == '.');

                        if (!isdot && !isdotdot) {
                            delete[] blkbuf;
                            return false; // Found a real entry.
                        }
                    }

                    blockoff += de->reclen;
                }

                diroff += blksize;
            }

            delete[] blkbuf;
            return true;
        }

        VFS::INode *Ext4Node::resolvesymlink(void) {
            if (!VFS::S_ISLNK(this->attr.st_mode)) {
                return NULL;
            }

            uint64_t linksize = ((uint64_t)this->diskino.sizethi << 32) | this->diskino.sizelo;
            if (linksize == 0 || linksize > 4096) {
                return NULL;
            }

            char *linkbuf = new char[linksize + 1];
            ssize_t res = this->readlink(linkbuf, linksize);
            if (res < 0) {
                delete[] linkbuf;
                return NULL;
            }
            linkbuf[res] = '\0';

            VFS::VFS *vfs = this->fs->getvfs();
            VFS::INode *node = NULL;
            // Resolve the link target.
            res = vfs->resolve(linkbuf, &node, this->getparent(), false);
            delete[] linkbuf;

            if (res < 0) {
                return NULL;
            }
            return node;
        }

        ssize_t Ext4Node::setsymlinkdata(const char *target, size_t len) {
            if (!VFS::S_ISLNK(this->attr.st_mode)) {
                return -EINVAL;
            }

            if (len < sizeof(this->diskino.block)) { // Short symlinks can be stored inline.
                NLib::ScopeSpinlock guard(&this->metalock);

                // Clear the extent flag since we're using inline storage.
                this->diskino.flags &= ~EXT4_EXTENTSFL;

                // Clear the block array and copy target.
                NLib::memset(this->diskino.block, 0, sizeof(this->diskino.block));
                NLib::memcpy(this->diskino.block, (void *)target, len);

                // Set size.
                this->diskino.sizelo = len;
                this->diskino.sizethi = 0;
                this->attr.st_size = len;
                this->attr.st_blocks = 0;

                // Write the inode back to disk.
                this->touchtime(true, true, false);
                int res = this->writeback();
                if (res < 0) {
                    return res;
                }
                return len;
            }

            // For longer symlinks, use the regular write path (extent-based).
            return this->write(target, len, 0, 0);
        }

        int Ext4Node::readpage(NMem::CachePage *page) {
            if (!VFS::S_ISREG(this->attr.st_mode)) {
                return -EINVAL; // Only regular files use page cache.
            }

            off_t offset = page->offset;

            uint64_t filesize = __atomic_load_n(&this->attr.st_size, __ATOMIC_ACQUIRE);

            // Zero the page first.
            NLib::memset(page->data(), 0, NArch::PAGESIZE);

            // If offset is beyond file size, return empty page.
            if ((uint64_t)offset >= filesize) {
                page->setflag(NMem::PAGE_UPTODATE);
                return 0;
            }

            uint32_t blksize = this->ext4fs->blksize;
            size_t toread = NArch::PAGESIZE;
            if ((uint64_t)offset + toread > filesize) {
                toread = filesize - offset;
            }

            uint8_t *dest = (uint8_t *)page->data();
            size_t bytesread = 0;

            while (bytesread < toread) {
                uint64_t logicalblk = (offset + bytesread) / blksize;
                size_t blkoff = (offset + bytesread) % blksize;
                size_t chunk = blksize - blkoff;
                if (chunk > toread - bytesread) {
                    chunk = toread - bytesread;
                }

                uint64_t physblk = this->getphysblock(logicalblk);
                if (physblk == 0) {
                    bytesread += chunk;
                    dest += chunk;
                    continue;
                }

                // Read via block device.
                off_t diskoffset = physblk * blksize + blkoff;
                ssize_t res = this->ext4fs->blkdev->readbytes(dest, chunk, diskoffset, 0);
                if (res < 0) {
                    return (int)res;
                }

                bytesread += chunk;
                dest += chunk;
            }

            page->setflag(NMem::PAGE_UPTODATE);
            return 0;
        }

        int Ext4Node::writepage(NMem::CachePage *page) {
            if (!VFS::S_ISREG(this->attr.st_mode)) {
                return -EINVAL; // Only regular files use page cache.
            }

            page->setflag(NMem::PAGE_WRITEBACK);

            off_t offset = page->offset;

            uint64_t filesize = __atomic_load_n(&this->attr.st_size, __ATOMIC_ACQUIRE);

            // Determine how much of the page is valid file data.
            size_t towrite = NArch::PAGESIZE;
            if ((uint64_t)offset + towrite > filesize) {
                towrite = filesize > (uint64_t)offset ? filesize - offset : 0;
            }

            if (towrite == 0) {
                page->clearflag(NMem::PAGE_WRITEBACK);
                page->markclean();
                return 0;
            }

            uint32_t blksize = this->ext4fs->blksize;
            const uint8_t *src = (const uint8_t *)page->data();
            size_t byteswritten = 0;

            while (byteswritten < towrite) {
                uint64_t logicalblk = (offset + byteswritten) / blksize;
                size_t blkoff = (offset + byteswritten) % blksize;
                size_t chunk = blksize - blkoff;
                if (chunk > towrite - byteswritten) {
                    chunk = towrite - byteswritten;
                }

                uint64_t physblk = this->getphysblock(logicalblk);
                if (physblk == 0) {
                    // Need to allocate a block for this write.
                    physblk = this->allocextent(logicalblk, 1);
                    if (physblk == 0) {
                        page->clearflag(NMem::PAGE_WRITEBACK);
                        page->errorcount++;
                        return -ENOSPC;
                    }
                }

                // Write via block device.
                off_t diskoffset = physblk * blksize + blkoff;
                ssize_t res = this->ext4fs->blkdev->writebytes(src + byteswritten, chunk, diskoffset, 0);
                if (res < 0) {
                    page->clearflag(NMem::PAGE_WRITEBACK);
                    page->errorcount++;
                    return (int)res;
                }

                byteswritten += chunk;
            }

            page->clearflag(NMem::PAGE_WRITEBACK);
            page->markclean();
            page->errorcount = 0;
            return 0;
        }

        int Ext4Node::sync(enum VFS::INode::syncmode mode) {
            // Sync dirty pages to disk first.
            int err = this->synccache();
            if (err != 0) {
                return -EIO; // synccache returns error count, convert to error code.
            }

            // For full sync, also write back inode metadata.
            if (mode == VFS::INode::SYNC_FULL) {
                NLib::ScopeSpinlock guard(&this->metalock);
                int res = this->writeback();
                if (res < 0) {
                    return res;
                }
            }

            return 0;
        }

        // Update inode timestamps. Pass true for timestamps to update.
        void Ext4Node::touchtime(bool mtime, bool ctime, bool atime) {
            NSys::Clock::Clock *realtime = NSys::Clock::getclock(NSys::Clock::CLOCK_REALTIME);
            struct NSys::Clock::timespec ts;
            realtime->gettime(&ts);

            if (mtime) {
                this->diskino.mtime = ts.tv_sec;
                this->attr.st_mtime = ts.tv_sec;
            }
            if (ctime) {
                this->diskino.ctime = ts.tv_sec;
                this->attr.st_ctime = ts.tv_sec;
            }
            if (atime) {
                this->diskino.atime = ts.tv_sec;
                this->attr.st_atime = ts.tv_sec;
            }
        }

        // Write the inode back to disk.
        int Ext4Node::writeback(void) {
            // Copy inode data under lock protection.
            struct inode inodecopy;
            NLib::memcpy(&inodecopy, &this->diskino, sizeof(struct inode));
            uint32_t ino = this->attr.st_ino;

            // Release lock during blocking I/O.
            this->metalock.release();

            int result = this->ext4fs->writeinode(ino, &inodecopy);

            // Re-acquire lock before returning.
            this->metalock.acquire();

            return result;
        }

        int Ext4Node::commitmetadata(bool mtime, bool ctime, bool atime) {
            NLib::ScopeSpinlock guard(&this->metalock);
            this->touchtime(mtime, ctime, atime);
            return this->writeback();
        }

        ssize_t Ext4Node::write(const void *buf, size_t count, off_t offset, int fdflags) {
            (void)fdflags;

            if (VFS::S_ISDIR(this->attr.st_mode)) {
                return -EISDIR;
            }

            // For regular files, use the page cache.
            if (VFS::S_ISREG(this->attr.st_mode)) {
                // Get current file size.
                uint64_t oldsize;
                uint32_t blksize;
                {
                    NLib::ScopeSpinlock guard(&this->metalock);
                    oldsize = ((uint64_t)this->diskino.sizethi << 32) | this->diskino.sizelo;
                    blksize = this->ext4fs->blksize;
                }

                // Calculate new size if extending.
                uint64_t newsize = offset + count;
                if (newsize > oldsize) {
                    // Pre-allocate blocks for the new region.
                    uint64_t startblk = oldsize / blksize;
                    uint64_t endblk = (newsize + blksize - 1) / blksize;

                    for (uint64_t blk = startblk; blk < endblk; blk++) {
                        uint64_t physblk = this->getphysblock(blk);
                        if (physblk == 0) {
                            physblk = this->allocextent(blk, 1);
                            if (physblk == 0) {
                                return -ENOSPC;
                            }
                        }
                    }
                }

                // Write through page cache.
                uint64_t writtenend = offset + count;
                if (writtenend > oldsize) {
                    __atomic_store_n(&this->attr.st_size, writtenend, __ATOMIC_RELEASE);

                    NLib::ScopeSpinlock guard(&this->metalock);
                    this->diskino.sizelo = writtenend & 0xFFFFFFFF;
                    this->diskino.sizethi = (writtenend >> 32) & 0xFFFFFFFF;

                    // Update block count.
                    uint64_t newblocks = (writtenend + blksize - 1) / blksize;
                    newblocks = newblocks * (blksize / 512); // Convert to 512-byte sectors.
                    this->diskino.blockslo = newblocks & 0xFFFFFFFF;
                    this->diskino.blkshi = (newblocks >> 32) & 0xFFFF;
                    this->attr.st_blocks = newblocks;
                }

                ssize_t result = this->writecached(buf, count, offset);

                if (result > 0) {
                    NLib::ScopeSpinlock guard(&this->metalock);

                    // If we got a short write when extending, adjust size back down.
                    uint64_t actualend = offset + result;
                    if (writtenend > oldsize && actualend < writtenend) {
                        // Partial write - adjust size to actual written end.
                        __atomic_store_n(&this->attr.st_size, actualend > oldsize ? actualend : oldsize, __ATOMIC_RELEASE);
                        this->diskino.sizelo = (actualend > oldsize ? actualend : oldsize) & 0xFFFFFFFF;
                        this->diskino.sizethi = ((actualend > oldsize ? actualend : oldsize) >> 32) & 0xFFFFFFFF;
                    }

                    // Update timestamps and writeback inode metadata.
                    this->touchtime(true, true, false);
                    this->writeback();
                } else if (result < 0 && writtenend > oldsize) {
                    // Write failed completely - restore old size.
                    __atomic_store_n(&this->attr.st_size, oldsize, __ATOMIC_RELEASE);
                    NLib::ScopeSpinlock guard(&this->metalock);
                    this->diskino.sizelo = oldsize & 0xFFFFFFFF;
                    this->diskino.sizethi = (oldsize >> 32) & 0xFFFFFFFF;
                }

                return result;
            }

            // Fallback for non-regular files (shouldn't happen normally).
            NLib::ScopeSpinlock guard(&this->metalock);
            uint32_t blksize = this->ext4fs->blksize;
            uint8_t *blkbuf = new uint8_t[blksize];
            size_t byteswritten = 0;

            while (byteswritten < count) {
                uint64_t logicalblk = (offset + byteswritten) / blksize;
                size_t blkoff = (offset + byteswritten) % blksize;
                size_t towrite = blksize - blkoff;
                if (towrite > count - byteswritten) {
                    towrite = count - byteswritten;
                }

                // Release lock during potentially blocking I/O operations.
                this->metalock.release();
                uint64_t physblk = this->getphysblock(logicalblk);

                // If the block doesn't exist, allocate it.
                if (physblk == 0) {
                    physblk = this->allocextent(logicalblk, 1);
                    if (physblk == 0) {
                        this->metalock.acquire();
                        delete[] blkbuf;
                        if (byteswritten > 0) {
                            // Update file size if we wrote anything.
                            uint64_t newsize = offset + byteswritten;
                            uint64_t oldsize = ((uint64_t)this->diskino.sizethi << 32) | this->diskino.sizelo;
                            if (newsize > oldsize) {
                                this->diskino.sizelo = newsize & 0xFFFFFFFF;
                                this->diskino.sizethi = (newsize >> 32) & 0xFFFFFFFF;
                                __atomic_store_n(&this->attr.st_size, newsize, memory_order_release);
                                this->touchtime(true, true, false); // Update mtime/ctime on write.
                                this->writeback(); // Writeback information.
                            }
                            return byteswritten;
                        }
                        return -ENOSPC;
                    }
                }

                // If we're doing a partial block write, read the existing block first.
                if (blkoff != 0 || towrite != blksize) {
                    ssize_t res = this->ext4fs->readblock(physblk, blkbuf);
                    if (res < 0) {
                        this->metalock.acquire();
                        delete[] blkbuf;
                        return res;
                    }
                }

                // Copy data into the block buffer.
                NLib::memcpy(blkbuf + blkoff, (void *)((const uint8_t *)buf + byteswritten), towrite);

                // Write the block back.
                ssize_t res = this->ext4fs->writeblock(physblk, blkbuf);
                this->metalock.acquire();

                if (res < 0) {
                    delete[] blkbuf;
                    return res;
                }

                byteswritten += towrite;
            }

            delete[] blkbuf;

            // Update file size if necessary.
            uint64_t newsize = offset + byteswritten;
            uint64_t oldsize = ((uint64_t)this->diskino.sizethi << 32) | this->diskino.sizelo;
            if (newsize > oldsize) {
                this->diskino.sizelo = newsize & 0xFFFFFFFF;
                this->diskino.sizethi = (newsize >> 32) & 0xFFFFFFFF;
                __atomic_store_n(&this->attr.st_size, newsize, memory_order_release);

                // Update block count.
                uint64_t newblocks = (newsize + blksize - 1) / blksize;
                newblocks = newblocks * (blksize / 512); // Convert to 512-byte sectors.
                this->diskino.blockslo = newblocks & 0xFFFFFFFF;
                this->diskino.blkshi = (newblocks >> 32) & 0xFFFF;
                this->attr.st_blocks = newblocks;
            }

            // Update timestamps and write inode back to disk.
            this->touchtime(true, true, false); // Update mtime/ctime on write.
            this->writeback();

            return byteswritten;
        }

        int Ext4Node::truncate(off_t length) {
            NLib::ScopeSpinlock guard(&this->metalock);

            if (length < 0) {
                return -EINVAL;
            }

            if (VFS::S_ISDIR(this->attr.st_mode)) {
                return -EISDIR;
            }

            uint64_t oldsize = ((uint64_t)this->diskino.sizethi << 32) | this->diskino.sizelo;
            uint64_t newsize = (uint64_t)length;

            if (newsize == oldsize) {
                return 0; // Nothing to do.
            }

            uint32_t blksize = this->ext4fs->blksize;

            if (newsize < oldsize) { // Only bother to shrink blocks, because growing is handled on write().
                // Reducing size.
                uint64_t newblocks = (newsize + blksize - 1) / blksize;

                if (this->diskino.flags & EXT4_EXTENTSFL) {
                    struct extenthdr *hdr = (struct extenthdr *)this->diskino.block;
                    if (hdr->magic == EXT4_EXTMAGIC && hdr->depth == 0) {
                        struct extent *extents = (struct extent *)((uint8_t *)this->diskino.block + sizeof(struct extenthdr));

                        // Walk extents and free blocks beyond newblocks.
                        for (uint16_t i = 0; i < hdr->entries; i++) {
                            uint32_t extstart = extents[i].fileblk;
                            uint16_t extlen = extents[i].len & 0x7FFF;
                            uint64_t physblk = ((uint64_t)extents[i].starthi << 32) | extents[i].startlo;

                            if (extstart >= newblocks) {
                                for (uint16_t j = 0; j < extlen; j++) {
                                    this->ext4fs->freeblock(physblk + j);
                                }

                                // Remove this extent by shifting remaining extents.
                                for (uint16_t j = i; j < hdr->entries - 1; j++) {
                                    extents[j] = extents[j + 1];
                                }
                                hdr->entries--;
                                i--;
                            } else if (extstart + extlen > newblocks) {
                                // Truncate partial extent.
                                uint16_t keeplen = newblocks - extstart;
                                for (uint16_t j = keeplen; j < extlen; j++) {
                                    this->ext4fs->freeblock(physblk + j);
                                }
                                extents[i].len = (extents[i].len & 0x8000) | (keeplen & 0x7FFF);
                            }
                        }
                    }
                }
            }

            // Update inode size.
            this->diskino.sizelo = newsize & 0xFFFFFFFF;
            this->diskino.sizethi = (newsize >> 32) & 0xFFFFFFFF;
            __atomic_store_n(&this->attr.st_size, newsize, memory_order_release);

            // Update block count.
            uint64_t blocks = (newsize + blksize - 1) / blksize;
            blocks = blocks * (blksize / 512); // Convert to 512-byte sectors.
            this->diskino.blockslo = blocks & 0xFFFFFFFF;
            this->diskino.blkshi = (blocks >> 32) & 0xFFFF;
            this->attr.st_blocks = blocks;

            // Update timestamps and write inode back to disk.
            this->touchtime(true, true, false); // Update mtime/ctime on truncate.
            this->writeback();

            return 0;
        }

        // Convert VFS file type to ext4 directory entry file type.
        static uint8_t modetodt(uint32_t mode) {
            switch (mode & VFS::S_IFMT) {
                case VFS::S_IFREG: return FT_REG_FILE;
                case VFS::S_IFDIR: return FT_DIR;
                case VFS::S_IFCHR: return FT_CHRDEV;
                case VFS::S_IFBLK: return FT_BLKDEV;
                case VFS::S_IFIFO: return FT_FIFO;
                case VFS::S_IFSOCK: return FT_SOCK;
                case VFS::S_IFLNK: return FT_SYMLINK;
                default: return FT_UNKNOWN;
            }
        }

        bool Ext4Node::add(VFS::INode *node) {
            NLib::ScopeSpinlock guard(&this->metalock);

            if (!VFS::S_ISDIR(this->attr.st_mode)) {
                return false;
            }

            Ext4Node *child = (Ext4Node *)node;
            const char *name = child->getname();
            size_t namelen = NLib::strlen(name);

            if (namelen > 255) { // Maximum ext4 direntry name.
                return false;
            }

            // Calculate required entry size (must be 4-byte aligned).
            size_t reqsize = sizeof(struct direntry2) - 255 + namelen;
            reqsize = (reqsize + 3) & ~3; // Align to 4 bytes.

            uint64_t dirsize = ((uint64_t)this->diskino.sizethi << 32) | this->diskino.sizelo;
            uint32_t blksize = this->ext4fs->blksize;
            uint8_t *blkbuf = new uint8_t[blksize];

            // Search existing blocks for space.
            uint64_t diroff = 0;
            while (diroff < dirsize) {
                uint64_t logicalblk = diroff / blksize;

                this->metalock.release();
                uint64_t physblk = this->getphysblock(logicalblk);

                if (physblk == 0) {
                    this->metalock.acquire();
                    diroff += blksize;
                    continue;
                }

                ssize_t res = this->ext4fs->readblock(physblk, blkbuf);
                this->metalock.acquire();

                if (res < 0) {
                    delete[] blkbuf;
                    return false;
                }

                // Search for space in this block.
                size_t blockoff = 0;
                while (blockoff < blksize) {
                    struct direntry2 *de = (struct direntry2 *)(blkbuf + blockoff);

                    if (de->reclen == 0) {
                        break;
                    }

                    // Stop if we hit the directory tail (checksum entry).
                    if (de->filetype == EXT4_FTDIRCSUM) {
                        break;
                    }

                    // Calculate actual size needed by this entry.
                    size_t actualsize = sizeof(struct direntry2) - 255 + de->namelen;
                    actualsize = (actualsize + 3) & ~3;

                    // Check if there's enough slack space after this entry.
                    if (de->reclen >= actualsize + reqsize) {
                        // Split the entry.
                        uint16_t oldreclen = de->reclen;
                        de->reclen = actualsize;

                        // Write new entry into directory entry block after the existing one.
                        struct direntry2 *newde = (struct direntry2 *)(blkbuf + blockoff + actualsize);
                        newde->inode = child->attr.st_ino;
                        newde->reclen = oldreclen - actualsize;
                        newde->namelen = namelen;
                        newde->filetype = modetodt(child->attr.st_mode);
                        NLib::memcpy(newde->name, (void *)name, namelen);

                        // Set directory block checksum before writing.
                        this->ext4fs->setdirblkcsum(this->attr.st_ino, this->diskino.generation, blkbuf);

                        // Write block back.
                        this->metalock.release();
                        res = this->ext4fs->writeblock(physblk, blkbuf);
                        this->metalock.acquire();

                        delete[] blkbuf;

                        if (res < 0) {
                            return false;
                        }

                        // Update parent link count for directories.
                        if (VFS::S_ISDIR(child->attr.st_mode)) {
                            this->diskino.linkscount++;
                            this->attr.st_nlink++; // References from parent directory.
                            this->touchtime(true, true, false); // Update mtime/ctime on dir modification.
                            this->writeback();
                        }

                        child->setparent(this);
                        this->_addchild(child); // Link into parent for cleanup on umount.
                        return true;
                    }

                    blockoff += de->reclen;
                }

                diroff += blksize;
            }

            this->metalock.release();
            uint64_t newlogblk = dirsize / blksize;
            // Allocate new extent if we have NO space for directory entries.
            uint64_t newphysblk = this->allocextent(newlogblk, 1);
            this->metalock.acquire();

            if (newphysblk == 0) {
                delete[] blkbuf;
                return false;
            }

            // Initialize the new block with our entry.
            NLib::memset(blkbuf, 0, blksize);
            struct direntry2 *newde = (struct direntry2 *)blkbuf;
            newde->inode = child->attr.st_ino;
            // Entry spans entire block minus tail space for checksum (shrinks when more entries are added).
            if (this->ext4fs->hasmetadatacsum()) {
                newde->reclen = blksize - sizeof(struct dirtail);
            } else {
                newde->reclen = blksize;
            }
            newde->namelen = namelen;
            newde->filetype = modetodt(child->attr.st_mode);
            NLib::memcpy(newde->name, (void *)name, namelen);

            // Set directory block checksum before writing.
            this->ext4fs->setdirblkcsum(this->attr.st_ino, this->diskino.generation, blkbuf);

            // Write the new block.
            this->metalock.release();
            ssize_t res = this->ext4fs->writeblock(newphysblk, blkbuf);
            this->metalock.acquire();

            delete[] blkbuf;

            if (res < 0) {
                return false;
            }

            // Update directory size.
            dirsize += blksize;
            this->diskino.sizelo = dirsize & 0xFFFFFFFF;
            this->diskino.sizethi = (dirsize >> 32) & 0xFFFFFFFF;
            __atomic_store_n(&this->attr.st_size, (off_t)dirsize, memory_order_release);

            // Update block count.
            uint64_t blocks = (dirsize + blksize - 1) / blksize;
            blocks = blocks * (blksize / 512);
            this->diskino.blockslo = blocks & 0xFFFFFFFF;
            this->diskino.blkshi = (blocks >> 32) & 0xFFFF;
            this->attr.st_blocks = blocks;

            // Update parent link count for directories.
            if (VFS::S_ISDIR(child->attr.st_mode)) {
                this->diskino.linkscount++;
                this->attr.st_nlink++;
            }

            this->touchtime(true, true, false); // Update mtime/ctime on dir modification.
            this->writeback();

            child->setparent(this);
            this->_addchild(child);
            return true;
        }

        bool Ext4Node::remove(const char *name) {
            NLib::ScopeSpinlock guard(&this->metalock);

            if (!VFS::S_ISDIR(this->attr.st_mode)) {
                return false;
            }

            size_t namelen = NLib::strlen(name);
            uint64_t dirsize = ((uint64_t)this->diskino.sizethi << 32) | this->diskino.sizelo;
            uint32_t blksize = this->ext4fs->blksize;
            uint8_t *blkbuf = new uint8_t[blksize];

            uint64_t diroff = 0;
            while (diroff < dirsize) {
                uint64_t logicalblk = diroff / blksize;

                this->metalock.release();
                uint64_t physblk = this->getphysblock(logicalblk);

                if (physblk == 0) {
                    this->metalock.acquire();
                    diroff += blksize;
                    continue;
                }

                ssize_t res = this->ext4fs->readblock(physblk, blkbuf);
                this->metalock.acquire();

                if (res < 0) {
                    delete[] blkbuf;
                    return false;
                }

                // Search for the entry in this block.
                size_t blockoff = 0;
                struct direntry2 *prevde = NULL;
                while (blockoff < blksize) {
                    struct direntry2 *de = (struct direntry2 *)(blkbuf + blockoff);

                    if (de->reclen == 0) {
                        break;
                    }

                    // Stop if we hit the directory tail (checksum entry).
                    if (de->filetype == EXT4_FTDIRCSUM) {
                        break;
                    }

                    if (de->inode != 0 && de->namelen == namelen) {
                        if (NLib::strncmp(name, de->name, namelen) == 0) { // Find our entry.
                            bool wasdir = (de->filetype == FT_DIR);

                            if (prevde) {
                                // Merge with previous entry.
                                prevde->reclen += de->reclen;
                            } else {
                                // Zero out inode to mark as deleted.
                                de->inode = 0;
                            }

                            // Set directory block checksum before writing.
                            this->ext4fs->setdirblkcsum(this->attr.st_ino, this->diskino.generation, blkbuf);

                            // Write block back.
                            this->metalock.release();
                            res = this->ext4fs->writeblock(physblk, blkbuf);
                            this->metalock.acquire();

                            delete[] blkbuf;

                            if (res < 0) {
                                return false;
                            }

                            // Update parent link count for directories.
                            if (wasdir && this->diskino.linkscount > 0) {
                                this->diskino.linkscount--;
                                this->attr.st_nlink--;
                                this->touchtime(true, true, false); // Update mtime/ctime on dir modification.
                                this->writeback();
                            }

                            // Remove from children cache.
                            this->children.remove(name);
                            return true;
                        }
                    }

                    prevde = de;
                    blockoff += de->reclen;
                }

                diroff += blksize;
            }

            delete[] blkbuf;
            return false;
        }

        ssize_t Ext4FileSystem::readblock(uint64_t blknum, void *buf) {
            off_t offset = blknum * this->blksize;
            return this->blkdev->readbytes(buf, this->blksize, offset, 0);
        }

        ssize_t Ext4FileSystem::writeblock(uint64_t blknum, const void *buf) {
            off_t offset = blknum * this->blksize;
            return this->blkdev->writebytes(buf, this->blksize, offset, 0);
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

        void Ext4FileSystem::updateinodebitmapcsum(uint32_t group, const void *bitmap) {
            if (!this->hasmetadatacsum()) {
                return;
            }

            uint32_t csum = this->calcinodebitmapcsum(group, bitmap);
            struct groupdesc *gd = &this->groupdescs[group];
            gd->inodebitmapcsumlo = csum & 0xFFFF;
            gd->inodebitmapcsumhi = (csum >> 16) & 0xFFFF;
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
            ssize_t res = this->blkdev->readbytes(inodebuf, this->sb.inodesize, inodeoff, 0);
            if (res < 0) {
                delete[] inodebuf;
                NUtil::printf("[fs/ext4fs]: Failed to read inode %u for update: %d.\n", ino, (int)res);
                return res;
            }

            // Copy our modified inode struct into the buffer.
            size_t copysize = this->sb.inodesize < sizeof(struct inode) ? this->sb.inodesize : sizeof(struct inode);
            NLib::memcpy(inodebuf, diskino, copysize);

            // Calculate and set inode checksum if metadata checksums are enabled.
            if (this->hasmetadatacsum()) {
                struct inode *bufino = (struct inode *)inodebuf;
                uint32_t csum = this->calcinodecsum(ino, inodebuf, this->sb.inodesize);
                bufino->csumlo = csum & 0xFFFF;
                if (this->sb.inodesize > 128) {
                    bufino->csumhi = (csum >> 16) & 0xFFFF;
                }
                // Update the caller's struct as well.
                diskino->csumlo = bufino->csumlo;
                diskino->csumhi = bufino->csumhi;
            }

            // Write the full inode buffer back to disk.
            res = this->blkdev->writebytes(inodebuf, this->sb.inodesize, inodeoff, 0);
            delete[] inodebuf;
            if (res < 0) {
                NUtil::printf("[fs/ext4fs]: Failed to write inode %u: %d.\n", ino, (int)res);
                return res;
            }

            return 0;
        }

        int Ext4FileSystem::writesuperblock(void) {
            if (this->hasmetadatacsum()) {
                this->sb.checksum = this->calcsuperblocksum();
            }

            ssize_t res = this->blkdev->writebytes(&this->sb, sizeof(struct superblock), 1024, 0);
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

            // Calculate and set group descriptor checksum.
            this->groupdescs[group].checksum = this->calcgroupdesccsum(group);

            uint64_t bgdtblock = (this->blksize == 1024) ? 2 : 1;
            uint16_t descsize = this->sb.descsize ? this->sb.descsize : 32;
            uint64_t offset = bgdtblock * this->blksize + group * descsize;

            ssize_t res = this->blkdev->writebytes(&this->groupdescs[group], descsize, offset, 0);
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

                            // Update inode bitmap checksum in group descriptor.
                            this->updateinodebitmapcsum(group, bitmap);

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

            // Update inode bitmap checksum in group descriptor.
            this->updateinodebitmapcsum(group, bitmap);

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
            ssize_t res = this->blkdev->readbytes(&diskino, sizeof(struct inode), inodeoff, 0);
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

            res = blkdev->readbytes(&this->sb, sizeof(struct superblock), 1024, 0);
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
            res = blkdev->readbytes(this->groupdescs, bgdtsize, bgdtblock * this->blksize, 0);
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