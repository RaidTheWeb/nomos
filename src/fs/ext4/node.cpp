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

        Ext4Node::Ext4Node(Ext4FileSystem *fs, const char *name, struct VFS::stat attr, struct inode *diskino) : VFS::INode((VFS::IFileSystem *)fs, name, attr) {
            this->ext4fs = fs;
            if (diskino) {
                NLib::memcpy(&this->diskino, diskino, sizeof(struct inode));
            }
        }

        // Read an indirect block pointer from disk.
        uint64_t Ext4Node::getindirectblock(uint64_t logicalblk) {
            // Ext4 (primarily in backwards compatibility mode) uses indirect blocks for block mapping.
            // Singly indirect blocks will look at the indirect block to find an additional list of blocks to index.
            // Doubly indirect blocks will look at the single indirect block to find a list of indirect blocks, each of which point to data blocks.
            // Triply indirect blocks will look at the double indirect block to find a list of single indirect blocks, each of which point to indirect blocks, which then point to data blocks.
            // It gets pretty clamplicated by the time you get to triply indirect blocks.

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
                physblk = ptrs[idx]; // Read physical block from indirect block.

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
                uint64_t indblk = ptrs[idx1]; // Same as single indirect block read.
                if (indblk == 0) {
                    delete[] blkbuf;
                    return 0;
                }

                if (this->ext4fs->readblock(indblk, blkbuf) < 0) { // Read from the single indirect to find double indirect.
                    delete[] blkbuf;
                    return 0;
                }

                ptrs = (uint32_t *)blkbuf;
                physblk = ptrs[idx2]; // Get physical block.

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
                uint64_t dindblk = ptrs[idx1]; // Get double indirect block from single indirect.
                if (dindblk == 0) {
                    delete[] blkbuf;
                    return 0;
                }

                if (this->ext4fs->readblock(dindblk, blkbuf) < 0) {
                    delete[] blkbuf;
                    return 0;
                }

                ptrs = (uint32_t *)blkbuf;
                uint64_t indblk = ptrs[idx2]; // Get triple indirect block from double indirect.
                if (indblk == 0) {
                    delete[] blkbuf;
                    return 0;
                }

                if (this->ext4fs->readblock(indblk, blkbuf) < 0) {
                    delete[] blkbuf;
                    return 0;
                }

                ptrs = (uint32_t *)blkbuf; // Get physical block from triple indirect block.
                physblk = ptrs[idx3];
            }

            delete[] blkbuf;
            return physblk;
        }

        ssize_t Ext4Node::read(void *buf, size_t count, off_t offset, int fdflags) {
            (void)fdflags;

            // For regular files, go through the page cache. Isn't like Ext4FileSystem::readblock(), because it caches at an inode-level instead of on the device level.
            if (VFS::S_ISREG(this->attr.st_mode)) {
                return this->readcached(buf, count, offset);
            }

            NLib::ScopeIRQSpinlock guard(&this->metalock);

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
                    ssize_t res = this->ext4fs->readblock(physblk, blkbuf); // Device-level read in terms of ext4 blocks.
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
            NLib::ScopeIRQSpinlock guard(&this->metalock);

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

                    // Skip empty entries (inode == 0 and namelen == 0).
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
            NLib::ScopeIRQSpinlock guard(&this->metalock);

            if (!VFS::S_ISLNK(this->attr.st_mode)) {
                return -EINVAL;
            }

            uint64_t linksize = ((uint64_t)this->diskino.sizethi << 32) | this->diskino.sizelo;

            if (linksize < sizeof(this->diskino.block)) { // "Fast symlinks" are stored in the block array itself (if short enough).
                size_t tocopy = linksize;
                if (tocopy > bufsiz) {
                    tocopy = bufsiz;
                }
                NLib::memcpy(buf, this->diskino.block, tocopy); // We can read shorter symlinks right out of the block array.
                return tocopy;
            }

            // Otherwise, we'd need to read the file itself (slow symlinks!).
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
            NLib::ScopeIRQSpinlock guard(&this->metalock);

            if (!VFS::S_ISDIR(this->attr.st_mode)) {
                return NULL;
            }

            // Check if child is already cached (we REALLY don't want to have to allocate a new Ext4Node by calling loadinode() every time).
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
                                this->_addchild(child); // Link into parent for cleanup on umount (and also so we can cache it).
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
                return true; // Non-directories are considered empty.
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
                    return true; // Failure to read block, consider non-empty. XXX: Is this wise?
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

                        if (!isdot && !isdotdot) { // Anything other than the generic directory links are real entries.
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
                NLib::ScopeIRQSpinlock guard(&this->metalock);

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

                this->touchtime(true, true, false); // Update modification and creation times.
                int res = this->writeback(); // Write inode changes.
                if (res < 0) {
                    return res;
                }
                return len;
            }

            // For longer symlinks, use the regular write path (extent-based, or indirect, if the filesystem feels like it).
            return this->write(target, len, 0, 0);
        }

        // Implementation of reading a single page for Ext4Node, required for page cache readcached().
        int Ext4Node::readpage(NMem::CachePage *page) {
            if (!VFS::S_ISREG(this->attr.st_mode)) {
                return -EINVAL; // Only regular files use page cache.
            }

            off_t offset = page->offset;

            uint64_t filesize = __atomic_load_n(&this->attr.st_size, memory_order_acquire);

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

                // Get physical block and contiguous run length.
                uint64_t runlen = 0;
                uint64_t physblk = this->getextentrun(logicalblk, &runlen);

                if (physblk == 0) {
                    // Hole (skip).
                    size_t skipbytes = blksize - blkoff;
                    if (skipbytes > toread - bytesread) {
                        skipbytes = toread - bytesread;
                    }
                    bytesread += skipbytes;
                    dest += skipbytes;
                    continue;
                }

                // Calculate how much we can read contiguously.
                // Start with remaining bytes in the current block.
                size_t chunk = blksize - blkoff;
                // Add full blocks from the extent run (minus 1 for current block).
                if (runlen > 1 && blkoff == 0) {
                    chunk = runlen * blksize;
                }
                // Clamp to what we need.
                if (chunk > toread - bytesread) {
                    chunk = toread - bytesread;
                }

                // Single batched read for the contiguous run (only really beneficial for block sizes under page size).
                off_t diskoffset = physblk * blksize + blkoff;
                ssize_t res = this->ext4fs->blkdev->readbytesdirect(dest, chunk, diskoffset);
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
            // NOTE: Includes contiguous extent writes within a single page only (largely redundant without sub-PAGESIZE block sizes).

            if (!VFS::S_ISREG(this->attr.st_mode)) {
                return -EINVAL; // Only regular files use page cache.
            }

            page->setflag(NMem::PAGE_WRITEBACK); // Mark that writeback is in progress.

            off_t offset = page->offset;

            uint64_t filesize = __atomic_load_n(&this->attr.st_size, memory_order_acquire);

            // Determine how much of the page is valid file data.
            size_t towrite = NArch::PAGESIZE;
            if ((uint64_t)offset + towrite > filesize) {
                towrite = filesize > (uint64_t)offset ? filesize - offset : 0;
            }

            if (towrite == 0) {
                page->clearflag(NMem::PAGE_WRITEBACK); // No data to write.
                page->markclean();
                return 0;
            }

            uint32_t blksize = this->ext4fs->blksize;
            const uint8_t *src = (const uint8_t *)page->data();
            size_t byteswritten = 0;

            while (byteswritten < towrite) {
                uint64_t logicalblk = (offset + byteswritten) / blksize;
                size_t blkoff = (offset + byteswritten) % blksize;

                // Get physical block and contiguous run length.
                uint64_t runlen = 0;
                uint64_t physblk = this->getextentrun(logicalblk, &runlen);

                if (physblk == 0) {
                    // Need to allocate blocks for this write.
                    // Calculate how many blocks we need for the remaining data.
                    size_t remaining = towrite - byteswritten;
                    size_t blocksneeded = (remaining + blksize - 1) / blksize;
                    if (blocksneeded > 0xFFFF) {
                        blocksneeded = 0xFFFF; // Max extent length.
                    }

                    physblk = this->allocextent(logicalblk, (uint16_t)blocksneeded);
                    if (physblk == 0) {
                        page->clearflag(NMem::PAGE_WRITEBACK);
                        page->errorcount++;
                        return -ENOSPC;
                    }
                    // Re-query to get the actual run length allocated.
                    physblk = this->getextentrun(logicalblk, &runlen);
                    if (physblk == 0) {
                        page->clearflag(NMem::PAGE_WRITEBACK);
                        page->errorcount++;
                        return -EIO;
                    }
                }

                // Calculate how much we can write contiguously.
                size_t chunk = blksize - blkoff;
                if (runlen > 1 && blkoff == 0) {
                    chunk = runlen * blksize;
                }
                if (chunk > towrite - byteswritten) {
                    chunk = towrite - byteswritten;
                }

                // Single batched write for the contiguous run.
                off_t diskoffset = physblk * blksize + blkoff;
                ssize_t res = this->ext4fs->blkdev->writebytesdirect(src + byteswritten, chunk, diskoffset);
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

        int Ext4Node::writepages(NMem::CachePage **pages, size_t count) {
            // Write multiple contiguous pages, coalescing into single I/O operations where possible.

            if (count == 0) {
                return 0;
            }

            if (!VFS::S_ISREG(this->attr.st_mode)) {
                return -EINVAL;
            }

            // Maximum pages to coalesce into a single temporary buffer (128KB).
            static constexpr size_t MAXBATCHPAGES = 32;

            // Mark all pages as writeback in progress.
            for (size_t i = 0; i < count; i++) {
                pages[i]->setflag(NMem::PAGE_WRITEBACK);
            }

            uint64_t filesize = __atomic_load_n(&this->attr.st_size, memory_order_acquire);
            uint32_t blksize = this->ext4fs->blksize;
            ssize_t written = 0;

            for (size_t i = 0; i < count;) {
                NMem::CachePage *page = pages[i];
                off_t offset = page->offset;

                // Determine how much of this page is valid file data.
                size_t pagevalid = NArch::PAGESIZE;
                if ((uint64_t)offset >= filesize) {
                    // Page is entirely beyond EOF, nothing to write.
                    page->clearflag(NMem::PAGE_WRITEBACK);
                    page->markclean();
                    i++;
                    written++;
                    continue;
                }
                if ((uint64_t)offset + pagevalid > filesize) {
                    pagevalid = filesize - offset;
                }

                // Get the physical block and extent run length.
                uint64_t logicalblk = offset / blksize;
                uint64_t runlen = 0;
                uint64_t physblk = this->getextentrun(logicalblk, &runlen);

                // If blocks not allocated, allocate them.
                if (physblk == 0) {
                    size_t blocksperpage = NArch::PAGESIZE / blksize;
                    size_t blocksneeded = blocksperpage;

                    physblk = this->allocextent(logicalblk, (uint16_t)blocksneeded);
                    if (physblk == 0) {
                        // Allocation failed, clear writeback on remaining pages and return.
                        for (size_t j = i; j < count; j++) {
                            pages[j]->clearflag(NMem::PAGE_WRITEBACK);
                            pages[j]->errorcount++;
                        }
                        if (written > 0) {
                            return written;
                        }
                        return -ENOSPC;
                    }
                    // Re-query extent info after allocation.
                    physblk = this->getextentrun(logicalblk, &runlen);
                    if (physblk == 0) {
                        for (size_t j = i; j < count; j++) {
                            pages[j]->clearflag(NMem::PAGE_WRITEBACK);
                            pages[j]->errorcount++;
                        }
                        if (written > 0) {
                            return written;
                        }
                        return -EIO;
                    }
                }

                // Calculate how many consecutive pages can be written in one batch.
                size_t batchcount = 1;
                size_t blocksperpage = NArch::PAGESIZE / blksize;
                uint64_t blocksavail = runlen;

                while (batchcount < MAXBATCHPAGES &&
                       i + batchcount < count &&
                       blocksavail > blocksperpage) {
                    NMem::CachePage *nextpage = pages[i + batchcount];

                    // Check file offset contiguity.
                    if ((uint64_t)nextpage->offset != (uint64_t)pages[i + batchcount - 1]->offset + NArch::PAGESIZE) {
                        break;
                    }

                    // Check if next page has allocated physical blocks (contiguous).
                    uint64_t nextlogical = nextpage->offset / blksize;
                    uint64_t nextrunlen = 0;
                    uint64_t nextphys = this->getextentrun(nextlogical, &nextrunlen);

                    // Verify next page's physical block is contiguous with current batch.
                    uint64_t expectedphys = physblk + batchcount * blocksperpage;
                    if (nextphys != expectedphys) {
                        break;
                    }

                    batchcount++;
                    blocksavail -= blocksperpage;
                }

                // Calculate total bytes to write for this batch.
                size_t totalbytes = batchcount * NArch::PAGESIZE;

                // Clamp to file size (don't write padding beyond EOF).
                if ((uint64_t)offset + totalbytes > filesize) {
                    totalbytes = filesize - offset;
                }

                off_t diskoffset = physblk * blksize;

                if (batchcount == 1) {
                    // Single page. Write directly from page data.
                    ssize_t res = this->ext4fs->blkdev->writebytesdirect(page->data(), totalbytes, diskoffset);
                    if (res < 0) {
                        page->clearflag(NMem::PAGE_WRITEBACK);
                        page->errorcount++;
                        // Clear remaining pages and return.
                        for (size_t j = i + 1; j < count; j++) {
                            pages[j]->clearflag(NMem::PAGE_WRITEBACK);
                        }
                        if (written > 0) {
                            return written;
                        }
                        return (int)res;
                    }
                    page->clearflag(NMem::PAGE_WRITEBACK);
                    page->markclean();
                    page->errorcount = 0;
                    i++;
                    written++;
                } else {
                    // Multiple pages, use temporary buffer for coalesced I/O.
                    uint8_t *tmpbuf = new uint8_t[batchcount * NArch::PAGESIZE];
                    if (!tmpbuf) {

                        // If we don't have memory for the buffer, fallback to writing pages individually (reclaim? :broken_heart:).
                        for (size_t j = 0; j < batchcount; j++) {
                            int err = this->writepage(pages[i + j]);
                            if (err < 0) {
                                // Clear remaining and return.
                                for (size_t k = i + j + 1; k < count; k++) {
                                    pages[k]->clearflag(NMem::PAGE_WRITEBACK);
                                }
                                if (written > 0) {
                                    return written;
                                }
                                return err;
                            }
                            written++;
                        }
                        i += batchcount;
                        continue;
                    }

                    // Gather page data into temporary buffer.
                    for (size_t j = 0; j < batchcount; j++) {
                        NLib::memcpy(tmpbuf + j * NArch::PAGESIZE, pages[i + j]->data(), NArch::PAGESIZE);
                    }

                    // Single coalesced write.
                    ssize_t res = this->ext4fs->blkdev->writebytesdirect(tmpbuf, totalbytes, diskoffset);
                    delete[] tmpbuf;

                    if (res < 0) {
                        // Mark batch as failed, clear remaining.
                        for (size_t j = 0; j < batchcount; j++) {
                            pages[i + j]->clearflag(NMem::PAGE_WRITEBACK);
                            pages[i + j]->errorcount++;
                        }
                        for (size_t j = i + batchcount; j < count; j++) {
                            pages[j]->clearflag(NMem::PAGE_WRITEBACK);
                        }
                        if (written > 0) {
                            return written;
                        }
                        return (int)res;
                    }

                    // Mark all pages in batch as clean.
                    for (size_t j = 0; j < batchcount; j++) {
                        pages[i + j]->clearflag(NMem::PAGE_WRITEBACK);
                        pages[i + j]->markclean();
                        pages[i + j]->errorcount = 0;
                    }

                    written += batchcount;
                    i += batchcount;
                }
            }

            return written;
        }

        NDev::BlockDevice *Ext4Node::getblockdevice(void) {
            return this->ext4fs->blkdev;
        }

        uint64_t Ext4Node::getpagelba(off_t pageoffset) {
            // Only regular files use page cache readahead.
            if (!VFS::S_ISREG(this->attr.st_mode)) {
                return 0;
            }

            uint32_t blksize = this->ext4fs->blksize;
            uint64_t logicalblk = pageoffset / blksize;

            // Get physical block via extent mapping.
            uint64_t runlen = 0;
            uint64_t physblk = this->getextentrun(logicalblk, &runlen);

            if (physblk == 0) {
                return 0; // Hole.
            }

            // Convert filesystem block to device LBA.
            // The device LBA is the physical block number times the ratio of fs blocksize to device blocksize.
            size_t devblksize = this->ext4fs->blkdev->blksize;
            uint64_t lba = physblk * (blksize / devblksize);

            return lba;
        }

        uint64_t Ext4Node::getpagelbacached(off_t pageoffset, bool *needsio) {
            // Only regular files use page cache readahead.
            if (!VFS::S_ISREG(this->attr.st_mode)) {
                if (needsio) *needsio = false;
                return 0;
            }

            uint32_t blksize = this->ext4fs->blksize;
            uint64_t logicalblk = pageoffset / blksize;

            // Try extent cache lookup only (non-blocking).
            uint64_t physblk = 0;
            uint64_t runlen = 0;
            if (!this->lookupcachedextent(logicalblk, &physblk, &runlen)) {
                // Extent not cached, would need I/O to resolve.
                if (needsio) *needsio = true;
                return 0;
            }

            // Found in cache.
            if (needsio) *needsio = false;

            if (physblk == 0) {
                return 0; // Hole.
            }

            // Convert filesystem block to device LBA.
            size_t devblksize = this->ext4fs->blkdev->blksize;
            uint64_t lba = physblk * (blksize / devblksize);

            return lba;
        }

        int Ext4Node::sync(enum VFS::INode::syncmode mode) {
            // Sync dirty pages to disk first (the case for FULL and DATA sync).
            int err = this->synccache();
            if (err != 0) {
                return -EIO; // synccache returns error count, convert to error code.
            }

            // For full sync, also write back inode metadata.
            if (mode == VFS::INode::SYNC_FULL) {
                NLib::ScopeIRQSpinlock guard(&this->metalock);
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

        // Atomic commit of metadata changes with timestamp updates.
        int Ext4Node::commitmetadata(bool mtime, bool ctime, bool atime) {
            NLib::ScopeIRQSpinlock guard(&this->metalock);
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
                    NLib::ScopeIRQSpinlock guard(&this->metalock);
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

                uint64_t writtenend = offset + count;
                if (writtenend > oldsize) { // Grow file size.
                    __atomic_store_n(&this->attr.st_size, writtenend, memory_order_release);

                    NLib::ScopeIRQSpinlock guard(&this->metalock);
                    this->diskino.sizelo = writtenend & 0xFFFFFFFF;
                    this->diskino.sizethi = (writtenend >> 32) & 0xFFFFFFFF;

                    // Update block count.
                    uint64_t newblocks = (writtenend + blksize - 1) / blksize;
                    newblocks = newblocks * (blksize / 512); // Convert to 512-byte sectors.
                    this->diskino.blockslo = newblocks & 0xFFFFFFFF;
                    this->diskino.blkshi = (newblocks >> 32) & 0xFFFF;
                    this->attr.st_blocks = newblocks;
                }

                // Write through page cache.
                ssize_t result = this->writecached(buf, count, offset);

                if (result > 0) {
                    NLib::ScopeIRQSpinlock guard(&this->metalock);

                    // If we got a short write when extending, adjust size back down.
                    uint64_t actualend = offset + result;
                    if (writtenend > oldsize && actualend < writtenend) {
                        // Partial write, adjust size to actual written end.
                        __atomic_store_n(&this->attr.st_size, actualend > oldsize ? actualend : oldsize, memory_order_release);
                        this->diskino.sizelo = (actualend > oldsize ? actualend : oldsize) & 0xFFFFFFFF;
                        this->diskino.sizethi = ((actualend > oldsize ? actualend : oldsize) >> 32) & 0xFFFFFFFF;
                    }

                    // Update timestamps and writeback inode metadata.
                    this->touchtime(true, true, false);
                    this->writeback();
                } else if (result < 0 && writtenend > oldsize) {
                    // Write failed completely, restore old size.
                    __atomic_store_n(&this->attr.st_size, oldsize, memory_order_release);
                    NLib::ScopeIRQSpinlock guard(&this->metalock);
                    this->diskino.sizelo = oldsize & 0xFFFFFFFF;
                    this->diskino.sizethi = (oldsize >> 32) & 0xFFFFFFFF;
                }

                return result;
            }

            // Fallback for non-regular files (shouldn't happen normally). XXX: Disallow?
            NLib::ScopeIRQSpinlock guard(&this->metalock);
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
            NLib::ScopeIRQSpinlock guard(&this->metalock);

            if (length < 0) {
                return -EINVAL;
            }

            if (VFS::S_ISDIR(this->attr.st_mode)) {
                return -EISDIR;
            }

            // Invalidate extent cache since extents nearly definitely change.
            this->invalidateextentcache();

            uint64_t oldsize = ((uint64_t)this->diskino.sizethi << 32) | this->diskino.sizelo;
            uint64_t newsize = (uint64_t)length;

            if (newsize == oldsize) {
                return 0; // Nothing to do.
            }

            uint32_t blksize = this->ext4fs->blksize;

            if (newsize < oldsize) { // Only bother to shrink blocks, because growing is automatically handled on write().
                // Reducing size.
                uint64_t newblocks = (newsize + blksize - 1) / blksize;

                if (this->diskino.flags & EXT4_EXTENTSFL) { // Extents need special handling.
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
                } else {
                    // NOTE: Jesus Christ, this is egregious.

                    // Handle freeing indirect blocks for legacy (non-extent) inodes.
                    uint64_t oldblocks = (oldsize + blksize - 1) / blksize;
                    uint32_t ptrsperblk = blksize / sizeof(uint32_t);

                    // Free direct blocks beyond newblocks.
                    for (uint64_t blk = newblocks; blk < oldblocks && blk < EXT4_NDIRBLOCKS; blk++) {
                        if (this->diskino.block[blk] != 0) {
                            this->ext4fs->freeblock(this->diskino.block[blk]);
                            this->diskino.block[blk] = 0;
                        }
                    }

                    // Handle single indirect block.
                    uint64_t indirectstart = EXT4_NDIRBLOCKS;
                    uint64_t indirectend = indirectstart + ptrsperblk;
                    if (oldblocks > indirectstart && this->diskino.block[EXT4_INDBLOCK] != 0) {
                        uint8_t *indbuf = new uint8_t[blksize];
                        if (this->ext4fs->readblock(this->diskino.block[EXT4_INDBLOCK], indbuf) >= 0) {
                            uint32_t *ptrs = (uint32_t *)indbuf;
                            bool anyremaining = false;

                            for (uint32_t i = 0; i < ptrsperblk; i++) {
                                uint64_t logblk = indirectstart + i;
                                if (logblk >= newblocks && logblk < oldblocks && ptrs[i] != 0) {
                                    this->ext4fs->freeblock(ptrs[i]);
                                    ptrs[i] = 0;
                                }
                                if (ptrs[i] != 0) {
                                    anyremaining = true;
                                }
                            }

                            if (anyremaining) {
                                // Write back modified indirect block.
                                this->ext4fs->writeblock(this->diskino.block[EXT4_INDBLOCK], indbuf);
                            } else if (newblocks <= indirectstart) {
                                // Free the indirect block itself.
                                this->ext4fs->freeblock(this->diskino.block[EXT4_INDBLOCK]);
                                this->diskino.block[EXT4_INDBLOCK] = 0;
                            }
                        }
                        delete[] indbuf;
                    }

                    // Handle double indirect block.
                    uint64_t dindirectstart = indirectend;
                    uint64_t dindirectend = dindirectstart + ptrsperblk * ptrsperblk;
                    if (oldblocks > dindirectstart && this->diskino.block[EXT4_DINDBLOCK] != 0) {
                        uint8_t *dindbuf = new uint8_t[blksize];
                        uint8_t *indbuf = new uint8_t[blksize];

                        if (this->ext4fs->readblock(this->diskino.block[EXT4_DINDBLOCK], dindbuf) >= 0) {
                            uint32_t *dptrs = (uint32_t *)dindbuf;
                            bool anydindremaining = false;

                            for (uint32_t i = 0; i < ptrsperblk; i++) {
                                if (dptrs[i] == 0) {
                                    continue;
                                }

                                uint64_t indbase = dindirectstart + i * ptrsperblk;
                                if (indbase >= oldblocks) {
                                    continue;
                                }

                                if (this->ext4fs->readblock(dptrs[i], indbuf) >= 0) {
                                    uint32_t *ptrs = (uint32_t *)indbuf;
                                    bool anyindremaining = false;

                                    for (uint32_t j = 0; j < ptrsperblk; j++) {
                                        uint64_t logblk = indbase + j;
                                        if (logblk >= newblocks && logblk < oldblocks && ptrs[j] != 0) {
                                            this->ext4fs->freeblock(ptrs[j]);
                                            ptrs[j] = 0;
                                        }
                                        if (ptrs[j] != 0) {
                                            anyindremaining = true;
                                        }
                                    }

                                    if (anyindremaining) {
                                        this->ext4fs->writeblock(dptrs[i], indbuf);
                                        anydindremaining = true;
                                    } else if (indbase >= newblocks) {
                                        this->ext4fs->freeblock(dptrs[i]);
                                        dptrs[i] = 0;
                                    } else {
                                        anydindremaining = true;
                                    }
                                }
                            }

                            if (anydindremaining) {
                                this->ext4fs->writeblock(this->diskino.block[EXT4_DINDBLOCK], dindbuf);
                            } else if (newblocks <= dindirectstart) {
                                this->ext4fs->freeblock(this->diskino.block[EXT4_DINDBLOCK]);
                                this->diskino.block[EXT4_DINDBLOCK] = 0;
                            }
                        }

                        delete[] indbuf;
                        delete[] dindbuf;
                    }

                    // Handle triple indirect block (similar pattern, but even more nested).
                    uint64_t tindirectstart = dindirectend;
                    if (oldblocks > tindirectstart && this->diskino.block[EXT4_TINDBLOCK] != 0) {
                        if (newblocks <= tindirectstart) {
                            // Free entire triple indirect tree.
                            uint8_t *tindbuf = new uint8_t[blksize];
                            uint8_t *dindbuf = new uint8_t[blksize];
                            uint8_t *indbuf = new uint8_t[blksize];

                            if (this->ext4fs->readblock(this->diskino.block[EXT4_TINDBLOCK], tindbuf) >= 0) {
                                uint32_t *tptrs = (uint32_t *)tindbuf;
                                for (uint32_t i = 0; i < ptrsperblk; i++) {
                                    if (tptrs[i] == 0) {
                                        continue;
                                    }
                                    if (this->ext4fs->readblock(tptrs[i], dindbuf) >= 0) {
                                        uint32_t *dptrs = (uint32_t *)dindbuf;
                                        for (uint32_t j = 0; j < ptrsperblk; j++) {
                                            if (dptrs[j] == 0) {
                                                continue;
                                            }
                                            if (this->ext4fs->readblock(dptrs[j], indbuf) >= 0) {
                                                uint32_t *ptrs = (uint32_t *)indbuf;
                                                for (uint32_t k = 0; k < ptrsperblk; k++) {
                                                    if (ptrs[k] != 0) {
                                                        this->ext4fs->freeblock(ptrs[k]);
                                                    }
                                                }
                                            }
                                            this->ext4fs->freeblock(dptrs[j]);
                                        }
                                    }
                                    this->ext4fs->freeblock(tptrs[i]);
                                }
                            }
                            this->ext4fs->freeblock(this->diskino.block[EXT4_TINDBLOCK]);
                            this->diskino.block[EXT4_TINDBLOCK] = 0;

                            delete[] indbuf;
                            delete[] dindbuf;
                            delete[] tindbuf;
                        }
                        // XXX: Partial triple indirect truncation is not implemented.
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

        bool Ext4Node::add(VFS::INode *node) {
            NLib::ScopeIRQSpinlock guard(&this->metalock);

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
            // Entry spans entire block (shrinks when more entries are added).
            newde->reclen = blksize;
            newde->namelen = namelen;
            newde->filetype = modetodt(child->attr.st_mode);
            NLib::memcpy(newde->name, (void *)name, namelen);

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
            NLib::ScopeIRQSpinlock guard(&this->metalock);

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

    }
}