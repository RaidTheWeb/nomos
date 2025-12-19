#include <dev/block.hpp>
#include <fs/ext4/defs.hpp>
#include <fs/ext4/ext4fs.hpp>
#include <lib/string.hpp>
#include <mm/slab.hpp>
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

        // Resolve the physical block (the actual stuff on the disk) for a logical (filesystem) block.
        uint64_t Ext4Node::getphysblock(uint64_t logicalblk) {
            if (!(this->diskino.flags & EXT4_EXTENTSFL)) { // Legacy indirect blocks.
                if (logicalblk < EXT4_NDIRBLOCKS) {
                    return this->diskino.block[logicalblk];
                }

                // XXX: Implement indirect blocks.
                return 0;
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

        ssize_t Ext4Node::read(void *buf, size_t count, off_t offset, int fdflags) {
            (void)fdflags;

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
                NUtil::printf("[fs/ext4fs]: Read directory block %llu (phys %llu)\n", logicalblk, physblk);
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


        ssize_t Ext4FileSystem::readblock(uint64_t blknum, void *buf) {
            off_t offset = blknum * this->blksize;
            return this->blkdev->readbytes(buf, this->blksize, offset, 0);
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

            NUtil::printf("[fs/ext4fs]: Reading superblock from %s\n", src);
            res = blkdev->readbytes(&this->sb, sizeof(struct superblock), 1024, 0);
            if (res < 0) {
                devnode->unref();
                return res;
            }

            NUtil::printf("[fs/ext4fs]: Superblock read complete\n");

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

            NUtil::printf("[fs/ext4fs]: Block group descriptors read complete\n");

            // Load root inode (inode 2).
            this->root = this->loadinode(EXT4_ROOTINO, "");
            if (!this->root) {
                NUtil::printf("[fs/ext4fs]: Failed to load root inode\n");
                delete[] this->groupdescs;
                this->groupdescs = NULL;
                devnode->unref();
                return -EIO;
            }

            NUtil::printf("[fs/ext4fs]: Root inode loaded\n");

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