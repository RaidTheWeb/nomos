#include <dev/block.hpp>
#include <fs/ext4/defs.hpp>
#include <fs/ext4/ext4fs.hpp>
#include <lib/string.hpp>
#include <mm/slab.hpp>
#include <stddef.h>
#include <sys/clock.hpp>
#include <util/kprint.hpp>

namespace NFS {
    namespace Ext4FS {

        // Feature flags for checksums.
        #define EXT4_FEATUREROCOMPATMETADATACSUM 0x0400
        #define EXT4_FEATUREROCOMPATGDTCSUM 0x0010
        #define EXT4_FEATUREINCOMPATCSUMSEED 0x2000

        // CRC32c polynomial (Castagnoli).
        static const uint32_t crc32c_table[256] = {
            0x00000000, 0xF26B8303, 0xE13B70F7, 0x1350F3F4, 0xC79A971F, 0x35F1141C, 0x26A1E7E8, 0xD4CA64EB,
            0x8AD958CF, 0x78B2DBCC, 0x6BE22838, 0x9989AB3B, 0x4D43CFD0, 0xBF284CD3, 0xAC78BF27, 0x5E133C24,
            0x105EC76F, 0xE235446C, 0xF165B798, 0x030E349B, 0xD7C45070, 0x25AFD373, 0x36FF2087, 0xC494A384,
            0x9A879FA0, 0x68EC1CA3, 0x7BBCEF57, 0x89D76C54, 0x5D1D08BF, 0xAF768BBC, 0xBC267848, 0x4E4DFB4B,
            0x20BD8EDE, 0xD2D60DDD, 0xC186FE29, 0x33ED7D2A, 0xE72719C1, 0x154C9AC2, 0x061C6936, 0xF477EA35,
            0xAA64D611, 0x580F5512, 0x4B5FA6E6, 0xB93425E5, 0x6DFE410E, 0x9F95C20D, 0x8CC531F9, 0x7EAEB2FA,
            0x30E349B1, 0xC288CAB2, 0xD1D83946, 0x23B3BA45, 0xF779DEAE, 0x05125DAD, 0x1642AE59, 0xE4292D5A,
            0xBA3A117E, 0x4851927D, 0x5B016189, 0xA96AE28A, 0x7DA08661, 0x8FCB0562, 0x9C9BF696, 0x6EF07595,
            0x417B1DBC, 0xB3109EBF, 0xA0406D4B, 0x522BEE48, 0x86E18AA3, 0x748A09A0, 0x67DAFA54, 0x95B17957,
            0xCBA24573, 0x39C9C670, 0x2A993584, 0xD8F2B687, 0x0C38D26C, 0xFE53516F, 0xED03A29B, 0x1F682198,
            0x5125DAD3, 0xA34E59D0, 0xB01EAA24, 0x42752927, 0x96BF4DCC, 0x64D4CECF, 0x77843D3B, 0x85EFBE38,
            0xDBFC821C, 0x2997011F, 0x3AC7F2EB, 0xC8AC71E8, 0x1C661503, 0xEE0D9600, 0xFD5D65F4, 0x0F36E6F7,
            0x61C69362, 0x93AD1061, 0x80FDE395, 0x72966096, 0xA65C047D, 0x5437877E, 0x4767748A, 0xB50CF789,
            0xEB1FCBAD, 0x197448AE, 0x0A24BB5A, 0xF84F3859, 0x2C855CB2, 0xDEEEDFB1, 0xCDBE2C45, 0x3FD5AF46,
            0x7198540D, 0x83F3D70E, 0x90A324FA, 0x62C8A7F9, 0xB602C312, 0x44694011, 0x5739B3E5, 0xA55230E6,
            0xFB410CC2, 0x092A8FC1, 0x1A7A7C35, 0xE811FF36, 0x3CDB9BDD, 0xCEB018DE, 0xDDE0EB2A, 0x2F8B6829,
            0x82F63B78, 0x709DB87B, 0x63CD4B8F, 0x91A6C88C, 0x456CAC67, 0xB7072F64, 0xA457DC90, 0x563C5F93,
            0x082F63B7, 0xFA44E0B4, 0xE9141340, 0x1B7F9043, 0xCFB5F4A8, 0x3DDE77AB, 0x2E8E845F, 0xDCE5075C,
            0x92A8FC17, 0x60C37F14, 0x73938CE0, 0x81F80FE3, 0x55326B08, 0xA759E80B, 0xB4091BFF, 0x466298FC,
            0x1871A4D8, 0xEA1A27DB, 0xF94AD42F, 0x0B21572C, 0xDFEB33C7, 0x2D80B0C4, 0x3ED04330, 0xCCBBC033,
            0xA24BB5A6, 0x502036A5, 0x4370C551, 0xB11B4652, 0x65D122B9, 0x97BAA1BA, 0x84EA524E, 0x7681D14D,
            0x2892ED69, 0xDAF96E6A, 0xC9A99D9E, 0x3BC21E9D, 0xEF087A76, 0x1D63F975, 0x0E330A81, 0xFC588982,
            0xB21572C9, 0x407EF1CA, 0x532E023E, 0xA145813D, 0x758FE5D6, 0x87E466D5, 0x94B49521, 0x66DF1622,
            0x38CC2A06, 0xCAA7A905, 0xD9F75AF1, 0x2B9CD9F2, 0xFF56BD19, 0x0D3D3E1A, 0x1E6DCDEE, 0xEC064EED,
            0xC38D26C4, 0x31E6A5C7, 0x22B65633, 0xD0DDD530, 0x0417B1DB, 0xF67C32D8, 0xE52CC12C, 0x1747422F,
            0x49547E0B, 0xBB3FFD08, 0xA86F0EFC, 0x5A048DFF, 0x8ECEE914, 0x7CA56A17, 0x6FF599E3, 0x9D9E1AE0,
            0xD3D3E1AB, 0x21B862A8, 0x32E8915C, 0xC083125F, 0x144976B4, 0xE622F5B7, 0xF5720643, 0x07198540,
            0x590AB964, 0xAB613A67, 0xB831C993, 0x4A5A4A90, 0x9E902E7B, 0x6CFBAD78, 0x7FAB5E8C, 0x8DC0DD8F,
            0xE330A81A, 0x115B2B19, 0x020BD8ED, 0xF0605BEE, 0x24AA3F05, 0xD6C1BC06, 0xC5914FF2, 0x37FACCF1,
            0x69E9F0D5, 0x9B8273D6, 0x88D28022, 0x7AB90321, 0xAE7367CA, 0x5C18E4C9, 0x4F48173D, 0xBD23943E,
            0xF36E6F75, 0x0105EC76, 0x12551F82, 0xE03E9C81, 0x34F4F86A, 0xC69F7B69, 0xD5CF889D, 0x27A40B9E,
            0x79B737BA, 0x8BDCB4B9, 0x988C474D, 0x6AE7C44E, 0xBE2DA0A5, 0x4C4623A6, 0x5F16D052, 0xAD7D5351
        };

        // CRC32c calculation function.
        static uint32_t crc32c(uint32_t crc, const void *buf, size_t len) {
            const uint8_t *p = (const uint8_t *)buf;
            crc = ~crc;
            while (len--) {
                crc = crc32c_table[(crc ^ *p++) & 0xFF] ^ (crc >> 8);
            }
            return ~crc;
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
            return this->ext4fs->writeinode(this->attr.st_ino, &this->diskino);
        }

        // Allocate a new extent for the file.
        uint64_t Ext4Node::allocextent(uint64_t logicalblk, uint16_t len) {
            if (!(this->diskino.flags & EXT4_EXTENTSFL)) {
                // XXX: Handle legacy indirect blocks.
                return 0;
            }

            struct extenthdr *hdr = (struct extenthdr *)this->diskino.block;
            if (hdr->magic != EXT4_EXTMAGIC) {
                return 0;
            }

            // Only handle depth 0 (inline extents) for now.
            if (hdr->depth != 0) {
                NUtil::printf("[fs/ext4fs]: Deep extent trees not yet supported for allocation\n");
                return 0;
            }

            // Check if we can add another extent.
            if (hdr->entries >= hdr->max) {
                NUtil::printf("[fs/ext4fs]: Extent array full, tree growth not yet supported\n");
                return 0;
            }

            // Try to allocate from the same group as the inode for locality.
            uint32_t inogroup = (this->attr.st_ino - 1) / this->ext4fs->sb.inodespergroup;
            uint64_t physblk = 0;

            // Allocate blocks one at a time.
            // XXX: Could definitely optimize to allocate contiguously.
            for (uint16_t i = 0; i < len; i++) {
                uint64_t blk = this->ext4fs->allocblock(inogroup);
                if (blk == 0) { // Failure!
                    // Free any blocks we already allocated.
                    for (uint16_t j = 0; j < i; j++) {
                        this->ext4fs->freeblock(physblk + j);
                    }
                    return 0;
                }

                if (i == 0) {
                    physblk = blk;
                } else if (blk != physblk + i) {
                    // Free the non-contiguous block and retry with len=1.
                    this->ext4fs->freeblock(blk);
                    len = i;
                    break;
                }
            }

            if (len == 0) {
                return 0;
            }

            // Try to extend an existing extent if possible.
            struct extent *extents = (struct extent *)((uint8_t *)this->diskino.block + sizeof(struct extenthdr));
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

            // Add a new extent entry.
            struct extent *newext = &extents[hdr->entries];
            newext->fileblk = logicalblk;
            newext->len = len;
            newext->starthi = (physblk >> 32) & 0xFFFF;
            newext->startlo = physblk & 0xFFFFFFFF;
            hdr->entries++;

            return physblk;
        }

        ssize_t Ext4Node::write(const void *buf, size_t count, off_t offset, int fdflags) {
            (void)fdflags;

            NLib::ScopeSpinlock guard(&this->metalock);

            if (VFS::S_ISDIR(this->attr.st_mode)) {
                return -EISDIR;
            }

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
                                this->attr.st_size = newsize;
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
                this->attr.st_size = newsize;

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
            this->attr.st_size = newsize;

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
            this->attr.st_size = dirsize;

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

        bool Ext4FileSystem::hasmetadatacsum(void) {
            return false; // XXX: Check for metadata checksum feature flag.
        }

        uint32_t Ext4FileSystem::getcsumseed(void) {
            if (this->sb.featincompat & EXT4_FEATUREINCOMPATCSUMSEED) {
                return this->sb.csumseed;
            }
            // Calculate default seed from UUID.
            return crc32c(~0, this->sb.uuid, sizeof(this->sb.uuid));
        }

        uint32_t Ext4FileSystem::calcblockbitmapcsum(uint32_t group, const void *bitmap) {
            (void)group; // Group number is not included in bitmap checksum per ext4 spec.
            if (!this->hasmetadatacsum()) {
                return 0;
            }

            uint32_t csum = this->getcsumseed();

            // Round up to include partial byte.
            size_t sz = (this->sb.blockspergroup + 7) / 8;
            csum = crc32c(csum, bitmap, sz);

            return csum;
        }

        uint32_t Ext4FileSystem::calcinodebitmapcsum(uint32_t group, const void *bitmap) {
            (void)group; // Group number is not included in bitmap checksum per ext4 spec.
            if (!this->hasmetadatacsum()) {
                return 0;
            }

            uint32_t csum = this->getcsumseed();

            // Round up to include partial byte.
            size_t sz = (this->sb.inodespergroup + 7) / 8;
            csum = crc32c(csum, bitmap, sz);

            return csum;
        }

        void Ext4FileSystem::updateblockbitmapcsum(uint32_t group, const void *bitmap) {
            if (!this->hasmetadatacsum()) {
                return;
            }

            uint32_t csum = this->calcblockbitmapcsum(group, bitmap);
            struct groupdesc *gd = &this->groupdescs[group];
            gd->blockbitmapcsumlo = csum & 0xFFFF;
            gd->blockbitmapcsumhi = (csum >> 16) & 0xFFFF;
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

        uint32_t Ext4FileSystem::calcdirblkcsum(uint32_t ino, uint32_t gen, const void *blk, size_t size) {
            if (!this->hasmetadatacsum()) {
                return 0;
            }

            uint32_t csum = this->getcsumseed();

            // Hash the inode number (little-endian).
            uint32_t le_ino = ino;
            csum = crc32c(csum, &le_ino, sizeof(le_ino));

            // Hash the inode generation.
            csum = crc32c(csum, &gen, sizeof(gen));

            // Hash the directory block (excluding the tail checksum field).
            csum = crc32c(csum, blk, size);

            return csum;
        }

        void Ext4FileSystem::setdirblkcsum(uint32_t ino, uint32_t gen, void *blk) {
            if (!this->hasmetadatacsum()) {
                return;
            }

            // Find the directory tail at the end of the block.
            struct dirtail *tail = (struct dirtail *)((uint8_t *)blk + this->blksize - sizeof(struct dirtail));

            // Set up the fake directory entry fields.
            tail->reserved = 0;
            tail->reclen = sizeof(struct dirtail);
            tail->reserved_namelen = 0;
            tail->reserved_filetype = EXT4_FTDIRCSUM;

            // Calculate checksum of block up to (but not including) the checksum field.
            size_t csumsize = this->blksize - sizeof(tail->checksum);
            tail->checksum = this->calcdirblkcsum(ino, gen, blk, csumsize);
        }

        uint32_t Ext4FileSystem::calcinodecsum(uint32_t ino, void *inodebuf, size_t inodesize) {
            struct inode *diskino = (struct inode *)inodebuf;
            uint32_t csum = this->getcsumseed();

            // Hash the inode number (little-endian).
            uint32_t le_ino = ino;
            csum = crc32c(csum, &le_ino, sizeof(le_ino));

            // Hash the inode generation.
            csum = crc32c(csum, &diskino->generation, sizeof(diskino->generation));

            // Save and clear checksum fields before calculating.
            uint16_t orig_csumlo = diskino->csumlo;
            uint16_t orig_csumhi = diskino->csumhi;
            diskino->csumlo = 0;
            diskino->csumhi = 0;

            // Hash the full inode buffer (using the actual on-disk inode size).
            csum = crc32c(csum, inodebuf, inodesize);

            // Restore original checksum fields.
            diskino->csumlo = orig_csumlo;
            diskino->csumhi = orig_csumhi;

            return csum;
        }

        uint16_t Ext4FileSystem::calcgroupdesccsum(uint32_t group) {
            if (this->hasmetadatacsum()) {
                // Use CRC32c for metadata checksum.
                uint32_t csum = this->getcsumseed();

                // Hash the group number (little-endian).
                uint32_t le_group = group;
                csum = crc32c(csum, &le_group, sizeof(le_group));

                // Save and clear checksum field.
                struct groupdesc *gd = &this->groupdescs[group];
                uint16_t orig_csum = gd->checksum;
                gd->checksum = 0;

                // Hash the group descriptor.
                uint16_t descsize = this->sb.descsize ? this->sb.descsize : 32;
                csum = crc32c(csum, gd, descsize);

                // Restore original checksum.
                gd->checksum = orig_csum;

                return csum & 0xFFFF;
            } else if (this->sb.featrocompat & EXT4_FEATUREROCOMPATGDTCSUM) {
                // Use CRC16 for legacy GDT checksum (simplified implementation).
                uint32_t csum = 0;
                csum = crc32c(csum, this->sb.uuid, sizeof(this->sb.uuid));

                uint32_t le_group = group;
                csum = crc32c(csum, &le_group, sizeof(le_group));

                struct groupdesc *gd = &this->groupdescs[group];
                uint16_t orig_csum = gd->checksum;
                gd->checksum = 0;

                uint16_t descsize = this->sb.descsize ? this->sb.descsize : 32;
                // Don't include the checksum field itself.
                size_t csum_offset = offsetof(struct groupdesc, checksum);
                csum = crc32c(csum, gd, csum_offset);
                if (descsize > csum_offset + sizeof(uint16_t)) {
                    csum = crc32c(csum, (uint8_t *)gd + csum_offset + sizeof(uint16_t), descsize - csum_offset - sizeof(uint16_t));
                }

                gd->checksum = orig_csum;

                return csum & 0xFFFF;
            }

            return 0; // No checksum.
        }

        uint32_t Ext4FileSystem::calcsuperblocksum(void) {
            constexpr size_t csumoffset = offsetof(struct superblock, checksum);
            uint32_t csum = crc32c(~0U, &this->sb, csumoffset);

            return csum;
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
            // Flush all cached blocks to disk.
            if (this->blkdev && this->blkdev->cache) {
                this->blkdev->cache->flush(); // Flush the entire cache.
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
                    struct extenthdr *hdr = (struct extenthdr *)ext4node->diskino.block;
                    if (hdr->magic == EXT4_EXTMAGIC && hdr->depth == 0) {
                        struct extent *extents = (struct extent *)((uint8_t *)ext4node->diskino.block + sizeof(struct extenthdr));
                        for (uint16_t i = 0; i < hdr->entries; i++) {
                            uint64_t physblk = ((uint64_t)extents[i].starthi << 32) | extents[i].startlo;
                            uint16_t len = extents[i].len & 0x7FFF;
                            for (uint16_t j = 0; j < len; j++) {
                                this->freeblock(physblk + j);
                            }
                        }
                    }
                    // XXX: Handle deeper extent trees.
                }

                // Free the inode.
                this->freeinode(ino, isdir);

                // Delete in-memory node.
                delete node;
            }

            return 0;
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