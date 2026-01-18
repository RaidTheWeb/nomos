#ifndef _FS__EXT4__EXT4FS_HPP
#define _FS__EXT4__EXT4FS_HPP

#include <dev/block.hpp>
#include <fs/vfs.hpp>
#include <lib/errno.hpp>
#include <lib/string.hpp>
#include <mm/pagecache.hpp>
#include <std/stddef.h>

namespace NFS {
    namespace Ext4FS {

        // Forward declaration.
        class Ext4FileSystem;

        // Extent magic number.
        #define EXT4_EXTMAGIC 0xF30A

        // Root inode number.
        #define EXT4_ROOTINO 2

        // Extent cache entry for avoiding repeated extent tree traversals (lame and dumb).
        struct extentcacheentry {
            uint64_t logicalstart;      // First logical block in extent.
            uint64_t physstart;         // First physical block in extent.
            uint32_t len;               // Number of blocks in extent.
            bool valid;                 // Entry is valid.
        };

        class Ext4Node : public VFS::INode {
            private:
                NLib::HashMap<Ext4Node *> children; // Track loaded child inodes for cleanup.

                // Extent cache for recent lookups (simple LRU-ish).
                static constexpr size_t EXTENT_CACHESIZE = 4;
                struct extentcacheentry extentcache[EXTENT_CACHESIZE] = {};
                size_t extentcacheidx = 0; // Round-robin insertion index.
                NArch::IRQSpinlock extentcachelock; // Protects extent cache access.
            public:
                Ext4FileSystem *ext4fs; // Owning filesystem (typed).
                struct inode diskino; // On-disk inode structure.

                Ext4Node(Ext4FileSystem *fs, const char *name, struct VFS::stat attr, struct inode *diskino);

                ~Ext4Node(void) {
                    delete this->name;

                    // Free all cached child nodes.
                    NLib::HashMap<Ext4Node *>::Iterator it = this->children.begin();
                    while (it.valid()) {
                        delete *it.value(); // Free child node.
                        it.next();
                    }
                }

                // Add a child node to the children cache.
                void _addchild(Ext4Node *child) {
                    this->children.insert(child->getname(), child);
                }

                // Remove a child node from the children cache (does not delete).
                void _removechild(const char *name) {
                    this->children.remove(name);
                }

                // Map a logical file block to a physical disk block.
                uint64_t getphysblock(uint64_t logicalblk);

                // Map a logical file block to physical block and return contiguous run length.
                uint64_t getextentrun(uint64_t logicalblk, uint64_t *runlen);

                // Extent cache helpers.
                bool lookupcachedextent(uint64_t logicalblk, uint64_t *physblk, uint64_t *runlen);
                void cacheextent(uint64_t logicalstart, uint64_t physstart, uint32_t len);
                void invalidateextentcache(void);

                // Read indirect block pointer for legacy (non-extent) inodes.
                uint64_t getindirectblock(uint64_t logicalblk);

                // Read file data using extent mapping.
                ssize_t read(void *buf, size_t count, off_t offset, int fdflags) override;

                ssize_t write(const void *buf, size_t count, off_t offset, int fdflags) override;

                // Truncate file to specified length.
                int truncate(off_t length) override;

                // Allocate a new extent for the file.
                uint64_t allocextent(uint64_t logicalblk, uint16_t len);

                // Allocate a block via indirect block mapping (legacy inodes).
                uint64_t allocindirect(uint64_t logicalblk);

                // Grow extent tree from depth 0 to depth 1.
                bool growextenttree(void);

                // Find the leaf block for a logical block in a deep extent tree.
                uint64_t findextentleaf(uint64_t logicalblk, uint8_t **leafbufout);

                // Allocate an extent in a deep extent tree (depth >= 1).
                uint64_t allocextentdeep(uint64_t logicalblk, uint16_t len, uint64_t physblk);

                // Update inode timestamps.
                void touchtime(bool mtime, bool ctime, bool atime);

                // Write the inode back to disk.
                int writeback(void);

                // Update timestamps and write inode back. NOTE: Only use when caller doesn't hold metalock.
                int commitmetadata(bool mtime, bool ctime, bool atime);

                // Read directory entries.
                ssize_t readdir(void *buf, size_t count, off_t offset) override;

                // Read symbolic link target.
                ssize_t readlink(char *buf, size_t bufsiz) override;

                // Lookup a child node by name.
                VFS::INode *lookup(const char *name) override;

                // Add a child node to this directory (on disk).
                bool add(VFS::INode *node) override;

                // Remove a child node from this directory (on disk).
                bool remove(const char *name) override;

                // Check if directory is empty.
                bool empty(void) override;

                // Resolve symbolic link to target node.
                VFS::INode *resolvesymlink(void) override;

                // Set symlink target data with inline symlink support.
                ssize_t setsymlinkdata(const char *target, size_t len) override;

                // Poll for events on this node.
                int poll(short events, short *revents, int fdflags) override {
                    (void)fdflags;
                    short mask = 0;

                    // Regular files are always ready for read/write.
                    if (events & VFS::POLLIN) {
                        mask |= VFS::POLLIN;
                    }
                    if (events & VFS::POLLOUT) {
                        mask |= VFS::POLLOUT;
                    }
                    if (events & VFS::POLLRDNORM) {
                        mask |= VFS::POLLRDNORM;
                    }
                    if (events & VFS::POLLWRNORM) {
                        mask |= VFS::POLLWRNORM;
                    }

                    *revents = mask;
                    return 0;
                }

                // Sync file data and metadata to disk.
                int sync(enum VFS::INode::syncmode mode) override;

                // Read a page from disk into the page cache.
                int readpage(NMem::CachePage *page) override;

                // Write a page from page cache to disk.
                int writepage(NMem::CachePage *page) override;

                // Write multiple contiguous pages to disk in a single I/O.
                int writepages(NMem::CachePage **pages, size_t count) override;

                // Get the backing block device for async readahead.
                NDev::BlockDevice *getblockdevice(void) override;

                // Map a page offset to device LBA for async readahead.
                uint64_t getpagelba(off_t pageoffset) override;

                // Map a page offset to device LBA using only cached extents (non-blocking).
                uint64_t getpagelbacached(off_t pageoffset, bool *needsio) override;
        };

        class Ext4FileSystem : public VFS::IFileSystem {
            public:
                struct superblock sb; // Superblock structure.
                NDev::BlockDevice *blkdev; // Underlying block device.
                struct groupdesc *groupdescs; // Block group descriptor table.
                uint32_t numgroups; // Number of block groups.
                uint32_t blksize; // Block size in bytes.
                uint32_t csumseed; // Checksum seed for metadata checksums.
                uint16_t inodesize; // On-disk inode size.
                bool readonly; // Mounted read-only due to unsupported RO_COMPAT features.
                bool haschecksums; // Filesystem has metadata checksums enabled.

                Ext4FileSystem(VFS::VFS *vfs) {
                    this->vfs = vfs;
                    this->blkdev = NULL;
                    this->groupdescs = NULL;
                    this->numgroups = 0;
                    this->blksize = 0;
                    this->csumseed = 0;
                    this->inodesize = 128;
                    this->readonly = false;
                    this->haschecksums = false;
                    this->root = NULL; // Will be set in mount().
                }

                ~Ext4FileSystem() {
                    if (this->groupdescs) {
                        delete[] this->groupdescs;
                    }
                }

                static VFS::IFileSystem *instance(VFS::VFS *vfs) {
                    return new Ext4FileSystem(vfs);
                }

                // Load an inode from disk by inode number.
                Ext4Node *loadinode(uint32_t ino, const char *name);

                // Read a block from the filesystem.
                ssize_t readblock(uint64_t blknum, void *buf);

                // Write a block to the filesystem.
                ssize_t writeblock(uint64_t blknum, const void *buf);

                // Write an inode back to disk.
                int writeinode(uint32_t ino, struct inode *diskino);

                // Write the superblock back to disk.
                int writesuperblock(void);

                // Write a group descriptor back to disk.
                int writegroupdesc(uint32_t group);

                // Count free blocks in a bitmap.
                uint32_t countfreeblocks(uint32_t group, const void *bitmap);

                // Count free inodes in a bitmap.
                uint32_t countfreeinodes(uint32_t group, const void *bitmap);

                // Set padding bits in inode bitmap (bits beyond inodespergroup).
                void setinodebitmappadding(void *bitmap);

                // Set padding bits in block bitmap (bits beyond blockspergroup).
                void setblockbitmappadding(void *bitmap);

                // Allocate a block from a specific block group.
                uint64_t allocblock(uint32_t prefgroup = 0);

                // Allocate multiple contiguous blocks from a specific block group.
                uint64_t allocblocks(uint32_t prefgroup, uint32_t count, uint32_t *allocated);

                // Free a previously allocated block.
                int freeblock(uint64_t blknum);

                // Free all blocks in an extent tree recursively.
                void freeextentblocks(uint32_t *node, uint64_t blknum);

                // Free all blocks referenced by indirect block pointers.
                void freeindirectblocks(struct inode *diskino);

                // Allocate an inode from a specific block group.
                uint32_t allocinode(uint32_t prefgroup = 0, bool isdir = false);

                // Free a previously allocated inode.
                int freeinode(uint32_t ino, bool isdir = false);

                // Compute checksum seed from UUID (if CSUM_SEED feature not present).
                void computecsumseed(void);

                // Compute superblock checksum.
                uint32_t sbchecksum(void);

                // Compute group descriptor checksum.
                uint16_t gdchecksum(uint32_t group, struct groupdesc *gd);

                // Compute inode checksum.
                uint32_t inodechecksum(uint32_t ino, struct inode *diskino);

                // Compute directory block checksum.
                uint32_t dirblockchecksum(uint32_t ino, uint32_t gen, void *block, size_t len);

                // Check if filesystem has HUGE_FILE feature.
                bool hugefile(void) const {
                    return this->sb.featrocompat & EXT4_FEATUREROCOMPATHUGEFILE;
                }

                int mount(const char *src, const char *path, VFS::INode *mntnode, uint64_t flags, const void *data) override;

                int umount(int flags) override;

                int sync(void) override;

                ssize_t create(const char *name, VFS::INode **nodeout, struct VFS::stat attr) override;

                int unlink(VFS::INode *node, VFS::INode *parent) override;

                int rename(VFS::INode *oldparent, VFS::INode *node, VFS::INode *newparent, const char *newname, VFS::INode *target) override;
        };
    }
}

#endif