#ifndef _FS__EXT4__EXT4FS_HPP
#define _FS__EXT4__EXT4FS_HPP

#include <dev/block.hpp>
#include <fs/vfs.hpp>
#include <lib/errno.hpp>
#include <lib/string.hpp>
#include <std/stddef.h>

namespace NFS {
    namespace Ext4FS {

        // Forward declaration.
        class Ext4FileSystem;

        // Inode flags.
        #define EXT4_EXTENTSFL 0x00080000 // Inode uses extents.
        #define EXT4_INLINEDATAFL 0x10000000 // Inode has inline data.

        // Extent magic number.
        #define EXT4_EXTMAGIC 0xF30A

        // Root inode number.
        #define EXT4_ROOTINO 2

        class Ext4Node : public VFS::INode {
            private:
                NLib::HashMap<Ext4Node *> children; // Track loaded child inodes for cleanup.
            public:
                Ext4FileSystem *ext4fs; // Owning filesystem (typed).
                struct inode diskino; // On-disk inode structure.

                Ext4Node(Ext4FileSystem *fs, const char *name, struct VFS::stat attr, struct inode *diskino);

                ~Ext4Node(void) {
                    NUtil::printf("[fs/ext4fs]: Deleting node '%s'\n", this->name);
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

                // Map a logical file block to a physical disk block.
                uint64_t getphysblock(uint64_t logicalblk);

                // Read file data using extent mapping.
                ssize_t read(void *buf, size_t count, off_t offset, int fdflags) override;

                ssize_t write(const void *buf, size_t count, off_t offset, int fdflags) override;

                // Truncate file to specified length.
                int truncate(off_t length) override;

                // Allocate a new extent for the file.
                uint64_t allocextent(uint64_t logicalblk, uint16_t len);

                // Update inode timestamps.
                void touchtime(bool mtime, bool ctime, bool atime);

                // Write the inode back to disk.
                int writeback(void);

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
        };

        class Ext4FileSystem : public VFS::IFileSystem {
            public:
                struct superblock sb; // Superblock structure.
                NDev::BlockDevice *blkdev; // Underlying block device.
                struct groupdesc *groupdescs; // Block group descriptor table.
                uint32_t numgroups; // Number of block groups.
                uint32_t blksize; // Block size in bytes.

                Ext4FileSystem(VFS::VFS *vfs) {
                    this->vfs = vfs;
                    this->blkdev = NULL;
                    this->groupdescs = NULL;
                    this->numgroups = 0;
                    this->blksize = 0;
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

                // Calculate inode checksum over a full inode buffer.
                uint32_t calcinodecsum(uint32_t ino, void *inodebuf, size_t inodesize);

                // Calculate group descriptor checksum.
                uint16_t calcgroupdesccsum(uint32_t group);

                // Calculate superblock checksum.
                uint32_t calcsuperblocksum(void);

                // Check if metadata checksums are enabled.
                bool hasmetadatacsum(void);

                // Get checksum seed (computed or from superblock).
                uint32_t getcsumseed(void);

                // Calculate block bitmap checksum.
                uint32_t calcblockbitmapcsum(uint32_t group, const void *bitmap);

                // Calculate inode bitmap checksum.
                uint32_t calcinodebitmapcsum(uint32_t group, const void *bitmap);

                // Update block bitmap checksum in group descriptor.
                void updateblockbitmapcsum(uint32_t group, const void *bitmap);

                // Update inode bitmap checksum in group descriptor.
                void updateinodebitmapcsum(uint32_t group, const void *bitmap);

                // Count free blocks in a bitmap.
                uint32_t countfreeblocks(uint32_t group, const void *bitmap);

                // Count free inodes in a bitmap.
                uint32_t countfreeinodes(uint32_t group, const void *bitmap);

                // Set padding bits in inode bitmap (bits beyond inodespergroup).
                void setinodebitmappadding(void *bitmap);

                // Set padding bits in block bitmap (bits beyond blockspergroup).
                void setblockbitmappadding(void *bitmap);

                // Calculate directory block checksum.
                uint32_t calcdirblkcsum(uint32_t ino, uint32_t gen, const void *blk, size_t size);

                // Set directory block checksum in the block's tail.
                void setdirblkcsum(uint32_t ino, uint32_t gen, void *blk);

                // Allocate a block from a specific block group.
                uint64_t allocblock(uint32_t prefgroup = 0);

                // Free a previously allocated block.
                int freeblock(uint64_t blknum);

                // Allocate an inode from a specific block group.
                uint32_t allocinode(uint32_t prefgroup = 0, bool isdir = false);

                // Free a previously allocated inode.
                int freeinode(uint32_t ino, bool isdir = false);

                int mount(const char *src, const char *path, VFS::INode *mntnode, uint64_t flags, const void *data) override;

                int umount(int flags) override;

                int sync(void) override;

                ssize_t create(const char *name, VFS::INode **nodeout, struct VFS::stat attr) override;

                int unlink(VFS::INode *node, VFS::INode *parent) override;
        };
    }
}

#endif