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

                ssize_t write(const void *buf, size_t count, off_t offset, int fdflags) override {
                    (void)buf;
                    (void)count;
                    (void)offset;
                    (void)fdflags;
                    return -EROFS;
                }

                // Read directory entries.
                ssize_t readdir(void *buf, size_t count, off_t offset) override;

                // Read symbolic link target.
                ssize_t readlink(char *buf, size_t bufsiz) override;

                // Lookup a child node by name.
                VFS::INode *lookup(const char *name) override;

                // Read-only filesystem - modifications not supported.
                bool add(VFS::INode *node) override {
                    (void)node;
                    return false;
                }
                bool remove(const char *name) override {
                    (void)name;
                    return false;
                }

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

                int mount(const char *src, const char *path, VFS::INode *mntnode, uint64_t flags, const void *data) override;

                int umount(int flags) override {
                    (void)flags;
                    this->mounted = false;
                    // Delete root node; its destructor will cascade and free all cached child nodes.
                    if (this->root) {
                        delete this->root;
                        this->root = NULL;
                    }
                    return 0;
                }

                int sync(void) override {
                    return 0;
                }

                ssize_t create(const char *name, VFS::INode **nodeout, struct VFS::stat attr) override {
                    (void)name;
                    (void)nodeout;
                    (void)attr;
                    return -EROFS;
                }

                int unlink(VFS::INode *node, VFS::INode *parent) override {
                    (void)node;
                    (void)parent;
                    return -EROFS;
                }
        };
    }
}

#endif