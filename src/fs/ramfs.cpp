#ifdef __x86_64__
#include <arch/x86_64/cpu.hpp>
#endif

#include <fs/ramfs.hpp>
#include <lib/errno.hpp>
#include <fs/pipefs.hpp>
#include <mm/pagecache.hpp>
#include <mm/ucopy.hpp>
#include <mm/vmalloc.hpp>

namespace NFS {
    namespace RAMFS {
        RAMNode::RAMNode(VFS::IFileSystem *fs, const char *name, struct VFS::stat attr) : VFS::INode(fs, name, attr) {
            if (VFS::S_ISFIFO(attr.st_mode)) { // Named pipe (FIFO) special handling.
                // Set redirect so that operations on this FIFO node are redirected to a PipeNode in PipeFS.
                // XXX: Consider a different approach later on: potentially, only create the PipeNode when the FIFO is opened for the first time?
                this->redirect = new PipeFS::PipeNode(PipeFS::pipefs, name, attr, true);
            }
        }

        int RAMNode::poll(short events, short *revents, int fdflags) {
            (void)fdflags;
            NLib::ScopeIRQSpinlock guard(&this->metalock);

            *revents = 0;

            if (events & VFS::POLLIN) {
                if (this->attr.st_size > 0) {
                    // Data is available to read.
                    *revents |= VFS::POLLIN;
                }
            }

            if (events & VFS::POLLOUT) {
                *revents |= VFS::POLLOUT; // Always writable.
            }

            return 0;
        }

        ssize_t RAMNode::read(void *buf, size_t count, off_t offset, int fdflags) {
            (void)fdflags;
            assert(buf, "Reading into invalid buffer.\n");
            assert(count, "Invalid count.\n");

            this->metalock.acquire();
            off_t fsize = this->attr.st_size;
            this->metalock.release();

            this->datalock.acquire();

            if (offset >= fsize) {
                this->datalock.release();
                return 0;
            }
            if ((off_t)(offset + count) > fsize) {
                count = fsize - offset;
            }

            if (NMem::UserCopy::iskernel(buf, count)) {
                NLib::memcpy((uint8_t *)buf, this->data + offset, count);
            } else {
                ssize_t ret = NMem::UserCopy::copyto(buf, this->data + offset, count);
                if (ret < 0) {
                    this->datalock.release();
                    return ret;
                }
            }
            this->datalock.release();
            return count;
        }

        ssize_t RAMNode::write(const void *buf, size_t count, off_t offset, int fdflags) {
            (void)fdflags;

            off_t requiredsize = offset + count;
            uint8_t *newdata = NULL;

            this->datalock.acquire();

            // XXX: Growing really big deadlocks the system, probably due to memory exhaustion.
            if (requiredsize > this->attr.st_size) {
                uint8_t *olddata = this->data;
                off_t oldsize = this->attr.st_size;

                // Release lock before allocation to prevent deadlock.
                this->datalock.release();


                newdata = (uint8_t *)NMem::allocator.realloc(olddata, requiredsize);
                if (!newdata) {
                    // Allocation failed, but we must not corrupt state.
                    return -ENOMEM;
                }

                // Re-acquire lock and check if someone else resized the file.
                this->datalock.acquire();

                if (this->data != olddata || this->attr.st_size != oldsize) {
                    this->datalock.release();
                    NMem::allocator.free(newdata);
                    return this->write(buf, count, offset, fdflags); // Retry.
                }

                // Commit the reallocation.
                this->data = newdata;
                this->attr.st_size = requiredsize;
                this->attr.st_blocks = (this->attr.st_size + this->attr.st_blksize - 1) / this->attr.st_blksize;
            }

            if (NMem::UserCopy::iskernel((void *)buf, count)) {
                NLib::memcpy(this->data + offset, (void *)buf, count);
            } else {
                ssize_t ret = NMem::UserCopy::copyfrom(this->data + offset, (const void *)buf, count);
                if (ret < 0) {
                    this->datalock.release();
                    return ret;
                }
            }
            this->datalock.release();

            // Invalidate cached pages so mmap mappings see the new data.
            // XXX: I reckon this could be smarter by invalidating the *relevant* pages, but this works for now. Not exactly performant though...
            if (NMem::pagecache) {
                NMem::pagecache->invalidateinode(this);
            }

            return count;
        }

        int RAMNode::truncate(off_t length) {
            if (length < 0) {
                return -EINVAL;
            }

            if (length == 0) {
                this->datalock.acquire();
                if (this->data != NULL) {
                    uint8_t *olddata = this->data;
                    this->data = NULL;
                    this->attr.st_size = 0;
                    this->attr.st_blocks = 0;
                    this->datalock.release();
                    // Free outside of lock to avoid deadlock.
                    NMem::allocator.free(olddata);
                } else {
                    this->attr.st_size = 0;
                    this->attr.st_blocks = 0;
                    this->datalock.release();
                }

                // Invalidate cached pages so mmap mappings see the truncated state.
                if (NMem::pagecache) {
                    NMem::pagecache->invalidateinode(this);
                }

                return 0;
            }

            // For growing truncate, allocate outside of lock to avoid deadlock.
            this->datalock.acquire();
            uint8_t *olddata = this->data;
            off_t oldsize = this->attr.st_size;
            this->datalock.release();

            uint8_t *newdata = (uint8_t *)NMem::allocator.realloc(olddata, length);
            if (!newdata) {
                return -ENOMEM;
            }

            // Re-acquire lock and verify state hasn't changed.
            this->datalock.acquire();
            if (this->data != olddata || this->attr.st_size != oldsize) {
                // State changed while we released lock, retry.
                this->datalock.release();
                NMem::allocator.free(newdata);
                return this->truncate(length);
            }

            this->data = newdata;
            this->attr.st_size = length;
            this->attr.st_blocks = (this->attr.st_size + this->attr.st_blksize - 1) / this->attr.st_blksize;

            this->datalock.release();

            // Invalidate cached pages so mmap mappings see the truncated state.
            if (NMem::pagecache) {
                NMem::pagecache->invalidateinode(this);
            }

            return 0;
        }

        // Read a page from the ramfs internal buffer into a cache page.
        int RAMNode::readpage(NMem::CachePage *page) {
            if (!page) {
                return -EINVAL;
            }

            off_t offset = page->offset;
            void *dest = page->data();

            // Zero the entire page first.
            NLib::memset(dest, 0, NArch::PAGESIZE);

            this->datalock.acquire();

            // Check if offset is within file bounds.
            if (offset >= this->attr.st_size) {
                this->datalock.release();
                page->setflag(NMem::PAGE_UPTODATE);
                return 0;
            }

            // Calculate how much to copy.
            size_t tocopy = NArch::PAGESIZE;
            if ((off_t)(offset + tocopy) > this->attr.st_size) {
                tocopy = this->attr.st_size - offset;
            }

            // Copy data from internal buffer to cache page.
            if (this->data && tocopy > 0) {
                NLib::memcpy(dest, this->data + offset, tocopy);
            }

            this->datalock.release();
            page->setflag(NMem::PAGE_UPTODATE);
            return 0;
        }

        // Write a dirty cache page back to the ramfs internal buffer.
        int RAMNode::writepage(NMem::CachePage *page) {
            if (!page) {
                return -EINVAL;
            }

            off_t offset = page->offset;
            void *src = page->data();

            // Check if we need to grow the file.
            off_t newend = offset + NArch::PAGESIZE;

            this->datalock.acquire();

            if (newend > this->attr.st_size) {
                uint8_t *olddata = this->data;
                off_t oldsize = this->attr.st_size;
                this->datalock.release();

                uint8_t *newdata = (uint8_t *)NMem::allocator.realloc(olddata, newend);
                if (!newdata) {
                    return -ENOMEM;
                }

                // Re-acquire lock and verify state.
                this->datalock.acquire();
                if (this->data != olddata || this->attr.st_size != oldsize) {
                    // State changed, free our allocation and retry.
                    this->datalock.release();
                    NMem::allocator.free(newdata);
                    return this->writepage(page);
                }

                this->data = newdata;
                this->attr.st_size = newend;
                this->attr.st_blocks = (this->attr.st_size + this->attr.st_blksize - 1) / this->attr.st_blksize;
            }

            // Copy data from cache page to internal buffer.
            size_t tocopy = NArch::PAGESIZE;
            if ((off_t)(offset + tocopy) > this->attr.st_size) {
                tocopy = this->attr.st_size - offset;
            }

            if (tocopy > 0) {
                NLib::memcpy(this->data + offset, src, tocopy);
            }

            this->datalock.release();
            page->clearflag(NMem::PAGE_DIRTY);
            return 0;
        }

        ssize_t RAMNode::readlink(char *buf, size_t bufsiz) {
            this->datalock.acquire();

            if (!VFS::S_ISLNK(this->attr.st_mode)) {
                this->datalock.release();
                return -EINVAL;
            }

            size_t tocopy = this->attr.st_size;
            if (bufsiz < tocopy) {
                tocopy = bufsiz;
            }

            ssize_t ret = NMem::UserCopy::copyto(buf, this->data, tocopy);
            this->datalock.release();
            if (ret < 0) {
                return ret;
            }
            return tocopy;
        }

        ssize_t RAMNode::readdir(void *buf, size_t count, off_t offset) {
            NLib::ScopeIRQSpinlock guard(&this->metalock);

            if (!VFS::S_ISDIR(this->attr.st_mode)) {
                return -ENOTDIR;
            }

            size_t bytesread = 0;
            size_t curroffset = 0;
            size_t reclen = sizeof(struct VFS::dirent);

            // Add "." entry.
            if (curroffset >= (size_t)offset) {
                if (bytesread + reclen > count) {
                    return bytesread;
                }
                struct VFS::dirent *dentry = (struct VFS::dirent *)((uint8_t *)buf + bytesread);

                struct VFS::dirent kdentry;
                kdentry.d_ino = this->attr.st_ino;
                kdentry.d_off = bytesread + reclen;
                kdentry.d_reclen = (uint16_t)reclen;
                kdentry.d_type = VFS::S_IFDIR >> 12;
                NLib::memset(kdentry.d_name, 0, sizeof(kdentry.d_name));
                kdentry.d_name[0] = '.';

                int ret = NMem::UserCopy::copyto(dentry, &kdentry, sizeof(struct VFS::dirent));
                if (ret < 0) {
                    return ret;
                }
                bytesread += reclen;
            }
            curroffset += reclen;

            // Add ".." entry.
            if (curroffset >= (size_t)offset) {
                if (bytesread + reclen > count) {
                    return bytesread;
                }
                struct VFS::dirent *dentry = (struct VFS::dirent *)((uint8_t *)buf + bytesread);
                struct VFS::dirent kdentry;

                INode *root = this->fs->getroot();
                if (root == this) {
                    kdentry.d_ino = this->attr.st_ino; // Parent of root is root.
                } else if (this->parent) {
                    kdentry.d_ino = this->parent->getattr().st_ino;
                } else {
                    kdentry.d_ino = 0; // No parent.
                }
                root->unref();

                kdentry.d_off = bytesread + reclen;
                kdentry.d_reclen = (uint16_t)reclen;
                kdentry.d_type = VFS::S_IFDIR >> 12;
                NLib::memset(kdentry.d_name, 0, sizeof(kdentry.d_name));
                kdentry.d_name[0] = '.';
                kdentry.d_name[1] = '.';

                int ret = NMem::UserCopy::copyto(dentry, &kdentry, sizeof(struct VFS::dirent));
                if (ret < 0) {
                    return ret;
                }

                bytesread += reclen;
            }
            curroffset += reclen;

            // Add regular entries:
            NLib::HashMap<RAMNode *>::Iterator it = this->children.begin();
            while (it.valid()) {
                RAMNode *child = *it.value();
                if (curroffset >= (size_t)offset) {
                    if (bytesread + reclen > count) {
                        break; // No more space.
                    }

                    struct VFS::dirent *dentry = (struct VFS::dirent *)((uint8_t *)buf + bytesread);
                    struct VFS::dirent kdentry;

                    kdentry.d_ino = child->attr.st_ino;
                    kdentry.d_off = bytesread + reclen;
                    kdentry.d_reclen = (uint16_t)reclen;
                    kdentry.d_type = (child->attr.st_mode & VFS::S_IFMT) >> 12; // File type is stored in the high bits of st_mode.
                    NLib::memset(kdentry.d_name, 0, sizeof(kdentry.d_name));
                    NLib::strncpy(kdentry.d_name, (char *)child->getname(), sizeof(kdentry.d_name) - 1);

                    int ret = NMem::UserCopy::copyto(dentry, &kdentry, sizeof(struct VFS::dirent));
                    if (ret < 0) {
                        return ret;
                    }

                    bytesread += reclen;
                }
                curroffset += reclen;
                it.next();
            }

            return bytesread;
        }

        VFS::INode *RAMNode::resolvesymlink(void) {
            this->datalock.acquire();

            if (!VFS::S_ISLNK(this->attr.st_mode)) {
                this->datalock.release();
                return NULL; // Non-symbolic links cannot resolve to node.
            }

            if (!this->attr.st_size) {
                this->datalock.release();
                return NULL; // Resolving empty symbolic link.
            }

            // Create a null-terminated copy of the symlink target.
            size_t linklen = this->attr.st_size;
            char *linktarget = new char[linklen + 1];
            if (!linktarget) {
                this->datalock.release();
                return NULL;
            }
            NLib::memcpy(linktarget, this->data, linklen);
            linktarget[linklen] = '\0';

            VFS::VFS *vfs = this->fs->getvfs();

            // Attempt to resolve the node our data points to. Uses normal resolution function, but it doesn't attempt to resolve symbolic links (we don't want any crazy recursion).
            VFS::INode *node = NULL;
            ssize_t res = vfs->resolve(linktarget, &node, this->getparent(), false);
            this->datalock.release();
            delete[] linktarget;
            if (res < 0) {
                return NULL;
            }
            return node;
        }

        VFS::INode *RAMNode::lookup(const char *name) {
            NLib::ScopeIRQSpinlock guard(&this->metalock);

            if (!VFS::S_ISDIR(this->attr.st_mode)) {
                return NULL; // Non-directories possess no children.
            }

            RAMNode **node = this->children.find(name);
            if (node) {
                (*node)->ref();
                return (*node);
            }

            return NULL;
        }

        bool RAMNode::add(VFS::INode *node) {
            NLib::ScopeIRQSpinlock guard(&this->metalock);

            if (!VFS::S_ISDIR(this->attr.st_mode)) {
                return false; // Non-directories possess no children.
            }

            RAMNode *rnode = (RAMNode *)node;

            node->setparent(this); // Ensure the node knows we're its parent.
            this->children.insert(rnode->getname(), rnode);

            // If adding a directory, increment parent's st_nlink for the '..' entry.
            if (VFS::S_ISDIR(node->getattr().st_mode)) {
                this->attr.st_nlink++;
            }

            return true;
        }

        bool RAMNode::remove(const char *name) {
            NLib::ScopeIRQSpinlock guard(&this->metalock);

            if (!VFS::S_ISDIR(this->attr.st_mode)) {
                return false; // Non-directories possess no children.
            }

            // Need to check if we're removing a directory to decrement st_nlink.
            RAMNode **child = this->children.find(name);
            if (child && VFS::S_ISDIR((*child)->attr.st_mode)) {
                // Removing a directory, decrement parent's st_nlink for the '..' entry.
                if (this->attr.st_nlink > 0) {
                    this->attr.st_nlink--;
                }
            }

            return this->children.remove(name);
        }

        int RAMFileSystem::mount(const char *src, const char *path, VFS::INode *mntnode, uint64_t flags, const void *data) {
            (void)src;
            (void)path;
            (void)flags;
            (void)data;

            NLib::ScopeSpinlock guard(&this->spin);

            if (this->mounted) {
                return -EINVAL;
            }

            // Set the parent of the root node to the mountpoint node.
            if (mntnode) {
                this->root->setparent(mntnode);
            }

            this->mounted = true;
            return 0;
        }

        int RAMFileSystem::umount(int flags) {
            (void)flags;
            NLib::ScopeSpinlock guard(&this->spin);

            if (!this->mounted) {
                return -EINVAL; // Unmounted.
            }

            delete this->root; // Delete root node. Its destructor will get rid of every child node in the hierarchy.
            this->root = NULL;
            return 0;
        }

        ssize_t RAMFileSystem::create(const char *name, VFS::INode **nodeout, struct VFS::stat attr) {
            NLib::ScopeSpinlock guard(&this->spin);
            attr.st_blksize = 512;
            attr.st_ino = this->nextinode++;
            if (VFS::S_ISDIR(attr.st_mode)) {
                attr.st_nlink = 2; // Directories start with 2 links (self and parent).
            } else {
                attr.st_nlink = 1; // Files start with 1 link.
            }

            *nodeout = new RAMNode(this, name, attr);
            return 0;
        }

        int RAMFileSystem::unlink(VFS::INode *node, VFS::INode *parent) {
            uint64_t ino = node->getattr().st_ino;

            // Remove from parent.
            bool worked = parent->remove(node->getname());
            parent->unref();
            node->unref(); // Drop our reference.

            if (!worked) {
                return -EINVAL; // Removal failed.
            }

            ssize_t res = node->unlink(); // Returns 0 if we're good to delete the node.
            if (res == 0) {
                delete node; // Delete the node.
            }
            return 0;
        }

        int RAMFileSystem::rename(VFS::INode *oldparent, VFS::INode *node, VFS::INode *newparent, const char *newname, VFS::INode *target) {
            // If target exists, we need to unlink it first.
            if (target) {
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

                // Remove target from newparent.
                bool worked = newparent->remove(target->getname());
                if (!worked) {
                    oldparent->unref();
                    node->unref();
                    newparent->unref();
                    target->unref();
                    return -EINVAL;
                }

                // Unlink target.
                ssize_t res = target->unlink();
                if (res == 0) {
                    delete target; // Delete if no more links/refs.
                } else {
                    target->unref();
                }
            }

            // Remove node from old parent.
            const char *oldname = node->getname();
            bool worked = oldparent->remove(oldname);
            oldparent->unref();
            if (!worked) {
                node->unref();
                newparent->unref();
                return -EINVAL;
            }

            // Set new name and add to new parent.
            node->setname(newname);
            newparent->add(node);
            newparent->unref();
            node->unref();

            return 0;
        }

        static struct VFS::fsreginfo ramfsinfo = {
            .name = "ramfs"
        };

        static struct VFS::fsreginfo tmpfsinfo = {
            .name = "tmpfs"
        };

        REGFS(ramfs, RAMFileSystem::instance, &ramfsinfo);
        REGFS(tmpfs, RAMFileSystem::instance, &tmpfsinfo);
    }
}
