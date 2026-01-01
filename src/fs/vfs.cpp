#ifdef __x86_64__
#include <arch/x86_64/cpu.hpp>
#endif
#include <fs/pipefs.hpp>
#include <fs/vfs.hpp>
#include <lib/errno.hpp>
#include <mm/pagecache.hpp>
#include <mm/ucopy.hpp>
#include <sys/clock.hpp>
#include <sys/syscall.hpp>

namespace NFS {
    namespace VFS {
        VFS *vfs = NULL;

        NMem::RadixTree *INode::getpagecache(void) {
            NLib::ScopeSpinlock guard(&this->metalock);
            if (!this->pagecache) {
                this->pagecache = new NMem::RadixTree();
            }
            return this->pagecache;
        }

        NMem::CachePage *INode::findcachedpage(off_t offset) {
            NMem::RadixTree *cache = this->getpagecache();
            if (!cache) {
                return NULL;
            }

            off_t index = offset / NArch::PAGESIZE;
            NMem::CachePage *page = cache->lookup(index);
            if (page) {
                page->pagelock();
            }
            return page;
        }

        NMem::CachePage *INode::getorcacheepage(off_t offset) {
            NMem::RadixTree *cache = this->getpagecache();
            if (!cache) {
                return NULL;
            }

            off_t pageoffset = (offset / NArch::PAGESIZE) * NArch::PAGESIZE;
            off_t index = pageoffset / NArch::PAGESIZE;

            // Check if page already exists.
            NMem::CachePage *page = cache->lookup(index);
            if (page) {
                page->pagelock();
                return page;
            }

            // Allocate new page.
            page = new NMem::CachePage();
            if (!page) {
                return NULL;
            }

            // Allocate physical page.
            void *phys = NArch::PMM::alloc(NArch::PAGESIZE);
            if (!phys) {
                delete page;
                return NULL;
            }

            page->physaddr = (uintptr_t)phys;
            page->pagemeta = NArch::PMM::phystometa((uintptr_t)phys);
            if (page->pagemeta) {
                page->pagemeta->flags |= NArch::PMM::PageMeta::PAGEMETA_PAGECACHE;
                page->pagemeta->cacheentry = page;
                page->pagemeta->ref();
            }

            page->inode = this;
            page->offset = pageoffset;
            page->flags = 0;

            // Hold a reference to the inode to prevent it from being freed while the page exists.
            this->ref();

            // Try to insert into radix tree.
            int err = cache->insert(index, page);
            if (err == -EEXIST) {
                if (page->pagemeta) {
                    page->pagemeta->flags &= ~NArch::PMM::PageMeta::PAGEMETA_PAGECACHE;
                    page->pagemeta->cacheentry = NULL;
                    page->pagemeta->unref();
                }
                // Release inode reference since we're discarding this page.
                this->unref();
                NArch::PMM::free(phys, NArch::PAGESIZE);
                delete page;

                page = cache->lookup(index);
                if (page) {
                    page->pagelock();
                }
                return page;
            } else if (err < 0) {
                // Allocation failure in radix tree.
                if (page->pagemeta) {
                    page->pagemeta->flags &= ~NArch::PMM::PageMeta::PAGEMETA_PAGECACHE;
                    page->pagemeta->cacheentry = NULL;
                    page->pagemeta->unref();
                }
                // Release inode reference since we're discarding this page.
                this->unref();
                NArch::PMM::free(phys, NArch::PAGESIZE);
                delete page;
                return NULL;
            }

            // Add to global page cache LRU.
            if (NMem::pagecache) {
                NMem::pagecache->addpage(page);
            }

            page->pagelock();
            return page;
        }

        void INode::invalidatecache(void) {
            NMem::RadixTree *cache = this->pagecache;
            if (!cache) {
                return;
            }

            // Iterate and remove all pages associated with this INode.
            cache->foreach([](NMem::CachePage *page, void *ctx) -> bool {
                (void)ctx;
                page->pagelock();

                // Remove from global cache.
                if (NMem::pagecache) {
                    NMem::pagecache->removepage(page);
                }

                // Free physical page.
                if (page->pagemeta) {
                    page->pagemeta->flags &= ~NArch::PMM::PageMeta::PAGEMETA_PAGECACHE;
                    page->pagemeta->cacheentry = NULL;
                    page->pagemeta->unref();
                }
                if (page->physaddr) {
                    NArch::PMM::free((void *)page->physaddr, NArch::PAGESIZE);
                }

                // Release reference to inode.
                if (page->inode) {
                    page->inode->unref();
                }

                page->pageunlock();
                delete page;
                return true;
            }, NULL);

            delete cache;
            this->pagecache = NULL;
        }

        int INode::synccache(void) {
            NMem::RadixTree *cache = this->pagecache;
            if (!cache) {
                return 0;
            }

            int errors = 0;
            cache->foreach([](NMem::CachePage *page, void *ctx) -> bool {
                int *errp = (int *)ctx;
                if (page->testflag(NMem::PAGE_DIRTY)) {
                    if (page->trypagelock()) {
                        INode *inode = (INode *)page->inode;
                        int err = inode->writepage(page); // Write back the page.
                        page->pageunlock();
                        if (err < 0) {
                            (*errp)++;
                        }
                    }
                }
                return true;
            }, &errors);

            return errors;
        }

        ssize_t INode::readcached(void *buf, size_t count, off_t offset) {
            if (!buf || count == 0) {
                return -EINVAL;
            }

            // Check file size and adjust count to not read past EOF.
            uint64_t filesize;
            {
                NLib::ScopeSpinlock guard(&this->metalock);
                filesize = this->attr.st_size;
            }

            if ((uint64_t)offset >= filesize) {
                return 0; // EOF - nothing to read.
            }

            if ((uint64_t)(offset + count) > filesize) {
                count = filesize - offset; // Clamp to remaining bytes.
            }

            ssize_t totalread = 0;
            uint8_t *dest = (uint8_t *)buf;

            while (count > 0) {
                off_t pageoffset = (offset / NArch::PAGESIZE) * NArch::PAGESIZE;
                size_t offwithinpage = offset % NArch::PAGESIZE;
                size_t toread = NArch::PAGESIZE - offwithinpage;
                if (toread > count) {
                    toread = count;
                }

                // Get or create page.
                NMem::CachePage *page = this->getorcacheepage(offset);
                if (!page) {
                    if (totalread > 0) {
                        return totalread;
                    }
                    return -ENOMEM;
                }

                // If page not up to date, fill it.
                if (!page->testflag(NMem::PAGE_UPTODATE)) {
                    int err = this->readpage(page);
                    if (err < 0) {
                        page->pageunlock();
                        if (totalread > 0) {
                            return totalread;
                        }
                        return err;
                    }
                }

                // Copy data to user buffer.
                NLib::memcpy(dest, (uint8_t *)page->data() + offwithinpage, toread);

                page->setflag(NMem::PAGE_REFERENCED);
                page->pageunlock();

                dest += toread;
                offset += toread;
                count -= toread;
                totalread += toread;
            }

            return totalread;
        }

        ssize_t INode::writecached(const void *buf, size_t count, off_t offset) {
            if (!buf || count == 0) {
                return -EINVAL;
            }

            ssize_t totalwritten = 0;
            const uint8_t *src = (const uint8_t *)buf;

            while (count > 0) {
                off_t pageoffset = (offset / NArch::PAGESIZE) * NArch::PAGESIZE;
                size_t offwithinpage = offset % NArch::PAGESIZE;
                size_t towrite = NArch::PAGESIZE - offwithinpage;
                if (towrite > count) {
                    towrite = count;
                }

                // Get or create page.
                NMem::CachePage *page = this->getorcacheepage(offset);
                if (!page) {
                    if (totalwritten > 0) {
                        return totalwritten;
                    }
                    return -ENOMEM;
                }

                // If partial page write and page not up to date, fill it first.
                if (!page->testflag(NMem::PAGE_UPTODATE) && (offwithinpage != 0 || towrite < NArch::PAGESIZE)) {
                    int err = this->readpage(page);
                    if (err < 0 && err != -ENOENT) {
                        page->pageunlock();
                        if (totalwritten > 0) {
                            return totalwritten;
                        }
                        return err;
                    }
                    if (err == -ENOENT) { // Zero the page if it doesn't exist.
                        NLib::memset(page->data(), 0, NArch::PAGESIZE);
                    }
                }

                // Copy data from user buffer.
                NLib::memcpy((uint8_t *)page->data() + offwithinpage, (void *)src, towrite);

                page->setflag(NMem::PAGE_UPTODATE);
                page->markdirty();
                page->pageunlock();

                src += towrite;
                offset += towrite;
                count -= towrite;
                totalwritten += towrite;
            }

            return totalwritten;
        }

        int INode::readpage(NMem::CachePage *page) {
            (void)page;
            return -ENOSYS;
        }

        int INode::writepage(NMem::CachePage *page) {
            (void)page;
            return -ENOSYS;
        }

        int VFS::mount(const char *src, const char *path, const char *fs, uint64_t flags, const void *data) {

            if (!NLib::strcmp(fs, "auto")) {
                return this->identifyfs(src);
            }

            fsfactory_t *factory = NULL;
            {
                NLib::ScopeSpinlock guard(&this->mountlock);
                fsfactory_t **fsp = this->filesystems.find(fs);
                if (!fsp) {
                    return -ENODEV; // Filesystem not found.
                }
                factory = *fsp;
            }

            IFileSystem *filesystem = factory(this); // Create new filesystem instance.

            return this->mount(src, path, filesystem, flags, data);
        }

        int VFS::mount(const char *src, const char *_path, IFileSystem *fs, uint64_t flags, const void *data) {
            INode *mntnode = NULL;
            Path mntpath = Path(_path);

            // Mount paths must be absolute.
            if (!mntpath.isabsolute()) {
                return -EINVAL;
            }

            const char *path = mntpath.construct();

            // Resolve the mountpoint node (except for root mount).
            if (mntpath.depth() > 0) {
                ssize_t ret = this->resolve(path, &mntnode, NULL, true, NULL);
                if (ret < 0) {
                    delete[] path;
                    return ret; // Mountpoint doesn't exist.
                }

                // Ensure mountpoint is a directory.
                if (!S_ISDIR(mntnode->getattr().st_mode)) {
                    delete[] path;
                    mntnode->unref();
                    return -ENOTDIR;
                }
            }

            {
                NLib::ScopeSpinlock guard(&this->mountlock);
                // Check if there is a mountpoint on this specific path already. Findmount cannot be used here, as it finds the best match, not exact match.
                NLib::DoubleList<struct mntpoint>::Iterator it = this->mounts.begin();
                // Shadow path with mount path.
                for (; it.valid(); it.next()) {
                    if (!NLib::strcmp(it.get()->path, path)) {
                        if (mntnode) {
                            mntnode->unref();
                        }
                        delete[] path;
                        return -EBUSY; // Mountpoint already in use.
                    }
                }

            }
            if (mntpath.depth() > 0) {
                // Ensure we have permission to mount here.
                NSched::Process *proc = NArch::CPU::get()->currthread->process;
                proc->lock.acquire();
                bool access = this->checkaccess(mntnode, R_OK | X_OK, proc->euid, proc->egid);
                proc->lock.release();
                if (!access) {
                    delete[] path;
                    mntnode->unref();
                    return -EACCES;
                }
            }

            {
                NLib::ScopeSpinlock guard(&this->mountlock);

                this->mounts.push((struct VFS::mntpoint) { NLib::strdup(path), fs, mntnode });

                if (!mntpath.depth() && !this->root) { // Attempt to assign root if we haven't already.
                    this->root = fs->getroot();
                }
            }

            if (fs->mount(src, path, mntnode, flags, data) != 0) {
                this->umount(path, 0); // Rollback mount on failure.
                if (mntnode) {
                    mntnode->unref();
                }
                delete[] path;
                return -EINVAL;
            }
            delete[] path;
            return 0;
        }

        int VFS::umount(const char *_path, int flags) {
            // Normalize and validate path.
            Path upath = Path(_path);

            // Umount paths must be absolute.
            if (!upath.isabsolute()) {
                return -EINVAL;
            }

            const char *path = upath.construct();

            // Prevent unmounting root filesystem.
            if (!NLib::strcmp(path, "/")) {
                delete[] path;
                return -EBUSY;
            }

            struct umount_ud {
                const char *match;
                const char *mntpath;
                IFileSystem *fs;
                INode *mntnode;
                size_t depth;
                bool found;
            } ud = { path, NULL, NULL, NULL, 0, false };

            {
                NLib::ScopeSpinlock guard(&this->mountlock);

                bool worked = this->mounts.remove([](struct mntpoint mnt, void *udata) {
                    struct umount_ud *u = (struct umount_ud *)udata;
                    if (!NLib::strcmp(mnt.path, u->match)) {
                        u->fs = mnt.fs;
                        u->mntpath = mnt.path; // Save path pointer for later deletion.
                        Path mntpath = Path(mnt.path);
                        u->mntnode = mnt.mntnode;
                        u->depth = mntpath.depth();
                        u->found = true;
                        return true;
                    }
                    return false;
                }, (void *)&ud);

                if (!ud.found) {
                    delete[] path;
                    return -EINVAL;
                }

                // Check if there are any child mounts under this path.
                // If so, the filesystem is busy and cannot be unmounted.
                Path umountpath = Path(ud.mntpath);
                size_t umountdepth = umountpath.depth();

                NLib::DoubleList<struct mntpoint>::Iterator it = this->mounts.begin();
                for (; it.valid(); it.next()) {
                    Path childpath = Path(it.get()->path);

                    // Check if this mount is a child of the mount being unmounted.
                    if (childpath.depth() > umountdepth) {
                        bool ischild = true;
                        NLib::DoubleList<const char *>::Iterator cit = childpath.iterator();
                        NLib::DoubleList<const char *>::Iterator uit = umountpath.iterator();

                        for (size_t i = 0; i < umountdepth; i++, cit.next(), uit.next()) {
                            if (NLib::strcmp(*cit.get(), *uit.get())) {
                                ischild = false;
                                break;
                            }
                        }

                        if (ischild) {
                            // Found a child mount, filesystem is busy.
                            // Reinsert the mount point.
                            this->mounts.push((struct VFS::mntpoint) { ud.mntpath, ud.fs, ud.mntnode });
                            delete[] path;
                            return -EBUSY;
                        }
                    }
                }

                // Check if the filesystem has any active usage.
                if (ud.fs && ud.fs->getfsrefcount() > 0) {
                    // Filesystem is busy, reinsert mount point.
                    this->mounts.push((struct VFS::mntpoint) { ud.mntpath, ud.fs, ud.mntnode });
                    delete[] path;
                    return -EBUSY;
                }

                // Check if the mount node itself has active references.
                if (ud.mntnode && ud.mntnode->getrefcount() > 1) {
                    // Mount point is busy, reinsert it.
                    this->mounts.push((struct VFS::mntpoint) { ud.mntpath, ud.fs, ud.mntnode });
                    delete[] path;
                    return -EBUSY;
                }

                if (!ud.depth && this->root) { // If this was the root mount, clear root reference.
                    this->root = NULL;
                }
            }

            // Call filesystem-specific umount (syncs, cleans up).
            if (ud.fs) {
                int ret = ud.fs->umount(flags);
                if (ret < 0) {
                    // Failed to unmount, reinsert mount point.
                    NLib::ScopeSpinlock guard(&this->mountlock);
                    this->mounts.push((struct VFS::mntpoint) { ud.mntpath, ud.fs, ud.mntnode });
                    if (!ud.depth && !this->root) {
                        this->root = ud.mntnode;
                    }
                    delete[] path;
                    return ret;
                }
                // Filesystem umount succeeded, now delete the filesystem object.
                delete ud.fs;
            }

            // Free the mount path string.
            if (ud.mntpath) {
                delete[] ud.mntpath;
            }

            // Unref the mount node.
            if (ud.mntnode) {
                ud.mntnode->unref();
            }

            delete[] path;
            return 0;
        }

        struct VFS::mntpoint *VFS::_findmount(Path *path) {
            // Find the best matching mount point for the given path.
            // The best matching mount point is the one with the longest matching prefix.
            // However, we must consider mounting points shadowed by others.

            struct mntpoint *best = NULL;
            size_t depth = 0;

            NLib::DoubleList<struct mntpoint>::Iterator it = this->mounts.begin();

            for (; it.valid(); it.next()) {
                Path mntpath = Path(it.get()->path);
                bool matches = true;
                NLib::DoubleList<const char *>::Iterator mpit = mntpath.iterator();
                NLib::DoubleList<const char *>::Iterator pit = path->iterator();

                size_t i = 0;
                for (; i < mntpath.depth(); pit.next(), mpit.next(), i++) {
                    if (i >= path->depth() || NLib::strcmp(*mpit.get(), *pit.get())) {
                        matches = false;
                        break;
                    }
                }

                if (!mntpath.depth() && mntpath.isabsolute() && path->isabsolute()) {
                    matches = true;
                }

                if (matches && mntpath.depth() >= depth) {
                    best = it.get();
                    depth = mntpath.depth();
                }
            }

            return best;
        }

        struct VFS::mntpoint *VFS::_findmountbynode(INode *node) {
            // Used during path traversal to detect mount point crossings.
            NLib::DoubleList<struct mntpoint>::Iterator it = this->mounts.begin();
            for (; it.valid(); it.next()) {
                if (it.get()->mntnode == node) {
                    return it.get();
                }
            }
            return NULL;
        }

        struct VFS::mntpoint *VFS::findmount(Path *path) {
            NLib::ScopeSpinlock guard(&this->mountlock);
            return this->_findmount(path);
        }

        struct VFS::mntpoint *VFS::findmountbynode(INode *node) {
            NLib::ScopeSpinlock guard(&this->mountlock);
            return this->_findmountbynode(node);
        }

        ssize_t VFS::resolve(const char *path, INode **nodeout, INode *relativeto, bool symlink, INode *procroot) {
            constexpr size_t MAX_SYMLINK_DEPTH = 40;

            Path rp = Path(path);

            // Determine the effective root for this resolution.
            INode *effroot = procroot ? procroot : this->root;

            if (!rp.depth()) { // Empty path or root path.
                if (rp.isabsolute()) { // Absolute path refers to root.
                    if (!effroot) {
                        return -ENOENT;
                    }
                    effroot->ref();
                    *nodeout = effroot;
                    return 0;
                } else { // Empty relative path refers to current directory.
                    INode *result = relativeto ? relativeto : effroot;
                    if (result) {
                        result->ref(); // Caller expects a referenced node.
                    } else {
                        return -ENOENT;
                    }

                    *nodeout = result;
                    return 0;
                }
                return 0;
            }

            if (!rp.isabsolute()) {
                INode *base = relativeto ? relativeto : effroot;

                // Prepend elements to construct an absolute path.
                while (base && base != effroot) {
                    INode *parent = base->getparent();

                    if (!parent) {
                        // We've hit a filesystem root. Find where this filesystem is mounted.
                        struct mntpoint *mnt = NULL;
                        NLib::DoubleList<struct mntpoint>::Iterator mit = this->mounts.begin();
                        for (; mit.valid(); mit.next()) {
                            if (mit.get()->fs->getroot() == base) {
                                mnt = mit.get();
                                break;
                            }
                        }

                        if (mnt && mnt->mntnode) {
                            // Found the mount point. Continue from the mount directory.
                            Path mntpath = Path(mnt->path);
                            // Prepend mount path components in reverse order.
                            NLib::DoubleList<const char *>::Iterator pit = mntpath.iterator();
                            // Collect components first, then prepend in reverse.
                            const char *comps[64]; // Reasonable max depth.
                            size_t ncomps = 0;
                            for (; pit.valid() && ncomps < 64; pit.next()) {
                                comps[ncomps++] = *pit.get();
                            }
                            // Prepend in reverse order (deepest first was collected first).
                            for (size_t i = ncomps; i > 0; i--) {
                                rp.pushcomponent(comps[i-1], false);
                            }
                            break;
                        } else {
                            // No mount found or at VFS root, stop.
                            break;
                        }
                    } else {
                        const char *name = base->getname();
                        if (name && *name) {
                            rp.pushcomponent(name, false);
                        }
                        base = parent;
                    }
                }

                rp.setabsolute();
            }

            const char *rpstr = rp.construct();
            Path pobj = Path(rpstr); // Forcibly collapse resultant path.
            delete[] rpstr;

            INode *current = NULL;
            size_t skip = 0;

            if (procroot) {
                // For any path in a chroot, start from procroot.
                current = procroot;
                current->ref();
                skip = 0; // Don't skip any components, traverse from procroot.
            } else {
                struct mntpoint *mount = this->findmount(&pobj);
                if (!mount) {
                    return -ENOENT; // Path is invalid. No mountpoint handles this path.
                }

                Path mntpath = Path(mount->path);
                skip = mntpath.depth(); // How many components of the main path should we skip to just get the path relative to the mount path?

                current = mount->fs->getroot();
            }

            NLib::DoubleList<const char *>::Iterator it = pobj.iterator();
            for (size_t i = 0; i < skip && it.valid(); i++) {
                it.next(); // Skip over components relevant to the mount path.
            }

            size_t symlink_depth = 0; // Track symlink resolution depth to prevent infinite loops.

            while (it.valid()) {

                if (!NLib::strcmp(*it.get(), "..")) {
                    INode *parent = current->getparent();

                    // Stop at the per-process root boundary to enforce chroot confinement.
                    if (!parent || current == effroot) {
                        // Stay at current if we're at the effective root.
                        it.next();
                        continue;
                    }

                    parent->ref(); // Increment refcount for parent.
                    current->unref(); // Unreference old current.
                    current = parent;
                    it.next();
                    continue;
                }

                // Check that we have search permission on the current node.
                if (!this->checkaccess(current, O_RDONLY | O_EXEC, 0, 0)) {
                    current->unref();
                    return -EACCES;
                }

                INode *next = current->lookup(*it.get());
                current->unref(); // Unreference old

                if (!next) {
                    return -ENOENT;
                }

                // Chroot precaution, ensure we cross mount points correctly.
                struct mntpoint *crossedmount = this->findmountbynode(next);
                if (crossedmount) {
                    // Switch from the underlying directory to the mounted filesystem's root.
                    next->unref();
                    next = crossedmount->fs->getroot();
                }

                it.next();
                current = next;
                if (symlink && S_ISLNK(current->getattr().st_mode)) { // If this node is a symbolic link.
                    if (symlink_depth >= MAX_SYMLINK_DEPTH) {
                        current->unref();
                        return -ELOOP; // Too many levels of symbolic links.
                    }
                    INode *resolved = current->resolvesymlink();
                    if (!resolved) {
                        current->unref();
                        return -ENOENT; // Invalid symbolic link.
                    }
                    current->unref(); // Unreference the symlink node.
                    current = resolved; // Resolved already has refcount from resolvesymlink.
                    symlink_depth++;

                    while (!it.valid() && S_ISLNK(current->getattr().st_mode)) {
                        if (symlink_depth >= MAX_SYMLINK_DEPTH) {
                            current->unref();
                            return -ELOOP; // Too many levels of symbolic links.
                        }
                        INode *nextresolved = current->resolvesymlink();
                        if (!nextresolved) {
                            current->unref();
                            return -ENOENT;
                        }
                        current->unref();
                        current = nextresolved;
                        symlink_depth++;
                    }
                }
            }

            if (!current) {
                return -ENOENT;
            }

            // Special handling for named pipes (FIFOs).
            if (current->getredirect()) {
                INode *redirected = current->getredirect();
                current->unref();
                current = redirected; // Follow redirect.
            }

            *nodeout = current;
            return 0;
        }

        ssize_t VFS::create(const char *path, INode **nodeout, struct stat attr, INode *relativeto, INode *procroot) {
            Path pobj = Path(path);

            if (!pobj.depth()) {
                return -EINVAL; // Cannot create root.
            }

            // Convert to absolute path if relative, same as resolve() does.
            if (!pobj.isabsolute()) {
                INode *base = relativeto ? relativeto : this->root;

                // Prepend elements to construct an absolute path.
                while (base && base != this->root) {
                    pobj.pushcomponent(base->getname(), false);
                    base = base->getparent();
                }

                pobj.setabsolute();
            }

            // Reconstruct to collapse any ".." components properly.
            const char *pobjstr = pobj.construct();
            Path abspobj = Path(pobjstr);
            delete[] pobjstr;

            // Check if path already exists.
            INode *existing = NULL;
            ssize_t res = this->resolve(path, &existing, relativeto, false, procroot);
            if (res == 0) {
                existing->unref();
                return -EEXIST; // Path already exists.
            }

            const char *parentpath = abspobj.dirname();
            INode *parent;
            res = this->resolve(parentpath, &parent, relativeto, true, procroot);
            delete parentpath; // Caller is expected to free `dirname()`.
            if (res < 0) {
                return res; // Parent doesn't already exist.
            }

            struct mntpoint *mount = this->findmount(&abspobj);
            if (!mount) {
                parent->unref(); // Don't leak parent reference.
                return -ENOENT; // Invalid mounting point.
            }

            INode *node = NULL;
            res = mount->fs->create(abspobj.basename(), &node, attr);
            if (res < 0) {
                parent->unref();
                return res; // Creation failed.
            }
            parent->add(node);
            parent->unref();

            node->ref(); // Increment refcount before returning, matching resolve() contract.
            *nodeout = node;
            return 0;
        }

        int VFS::unlink(const char *path, INode *relativeto, int flags, int uid, int gid, INode *procroot) {
            Path pobj = Path(path);

            if (!pobj.depth()) {
                return -EINVAL; // Cannot unlink root.
            }

            INode *node = NULL;
            ssize_t res = this->resolve(path, &node, relativeto, false, procroot);
            if (res < 0) {
                return res; // Failed to resolve path.
            }

            // Get parent directory.
            INode *parent = node->getparent();
            if (!parent) {
                node->unref();
                return -EINVAL; // Cannot unlink root node.
            }
            parent->ref();

            // Check if we're trying to unlink a directory.
            struct stat st = node->getattr();
            if (S_ISDIR(st.st_mode)) {
                if (!(flags & AT_REMOVEDIR)) {
                    // Trying to unlink a directory without AT_REMOVEDIR flag.
                    parent->unref();
                    node->unref();
                    return -EISDIR;
                }
                if (!node->empty()) {
                    // Directory is not empty.
                    parent->unref();
                    node->unref();
                    return -ENOTEMPTY;
                }
            } else {
                if (flags & AT_REMOVEDIR) {
                    // AT_REMOVEDIR specified but target is not a directory.
                    parent->unref();
                    node->unref();
                    return -ENOTDIR;
                }
            }

            if (!this->checkaccess(parent, O_RDWR | O_EXEC, uid, gid)) {
                parent->unref();
                node->unref();
                return -EACCES; // No write/search permission on parent directory.
            }

            // Call filesystem-specific unlink, it handles unreferencing our references to node and parent.
            int ret = node->fs->unlink(node, parent);

            return ret;
        }

        int VFS::rename(const char *oldpath, INode *oldrelativeto, const char *newpath, INode *newrelativeto, int uid, int gid, INode *procroot) {
            Path oldpobj = Path(oldpath);
            Path newpobj = Path(newpath);

            if (!oldpobj.depth()) {
                return -EINVAL; // Cannot rename root.
            }
            if (!newpobj.depth()) {
                return -EINVAL; // Cannot rename to root.
            }

            // Resolve the source node (without following final symlink).
            INode *srcnode = NULL;
            ssize_t res = this->resolve(oldpath, &srcnode, oldrelativeto, false, procroot);
            if (res < 0) {
                return res; // Failed to resolve source.
            }

            // Get source parent directory.
            INode *srcparent = srcnode->getparent();
            if (!srcparent) {
                srcnode->unref();
                return -EINVAL; // Cannot rename root node.
            }
            srcparent->ref();

            // Check write permission on source parent.
            if (!this->checkaccess(srcparent, O_RDWR | O_EXEC, uid, gid)) {
                srcparent->unref();
                srcnode->unref();
                return -EACCES;
            }

            // Resolve destination parent directory.
            const char *dstdirpath = newpobj.dirname();
            INode *dstparent = NULL;
            res = this->resolve(dstdirpath, &dstparent, newrelativeto, true, procroot);
            delete dstdirpath;
            if (res < 0) {
                srcparent->unref();
                srcnode->unref();
                return res; // Destination parent doesn't exist.
            }

            if (!S_ISDIR(dstparent->getattr().st_mode)) {
                dstparent->unref();
                srcparent->unref();
                srcnode->unref();
                return -ENOTDIR; // Destination parent is not a directory.
            }

            // Check write permission on destination parent.
            if (!this->checkaccess(dstparent, O_RDWR | O_EXEC, uid, gid)) {
                dstparent->unref();
                srcparent->unref();
                srcnode->unref();
                return -EACCES;
            }

            // Check if source and destination are on the same filesystem.
            if (srcnode->fs != dstparent->fs) {
                dstparent->unref();
                srcparent->unref();
                srcnode->unref();
                return -EXDEV; // Cross-device rename not supported.
            }

            // Check if destination already exists.
            const char *dstname = newpobj.basename();
            INode *dstnode = dstparent->lookup(dstname);

            // Handle various rename cases.
            if (dstnode) {
                struct stat srcst = srcnode->getattr();
                struct stat dstst = dstnode->getattr();

                // Check if source and destination are the same file.
                if (srcst.st_ino == dstst.st_ino && srcst.st_dev == dstst.st_dev) {
                    // Same file, nothing to do.
                    dstnode->unref();
                    dstparent->unref();
                    srcparent->unref();
                    srcnode->unref();
                    return 0;
                }

                if (S_ISDIR(srcst.st_mode)) {
                    if (!S_ISDIR(dstst.st_mode)) {
                        // Woah pal, source can't be a directory if destination isn't.
                        dstnode->unref();
                        dstparent->unref();
                        srcparent->unref();
                        srcnode->unref();
                        return -ENOTDIR;
                    }
                } else {
                    if (S_ISDIR(dstst.st_mode)) {
                        // Woah pal, destination can't be a directory if source isn't.
                        dstnode->unref();
                        dstparent->unref();
                        srcparent->unref();
                        srcnode->unref();
                        return -EISDIR;
                    }
                }
            }

            // Get the filesystem to handle it.
            int ret = srcnode->fs->rename(srcparent, srcnode, dstparent, dstname, dstnode);
            return ret;
        }

        void VFS::syncall(void) {
            NLib::ScopeSpinlock guard(&this->mountlock);

            NLib::DoubleList<struct mntpoint>::Iterator it = this->mounts.begin();
            for (; it.valid(); it.next()) {
                it.get()->fs->sync();
            }
        }

        int FileDescriptorTable::open(INode *node, int flags) {
            NLib::ScopeWriteLock guard(&this->lock);

            int fd = this->openfds.findfirst();
            if (fd == -1) {
                fd = this->openfds.getsize();
                if (fd + 32 > MAXFDS) {
                    return -EMFILE; // Too many open files.
                }

                if (!this->fds.resize(fd + 32)) {
                    return -ENOMEM;
                }

                if (!this->openfds.resize(fd + 32)) {
                    return -ENOMEM;
                }

                if (!this->closeonexec.resize(fd + 32)) {
                    return -ENOMEM;
                }
            }

            this->fds[fd] = new FileDescriptor(node, flags);
            if (!this->fds[fd]) {
                return -ENOMEM;
            }

            // Increment filesystem reference count for this open file.
            if (node && node->fs) {
                node->fs->fsref();
            }

            if (flags & O_CLOEXEC) {
                this->closeonexec.set(fd);
            }

            this->openfds.set(fd);
            return fd;
        }

        void FileDescriptorTable::reserve(int fd, INode *node, int flags) {
            NLib::ScopeWriteLock guard(&this->lock);

            this->fds[fd] = new FileDescriptor(node, flags);
            if (!this->fds[fd]) {
                return;
            }

            // Increment filesystem reference count for this open file.
            if (node && node->fs) {
                node->fs->fsref();
            }

            this->openfds.set(fd);
        }

        int FileDescriptorTable::close(int fd) {
            NLib::ScopeWriteLock guard(&this->lock);

            if (fd < 0 || fd >= (int)this->fds.getsize() || !this->fds[fd] || !this->openfds.test(fd)) {
                return -EBADF;
            }

            FileDescriptor *desc = this->fds[fd];
            int res = 0;
            if (desc->unref() == 0) {
                INode *node = desc->getnode();
                res = node->close(desc->getflags());

                // Decrement filesystem reference count when closing the last reference.
                if (node->fs) {
                    node->fs->fsunref();
                }

                node->unref();
                delete desc;
            }
            this->fds[fd] = NULL;
            this->openfds.clear(fd); // Mark as unallocated.
            this->closeonexec.clear(fd); // Mark as unallocated.
            return res;
        }

        int FileDescriptorTable::dup(int oldfd) {
            NLib::ScopeWriteLock guard(&this->lock);

            if (oldfd < 0 || oldfd >= (int)this->fds.getsize() || !this->fds[oldfd] || !this->openfds.test(oldfd)) {
                return -EBADF;
            }

            int newfd = this->openfds.findfirst();
            if (newfd == -1) { // None available. :broken_heart: emoji
                newfd = this->openfds.getsize(); // New FD will be the new bit from this resize. Simply saves another call to findfirst().
                if (newfd + 32 > MAXFDS) {
                    return -EMFILE; // Too many open files.
                }

                if (!this->fds.resize(newfd + 32)) { // Resize vector. It'll grow to accomodate the new data.

                    return -ENOMEM;
                }

                if (!this->openfds.resize(newfd + 32)) {
                    return -ENOMEM;
                }
                if (!this->closeonexec.resize(newfd + 32)) { // Both bitmaps needs to be maintained.
                    return -ENOMEM;
                }
            }

            this->fds[newfd] = this->fds[oldfd];
            this->fds[newfd]->ref(); // Increase reference count of descriptor. We're now referring to it by another additional FD.
            this->openfds.set(newfd); // Set bit to mark as allocated.
            return newfd;
        }

        int FileDescriptorTable::dup2(int oldfd, int newfd, bool fcntl) {
            NLib::ScopeWriteLock guard(&this->lock);

            if (oldfd < 0 || oldfd >= (int)this->fds.getsize() || !this->fds[oldfd] || !this->openfds.test(oldfd)) { // Discard if we can tell that the FD is bad.
                return -EBADF;
            }

            if (fcntl) {
                if (newfd < 0) {
                    return -EINVAL;
                }

                // Find lowest-numbered available fd >= newfd.
                int candidate = -1;
                for (int i = newfd; i < (int)this->openfds.getsize(); i++) {
                    if (!this->openfds.test(i)) {
                        candidate = i;
                        break;
                    }
                }

                if (candidate == -1) {
                    candidate = this->openfds.getsize();
                    if (candidate + 32 > MAXFDS) {
                        return -EMFILE;
                    }

                    if (!this->fds.resize(candidate + 32)) {
                        return -ENOMEM;
                    }

                    if (!this->openfds.resize(candidate + 32)) {
                        return -ENOMEM;
                    }

                    if (!this->closeonexec.resize(candidate + 32)) {
                        return -ENOMEM;
                    }
                }

                this->fds[candidate] = this->fds[oldfd];
                this->fds[candidate]->ref();
                this->openfds.set(candidate);
                return candidate;
            }

            // Non-fcntl (dup2) semantics: newfd is exact target.
            if (newfd < 0 || newfd > MAXFDS) { // Discard if this is a negative. Positive FDs are still valid, because we can just expand the FD table. Arbitrary maximum is imposed to prevent rampant memory consumption.
                return -EBADF;
            }

            if (oldfd == newfd) {
                return newfd; // Don't even bother.
            }

            if (newfd >= (int)this->fds.getsize()) {
                if (!this->fds.resize(newfd + 1)) {
                    return -ENOMEM;
                }

                if (!this->openfds.resize(newfd + 1)) {
                    return -ENOMEM;
                }
                if (!this->closeonexec.resize(newfd + 1)) { // Both bitmaps needs to be maintained.
                    return -ENOMEM;
                }
            }

            if (this->openfds.test(newfd)) { // Close the existing descriptor if open.
                FileDescriptor *olddesc = this->fds[newfd];
                if (olddesc->unref() == 0) { // Decrement reference within our table.
                    INode *node = olddesc->getnode();
                    node->close(olddesc->getflags());
                    node->unref();
                    delete olddesc;
                }
            }

            this->fds[newfd] = this->fds[oldfd];
            this->fds[newfd]->ref();
            this->openfds.set(newfd); // Occupy new FD.
            this->closeonexec.clear(newfd); // dup2 clears close-on-exec per POSIX.
            return newfd;
        }

        FileDescriptor *FileDescriptorTable::get(int fd) {
            NLib::ScopeReadLock guard(&this->lock);

            if (fd < 0 || fd >= (int)this->fds.getsize() || !this->openfds.test(fd)) {
                // If the fd is negative, over our current maximum, or not currently allocated:
                return NULL;
            }
            return this->fds[fd]; // Otherwise: Return it.
        }

        FileDescriptorTable *FileDescriptorTable::fork(void) {
            NLib::ScopeWriteLock guard(&this->lock);

            FileDescriptorTable *newtable = new FileDescriptorTable();

            if (!newtable->fds.resize(this->fds.getsize()) || !newtable->openfds.resize(this->fds.getsize()) || !newtable->closeonexec.resize(this->fds.getsize())) { // Attempt to resize all tracking of FDs, failure returns NULL, and deletes the allocation (for the sake of memory usage).
                delete newtable;
                return NULL;
            }

            for (size_t i = 0; i < this->fds.getsize(); i++) {
                if (this->openfds.test(i)) { // There is an open FD, copy it.
                    newtable->fds[i] = this->fds[i]; // Copy reference to same FileDescriptor.
                    newtable->fds[i]->ref(); // Increase refcount.
                    newtable->openfds.set(i); // Mark as allocated.


                    if (this->closeonexec.test(i)) { // If this is also marked as close on exec.
                        newtable->closeonexec.set(i); // Mark as allocated.
                    }
                } else {
                    this->openfds.clear(i);
                    this->closeonexec.clear(i);
                }
            }

            return newtable;
        }

        bool FileDescriptorTable::iscloseonexec(int fd) {
            NLib::ScopeReadLock guard(&this->lock);

            if (fd < 0 || fd >= (int)this->fds.getsize() || !this->openfds.test(fd)) {
                return false;
            }

            return this->closeonexec.test(fd);
        }

        void FileDescriptorTable::setcloseonexec(int fd, bool closeit) {
            NLib::ScopeWriteLock guard(&this->lock);

            if (fd < 0 || fd >= (int)this->fds.getsize() || !this->openfds.test(fd)) {
                return;
            }

            if (closeit) {
                this->closeonexec.set(fd);
            } else {
                this->closeonexec.clear(fd);
            }
        }

        void FileDescriptorTable::doexec(void) {
            NLib::ScopeWriteLock guard(&this->lock);

            for (size_t i = 0; i < this->closeonexec.getsize(); i++) { // Effectively the same logic as closeall(), but we only close FDs marked as close-on-exec.
                if (this->closeonexec.test(i)) {
                    FileDescriptor *desc = this->fds[i];
                    if (desc->unref() == 0) {
                        INode *node = desc->getnode();
                        node->close(desc->getflags());
                        node->unref();
                        delete desc;
                    }
                    this->fds[i] = NULL;
                    this->openfds.clear(i);
                    this->closeonexec.clear(i);
                }
            }
        }

        void FileDescriptorTable::closeall(void) {
            NLib::ScopeWriteLock guard(&this->lock);

            for (size_t i = 0; i < this->openfds.getsize(); i++) {
                if (this->openfds.test(i)) { // Allocated. Free associated if without reference.
                    FileDescriptor *desc = this->fds[i];
                    if (desc->unref() == 0) {
                        INode *node = desc->getnode();
                        node->close(desc->getflags());
                        node->unref();
                        delete desc; // Delete descriptor itself if we ran out of references.
                    }
                    this->fds[i] = NULL;
                    this->openfds.clear(i);
                    this->closeonexec.clear(i);
                }
            }
        }

        bool VFS::checkaccess(INode *node, int flags, uint32_t uid, uint32_t gid) {
            struct stat st = node->getattr();

            // Root always bypasses.
            if (uid == 0) {
                return true;
            }

            if ((flags & O_ACCMODE) == O_RDONLY || (flags & O_ACCMODE) == O_RDWR) {
                if (uid == st.st_uid) {
                    if (!(st.st_mode & S_IRUSR)) {
                        return false;
                    }
                } else if (gid == st.st_gid) {
                    if (!(st.st_mode & S_IRGRP)) {
                        return false;
                    }
                } else {
                    if (!(st.st_mode & S_IROTH)) {
                        return false;
                    }
                }
            }

            if ((flags & O_ACCMODE) == O_WRONLY || (flags & O_ACCMODE) == O_RDWR) {
                if (uid == st.st_uid) {
                    if (!(st.st_mode & S_IWUSR)) {
                        return false;
                    }
                } else if (gid == st.st_gid) {
                    if (!(st.st_mode & S_IWGRP)) {
                        return false;
                    }
                } else {
                    if (!(st.st_mode & S_IWOTH)) {
                        return false;
                    }
                }
            }

            if (flags & O_EXEC || S_ISDIR(st.st_mode)) {
                if (uid == st.st_uid) {
                    if (!(st.st_mode & S_IXUSR)) {
                        return false;
                    }
                } else if (gid == st.st_gid) {
                    if (!(st.st_mode & S_IXGRP)) {
                        return false;
                    }
                } else {
                    if (!(st.st_mode & S_IXOTH)) {
                        return false;
                    }
                }
            }

            return true;
        }


        int VFS::identifyfs(const char *src) {
            // XXX: Implement filesystem auto-detection.
            return -ENODEV;
        }

        extern "C" uint64_t sys_openat(int dirfd, const char *path, int flags, unsigned int mode) {
            SYSCALL_LOG("sys_openat(%d, %s, %d, %u).\n", dirfd, path, flags, mode);

            ssize_t pathsize = NMem::UserCopy::strnlen(path, 1024); // XXX: Maximum path length.
            if (pathsize < 0) {
                SYSCALL_RET(pathsize); // Contains errno.
            }

            char *pathbuf = new char[pathsize + 1];
            if (!pathbuf) {
                SYSCALL_RET(-ENOMEM);
            }

            int ret = NMem::UserCopy::strncpyfrom(pathbuf, path, pathsize);
            if (ret < 0) {
                delete[] pathbuf;
                SYSCALL_RET(ret); // Contains errno.
            }

            pathbuf[pathsize] = '\0';

            INode *dirnode = NULL;

            NSched::Process *proc = NArch::CPU::get()->currthread->process;
            proc->lock.acquire();

            if (pathbuf[0] == '/') { // Absolute path invalidates dirfd.
                dirnode = vfs->getroot();
            } else {
                if (dirfd == AT_FDCWD) { // Special case: FD is CWD.
                    dirnode = proc->cwd;
                    if (!dirnode) { // If the process has no CWD, we use root.
                        dirnode = vfs->getroot();
                    } else {
                        dirnode->ref(); // Increase reference.
                    }
                } else {
                    FileDescriptor *desc = proc->fdtable->get(dirfd);
                    if (!desc) {
                        delete[] pathbuf;
                        proc->lock.release();
                        SYSCALL_RET(-EBADF);
                    }

                    dirnode = desc->getnode();
                    if (!S_ISDIR(dirnode->getattr().st_mode)) {
                        dirnode->unref();
                        delete[] pathbuf;
                        proc->lock.release();
                        SYSCALL_RET(-ENOTDIR);
                    }
                }
            }

            int uid = proc->euid;;
            int gid = proc->egid;
            INode *procroot = proc->root;
            if (procroot) {
                procroot->ref(); // Increase reference for our use.
            }
            proc->lock.release();

            INode *node;
            ssize_t res = vfs->resolve(pathbuf, &node, dirnode, !(flags & O_NOFOLLOW), procroot);
            dirnode->unref();
            if (procroot) {
                procroot->unref();
            }
            if (res == -EACCES) { // We don't have permission to traverse the path.
                delete[] pathbuf;
                SYSCALL_RET(-EACCES); // Propagate access error.
            }

            if (res != 0) { // Couldn't find it. Check if there's a reason to create it.
                if (!(flags & O_CREAT)) {
                    delete[] pathbuf;
                    SYSCALL_RET(res); // Don't bother if there's no create flag.
                }
                // Re-acquire procroot for create operation.
                proc->lock.acquire();
                INode *procroot = proc->root;
                if (procroot) {
                    procroot->ref();
                }
                proc->lock.release();

                // Create the node.
                struct stat attr = { 0 };
                attr.st_mode = mode | S_IFREG;
                attr.st_uid = uid;
                attr.st_gid = gid;
                ssize_t res = vfs->create(pathbuf, &node, attr, dirnode, procroot);
                if (procroot) {
                    procroot->unref();
                }
                if (res < 0) {
                    delete[] pathbuf;
                    SYSCALL_RET(res); // Creation failed.
                }
            }

            delete[] pathbuf;

            struct stat st = node->getattr();

            if ((flags & O_DIRECTORY) && !S_ISDIR(st.st_mode)) { // If we're supposed to open a directory, we'd have to verify that the node is a directory.
                node->unref();
                SYSCALL_RET(-ENOTDIR);
            }

            if (!vfs->checkaccess(node, flags, uid, gid)) { // Check if current process' effective UID and GID are valid for access the node in this way.
                node->unref();
                SYSCALL_RET(-EACCES);
            }

            int accmode = flags & O_ACCMODE;

            switch (accmode) {
                case O_RDONLY:
                    if (flags & O_TRUNC) {
                        node->unref();
                        SYSCALL_RET(-EINVAL); // Can't truncate without write access.
                    }
                    break;
                case O_WRONLY:
                case O_RDWR:
                    if (S_ISDIR(st.st_mode)) {
                        node->unref();
                        SYSCALL_RET(-EISDIR); // Can't write to directory.
                    }
                    break;
                default:
                    node->unref();
                    SYSCALL_RET(-EINVAL);
            }

            // if ((flags & O_TRUNC) && S_ISREG(st.st_mode)) {

            // }

            int fd = proc->fdtable->open(node, flags);
            if (fd < 0) {
                node->unref();
                SYSCALL_RET(fd); // Propagate error.
            }

            res = node->open(flags); // Trigger open hook.
            if (res < 0) {
                proc->fdtable->close(fd); // Clean up FD table entry and call INode::close().
                node->unref();
                SYSCALL_RET(res); // Open failed.
            }

            node->unref(); // Unreference. FD table will handle the reference.

            SYSCALL_RET(fd);
        }

        extern "C" uint64_t sys_dup(int fd, int flags) {
            SYSCALL_LOG("sys_dup(%d, %d).\n", fd, flags);

            NSched::Process *proc = NArch::CPU::get()->currthread->process;

            SYSCALL_RET(proc->fdtable->dup(fd));
        }

        extern "C" uint64_t sys_dup2(int fd, int flags, int newfd) {
            SYSCALL_LOG("sys_dup2(%d, %d, %d).\n", fd, flags, newfd);

            NSched::Process *proc = NArch::CPU::get()->currthread->process;

            SYSCALL_RET(proc->fdtable->dup2(fd, newfd));
        }

        extern "C" uint64_t sys_close(int fd) {
            SYSCALL_LOG("sys_close(%d).\n", fd);

            if (fd < 0) {
                SYSCALL_RET(-EBADF);
            }

            NSched::Process *proc = NArch::CPU::get()->currthread->process;

            int res = proc->fdtable->close(fd);
            SYSCALL_RET(res);
        }

        extern "C" uint64_t sys_getdents(int fd, void *buf, size_t count) {
            SYSCALL_LOG("sys_getdents(%d, %p, %lu).\n", fd, buf, count);

            if (fd < 0) {
                SYSCALL_RET(-EBADF);
            }

            if (!buf && count > 0) {
                SYSCALL_RET(-EFAULT);
            }

            if (!NMem::UserCopy::valid(buf, count)) {
                SYSCALL_RET(-EFAULT); // Invalid buffer.
            }

            NSched::Process *proc = NArch::CPU::get()->currthread->process;

            FileDescriptor *desc = proc->fdtable->get(fd);
            if (!desc) {
                SYSCALL_RET(-EBADF);
            }

            INode *node = desc->getnode();

            struct stat st = node->getattr();
            if (!S_ISDIR(st.st_mode)) {
                node->unref();
                SYSCALL_RET(-ENOTDIR);
            }

            ssize_t read = node->readdir(buf, count, desc->getoff());
            node->unref();
            if (read < 0) {
                SYSCALL_RET(read); // Return error code.
            }

            desc->addoff(read); // Increment offset.

            SYSCALL_RET(read); // Return the actual number of bytes read.
        }

        extern "C" uint64_t sys_fchdir(int fd) {
            SYSCALL_LOG("sys_fchdir(%d).\n", fd);

            if (fd < 0) {
                SYSCALL_RET(-EBADF);
            }

            NSched::Process *proc = NArch::CPU::get()->currthread->process;

            FileDescriptor *desc = proc->fdtable->get(fd);
            if (!desc) {
                SYSCALL_RET(-EBADF);
            }

            INode *node = desc->getnode();

            struct stat st = node->getattr();
            if (!S_ISDIR(st.st_mode)) {
                node->unref();
                SYSCALL_RET(-ENOTDIR);
            }

            // POSIX requires search (execute) permission on the directory.
            proc->lock.acquire();
            int uid = proc->euid;
            int gid = proc->egid;
            proc->lock.release();

            if (!vfs->checkaccess(node, O_EXEC, uid, gid)) {
                node->unref();
                SYSCALL_RET(-EACCES);
            }

            proc->lock.acquire();
            INode *oldcwd = proc->cwd;
            proc->cwd = node; // Set new CWD.
            if (node->fs) {
                node->fs->fsref();  // New filesystem gets a reference
            }
            proc->lock.release();

            if (oldcwd) {
                if (oldcwd->fs) {
                    oldcwd->fs->fsunref();  // Old filesystem loses a reference
                }
                oldcwd->unref(); // Unreference old CWD.
            }
            SYSCALL_RET(0);
        }

        extern "C" uint64_t sys_chdir(const char *path) {
            SYSCALL_LOG("sys_chdir(%s).\n", path);

            ssize_t pathsize = NMem::UserCopy::strnlen(path, 1024); // XXX: Maximum path length.
            if (pathsize < 0) {
                SYSCALL_RET(pathsize); // Contains errno.
            }

            char *pathbuf = new char[pathsize + 1];
            if (!pathbuf) {
                SYSCALL_RET(-ENOMEM);
            }

            int ret = NMem::UserCopy::strncpyfrom(pathbuf, path, pathsize);
            if (ret < 0) {
                delete[] pathbuf;
                SYSCALL_RET(ret); // Contains errno.
            }

            pathbuf[pathsize] = '\0';

            NSched::Process *proc = NArch::CPU::get()->currthread->process;
            proc->lock.acquire();
            int uid = proc->euid;
            int gid = proc->egid;
            INode *cwd = proc->cwd;
            if (cwd) {
                cwd->ref(); // Increase reference for our use.
            }
            INode *procroot = proc->root;
            if (procroot) {
                procroot->ref(); // Increase reference for our use.
            }
            proc->lock.release();

            INode *node;
            ssize_t res = vfs->resolve(pathbuf, &node, cwd, true, procroot);
            delete[] pathbuf;

            if (cwd) {
                cwd->unref(); // Unreference old CWD reference.
            }
            if (procroot) {
                procroot->unref();
            }

            if (res < 0) {
                SYSCALL_RET(res);
            }

            struct stat st = node->getattr();
            if (!S_ISDIR(st.st_mode)) {
                node->unref();
                SYSCALL_RET(-ENOTDIR);
            }

            // POSIX requires search (execute) permission on the directory.
            if (!vfs->checkaccess(node, O_EXEC, uid, gid)) {
                node->unref();
                SYSCALL_RET(-EACCES);
            }

            proc->lock.acquire();
            INode *oldcwd = proc->cwd;
            proc->cwd = node; // Set new CWD.
            if (node->fs) {
                node->fs->fsref();  // New filesystem gets a reference
            }
            proc->lock.release();

            if (oldcwd) {
                if (oldcwd->fs) {
                    oldcwd->fs->fsunref();  // Old filesystem loses a reference
                }
                oldcwd->unref(); // Unreference old CWD.
            }
            SYSCALL_RET(0);
        }

        extern "C" uint64_t sys_chroot(const char *path) {
            SYSCALL_LOG("sys_chroot(%s).\n", path);

            // Only root (euid == 0) can call chroot.
            NSched::Process *proc = NArch::CPU::get()->currthread->process;
            proc->lock.acquire();
            int euid = proc->euid;
            proc->lock.release();

            if (euid != 0) {
                SYSCALL_RET(-EPERM);
            }

            ssize_t pathsize = NMem::UserCopy::strnlen(path, 1024); // XXX: Maximum path length.
            if (pathsize < 0) {
                SYSCALL_RET(pathsize); // Contains errno.
            }

            char *pathbuf = new char[pathsize + 1];
            if (!pathbuf) {
                SYSCALL_RET(-ENOMEM);
            }

            int ret = NMem::UserCopy::strncpyfrom(pathbuf, path, pathsize);
            if (ret < 0) {
                delete[] pathbuf;
                SYSCALL_RET(ret); // Contains errno.
            }

            pathbuf[pathsize] = '\0';

            proc->lock.acquire();
            int uid = proc->euid;
            int gid = proc->egid;
            INode *cwd = proc->cwd;
            if (cwd) {
                cwd->ref(); // Increase reference for our use.
            }
            INode *procroot = proc->root;
            if (procroot) {
                procroot->ref(); // Increase reference for our use.
            }
            proc->lock.release();

            INode *node;
            ssize_t res = vfs->resolve(pathbuf, &node, cwd, true, procroot);
            delete[] pathbuf;

            if (cwd) {
                cwd->unref(); // Unreference old CWD reference.
            }
            if (procroot) {
                procroot->unref();
            }

            if (res < 0) {
                SYSCALL_RET(res);
            }

            struct stat st = node->getattr();
            if (!S_ISDIR(st.st_mode)) {
                node->unref();
                SYSCALL_RET(-ENOTDIR);
            }

            // POSIX requires search (execute) permission on the directory.
            if (!vfs->checkaccess(node, O_EXEC, uid, gid)) {
                node->unref();
                SYSCALL_RET(-EACCES);
            }

            proc->lock.acquire();
            INode *oldroot = proc->root;
            proc->root = node; // Set new root.
            if (node->fs) {
                node->fs->fsref();  // New filesystem gets a reference
            }
            proc->lock.release();

            if (oldroot) {
                if (oldroot->fs) {
                    oldroot->fs->fsunref();  // Old filesystem loses a reference
                }
                oldroot->unref(); // Unreference old root.
            }
            SYSCALL_RET(0);
        }

        extern "C" ssize_t sys_getcwd(char *buf, size_t size) {
            SYSCALL_LOG("sys_getcwd(%p, %lu).\n", buf, size);

            if (!buf || size == 0) {
                SYSCALL_RET(-EINVAL);
            }

            if (!NMem::UserCopy::valid(buf, size)) {
                SYSCALL_RET(-EFAULT);
            }

            NSched::Process *proc = NArch::CPU::get()->currthread->process;
            NLib::ScopeIRQSpinlock guard(&proc->lock);

            INode *cwd = proc->cwd;
            if (!cwd) {
                cwd = vfs->getroot(); // getroot() increments refcount.
                if (!cwd) {
                    SYSCALL_RET(-ENOENT);
                }
            } else {
                cwd->ref(); // Increase reference for our use.
            }

            // Get the effective root (process root if chrooted, otherwise global root).
            INode *effroot = proc->root;
            if (!effroot) {
                effroot = vfs->getroot(); // getroot() increments refcount.
            } else {
                effroot->ref();
            }

            // Build path by walking up the parent chain to effective root.
            Path resultpath = Path(true); // Start with absolute path.
            INode *current = cwd;

            while (current && current != effroot) {
                const char *name = current->getname();
                if (name && name[0] != '\0') {
                    resultpath.pushcomponent(name, false); // Push to front (we're walking backwards).
                }
                INode *parent = current->getparent();

                if (!parent) {
                    // Reached root without finding effective root, this shouldn't happen.
                    current->unref();
                    effroot->unref();
                    SYSCALL_RET(-ENOENT);
                }

                parent->ref(); // Increment parent refcount.
                current->unref(); // Decrement current refcount.
                current = parent;
            }

            // Clean up remaining references.
            if (current) {
                current->unref();
            }
            effroot->unref();

            const char *pathstr = resultpath.construct();
            if (!pathstr) {
                SYSCALL_RET(-ENOMEM);
            }

            size_t pathlen = NLib::strlen(pathstr);
            if (pathlen + 1 > size) {
                delete[] pathstr;
                SYSCALL_RET(-ERANGE);
            }

            // Copy to userspace.
            int ret = NMem::UserCopy::copyto(buf, pathstr, pathlen + 1);
            delete[] pathstr;

            if (ret < 0) {
                SYSCALL_RET(ret);
            }

            SYSCALL_RET(pathlen + 1); // Return the length including null terminator on success.
        }

        extern "C" uint64_t sys_read(int fd, void *buf, size_t count) {
            SYSCALL_LOG("sys_read(%d, %p, %lu).\n", fd, buf, count);
            if (fd < 0) {
                SYSCALL_RET(-EBADF);
            }

            if (!buf && count > 0) {
                SYSCALL_RET(-EFAULT);
            }

            if (!NMem::UserCopy::valid(buf, count)) {
                SYSCALL_RET(-EFAULT); // Invalid buffer.
            }

            NSched::Process *proc = NArch::CPU::get()->currthread->process;

            FileDescriptor *desc = proc->fdtable->get(fd);
            if (!desc) {
                SYSCALL_RET(-EBADF);
            }

            int accmode = desc->getflags() & O_ACCMODE;

            if (accmode != O_RDONLY && accmode != O_RDWR) {
                SYSCALL_RET(-EBADF); // Not open for read.
            }

            INode *node = desc->getnode();

            struct stat st = node->getattr();

            if (S_ISDIR(st.st_mode)) {
                node->unref();
                SYSCALL_RET(-EISDIR);
            }

            if (S_ISLNK(st.st_mode)) {
                node->unref();
                SYSCALL_RET(-EINVAL);
            }

            ssize_t read = node->read(buf, count, desc->getoff(), desc->getflags());
            node->unref();
            if (read < 0) {
                SYSCALL_RET(read); // Return error code.
            }

            desc->addoff(read); // Increment offset.

            SYSCALL_RET(read); // Return the actual number of bytes read.
        }

        extern "C" uint64_t sys_write(int fd, const void *buf, size_t count) {
            SYSCALL_LOG("sys_write(%d, %p, %lu).\n", fd, buf, count);

            if (fd < 0) {
                SYSCALL_RET(-EBADF);
            }

            if (!buf && count > 0) {
                SYSCALL_RET(-EFAULT);
            }

            if (!NMem::UserCopy::valid(buf, count)) {
                SYSCALL_RET(-EFAULT); // Invalid buffer.
            }

            NSched::Process *proc = NArch::CPU::get()->currthread->process;

            FileDescriptor *desc = proc->fdtable->get(fd);
            if (!desc) {
                SYSCALL_RET(-EBADF);
            }

            int accmode = desc->getflags() & O_ACCMODE;

            if (accmode != O_WRONLY && accmode != O_RDWR) {
                SYSCALL_RET(-EBADF);
            }

            INode *node = desc->getnode();
            struct stat st = node->getattr();
            if (S_ISDIR(st.st_mode)) {
                node->unref();
                SYSCALL_RET(-EISDIR);
            }

            uint64_t wroff = desc->getoff();
            if (desc->getflags() & O_APPEND) {
                wroff = st.st_size; // We should begin at the end of the file.
            }

            ssize_t written = node->write(buf, count, wroff, desc->getflags());
            node->unref();
            if (written < 0) {
                SYSCALL_RET(written);
            }

            if (!(desc->getflags() & O_APPEND)) {
                desc->setoff(wroff + written); // New offset should be here.
            }

            SYSCALL_RET(written);
        }

        extern "C" uint64_t sys_ioctl(int fd, unsigned long request, uint64_t arg) {
            SYSCALL_LOG("sys_ioctl(%d, %lu, %p).\n", fd, request, arg);

            if (fd < 0) {
                SYSCALL_RET(-EBADF);
            }

            // Note: arg validation is request-specific and handled by ioctl implementation
            // Some ioctls use arg as an integer value, not a pointer

            NSched::Process *proc = NArch::CPU::get()->currthread->process;

            FileDescriptor *desc = proc->fdtable->get(fd);
            if (!desc) {
                SYSCALL_RET(-EBADF);
            }

            INode *node = desc->getnode();

            struct stat st = node->getattr();

            if (!S_ISCHR(st.st_mode)) {
                node->unref();
                SYSCALL_RET(-ENOTTY); // Not character special.
            }
            int ret = node->ioctl(request, arg);
            node->unref();

            SYSCALL_RET(ret);
        }

        extern "C" uint64_t sys_seek(int fd, off_t off, int whence) {
            SYSCALL_LOG("sys_seek(%d, %ld, %d).\n", fd, off, whence);

            if (fd < 0) {
                SYSCALL_RET(-EBADF);
            }

            NSched::Process *proc = NArch::CPU::get()->currthread->process;

            FileDescriptor *desc = proc->fdtable->get(fd);
            if (!desc) {
                SYSCALL_RET(-EBADF);
            }

            INode *node = desc->getnode();

            struct stat st = node->getattr();

            if (S_ISFIFO(st.st_mode) || S_ISSOCK(st.st_mode)) {
                node->unref();
                SYSCALL_RET(-ESPIPE);
            }
            node->unref();

            off_t newoff = 0;
            switch (whence) {
                case SEEK_SET:
                    newoff = off; // Works from absolute position.
                    break;
                case SEEK_CUR:
                    newoff = desc->getoff() + off; // Relative.
                    break;
                case SEEK_END:
                    newoff = st.st_size + off; // Relative from end of file.
                    break;
                default:
                    SYSCALL_RET(-EINVAL);
            }

            if (newoff < 0) {
                SYSCALL_RET(-EINVAL); // Ultimately, invalid offset.
            }

            desc->setoff(newoff); // Set new offset.
            SYSCALL_RET(newoff);
        }

        extern "C" uint64_t sys_fcntl(int fd, int cmd, uint64_t arg) {
            SYSCALL_LOG("sys_fcntl(%d, %d, %p).\n", fd, cmd, arg);

            if (fd < 0) {
                SYSCALL_RET(-EBADF);
            }

            NSched::Process *proc = NArch::CPU::get()->currthread->process;

            FileDescriptor *desc = proc->fdtable->get(fd);
            if (!desc) {
                SYSCALL_RET(-EBADF);
            }

            switch (cmd) {
                case F_DUPFD:
                    SYSCALL_RET(proc->fdtable->dup2(fd, (int)arg, true));
                case F_GETFD:
                    SYSCALL_RET(proc->fdtable->iscloseonexec(fd) ? FD_CLOEXEC : 0);
                case F_SETFD:
                    if (arg & FD_CLOEXEC) {
                        proc->fdtable->setcloseonexec(fd, true);
                    } else {
                        proc->fdtable->setcloseonexec(fd, false);
                    }
                    SYSCALL_RET(0);
                case F_GETFL:
                    SYSCALL_RET(desc->getflags());
                case F_SETFL:
                    desc->setflags((int)arg);
                    SYSCALL_RET(0);
                case F_DUPFD_CLOEXEC: {
                    int newfd = proc->fdtable->dup2(fd, (int)arg, true);
                    if (newfd >= 0) {
                        proc->fdtable->setcloseonexec(newfd, true);
                    }
                    SYSCALL_RET(newfd);
                }
                case F_SETLK64:
                case F_SETLKW64:
                case F_GETLK64:
                    SYSCALL_RET(0); // No locking implemented.
                default:
                    SYSCALL_RET(-EINVAL);
            }
        }

        // Userspace definition of `struct stat`.
        struct ustat {
            uint64_t        st_dev;
            uint64_t        st_ino;
            uint64_t        st_nlink;
            uint32_t        st_mode;
            uint32_t        st_uid;
            uint32_t        st_gid;
            uint64_t        st_rdev;
            int64_t         st_size;
            int64_t         st_blksize;
            int64_t         st_blocks;
            long            st_atime;
            long            st_atime_nsec;
            long            st_mtime;
            long            st_mtime_nsec;
            long            st_ctime;
            long            st_ctime_nsec;
        };

        extern "C" uint64_t sys_stat(int fd, const char *path, size_t len, struct ustat *statbuf, int flags) {
            SYSCALL_LOG("sys_stat(%d, %s, %lu, %p, %d).\n", fd, path, len, statbuf, flags);

            if (fd == AT_FDCWD) {
                // Stat is path relative to CWD.
                ssize_t pathsize = NMem::UserCopy::strnlen(path, len);
                if (pathsize < 0) {
                    SYSCALL_RET(pathsize); // Contains errno.
                }
                char *pathbuf = new char[pathsize + 1];
                if (!pathbuf) {
                    SYSCALL_RET(-ENOMEM);
                }

                int ret = NMem::UserCopy::strncpyfrom(pathbuf, path, pathsize);
                if (ret < 0) {
                    delete[] pathbuf;
                    SYSCALL_RET(ret); // Contains errno.
                }

                pathbuf[pathsize] = '\0';

                NSched::Process *proc = NArch::CPU::get()->currthread->process;
                proc->lock.acquire();

                INode *cwd = proc->cwd;
                if (!cwd) {
                    cwd = vfs->getroot(); // If the process has no CWD, we use root.
                } else {
                    cwd->ref(); // Increase reference.
                }
                INode *procroot = proc->root;
                if (procroot) {
                    procroot->ref();
                }
                proc->lock.release();

                INode *node;
                ssize_t res = vfs->resolve(pathbuf, &node, cwd, !(flags & AT_SYMLINK_NOFOLLOW), procroot);
                cwd->unref();
                if (procroot) {
                    procroot->unref();
                }
                delete[] pathbuf;
                if (res < 0) {
                    SYSCALL_RET(res);
                }

                struct stat st = node->getattr();
                node->unref();

                struct ustat ust;
                ust.st_dev = st.st_dev;
                ust.st_ino = st.st_ino;
                ust.st_nlink = st.st_nlink;
                ust.st_mode = st.st_mode;
                ust.st_uid = st.st_uid;
                ust.st_gid = st.st_gid;
                ust.st_rdev = st.st_rdev;
                ust.st_size = st.st_size;
                ust.st_blksize = st.st_blksize;
                ust.st_blocks = st.st_blocks;
                ust.st_atime = st.st_atime;
                ust.st_atime_nsec = 0;
                ust.st_mtime = st.st_mtime;
                ust.st_mtime_nsec = 0;
                ust.st_ctime = st.st_ctime;
                ust.st_ctime_nsec = 0;

                res = NMem::UserCopy::copyto(statbuf, &ust, sizeof(struct ustat));
                if (res < 0) {
                    SYSCALL_RET(res);
                }
                SYSCALL_RET(0);
            } else if (fd >= 0) {
                if (len == 0) { // Stat should be of an FD.
                    // Ensure that path is empty string.
                    char ch;
                    int res = NMem::UserCopy::copyfrom(&ch, path, 1);
                    if (res < 0) {
                        SYSCALL_RET(res);
                    }
                    if (ch != '\0') {
                        SYSCALL_RET(-EINVAL);
                    }

                    NSched::Process *proc = NArch::CPU::get()->currthread->process;
                    FileDescriptor *desc = proc->fdtable->get(fd);
                    if (!desc) {
                        SYSCALL_RET(-EBADF);
                    }

                    INode *node = desc->getnode();
                    struct stat st = node->getattr();
                    node->unref();

                    struct ustat ust;
                    ust.st_dev = st.st_dev;
                    ust.st_ino = st.st_ino;
                    ust.st_nlink = st.st_nlink;
                    ust.st_mode = st.st_mode;
                    ust.st_uid = st.st_uid;
                    ust.st_gid = st.st_gid;
                    ust.st_rdev = st.st_rdev;
                    ust.st_size = st.st_size;
                    ust.st_blksize = st.st_blksize;
                    ust.st_blocks = st.st_blocks;
                    ust.st_atime = st.st_atime;
                    ust.st_atime_nsec = 0;
                    ust.st_mtime = st.st_mtime;
                    ust.st_mtime_nsec = 0;
                    ust.st_ctime = st.st_ctime;
                    ust.st_ctime_nsec = 0;

                    int res2 = NMem::UserCopy::copyto(statbuf, &ust, sizeof(struct ustat));
                    if (res2 < 0) {
                        SYSCALL_RET(res2);
                    }
                    SYSCALL_RET(0);
                } else { // Stat is path relative to FD.
                    ssize_t pathsize = NMem::UserCopy::strnlen(path, len);
                    if (pathsize < 0) {
                        SYSCALL_RET(pathsize); // Contains errno.
                    }
                    char *pathbuf = new char[pathsize + 1];
                    if (!pathbuf) {
                        SYSCALL_RET(-ENOMEM);
                    }

                    int ret = NMem::UserCopy::strncpyfrom(pathbuf, path, pathsize);
                    if (ret < 0) {
                        delete[] pathbuf;
                        SYSCALL_RET(ret); // Contains errno.
                    }

                    pathbuf[pathsize] = '\0';

                    NSched::Process *proc = NArch::CPU::get()->currthread->process;
                    proc->lock.acquire();
                    INode *procroot = proc->root;
                    if (procroot) {
                        procroot->ref();
                    }
                    proc->lock.release();

                    FileDescriptor *desc = proc->fdtable->get(fd);
                    if (!desc) {
                        if (procroot) {
                            procroot->unref();
                        }
                        delete[] pathbuf;
                        SYSCALL_RET(-EBADF);
                    }

                    INode *dirnode = desc->getnode();
                    if (!S_ISDIR(dirnode->getattr().st_mode)) {
                        dirnode->unref();
                        if (procroot) {
                            procroot->unref();
                        }
                        delete[] pathbuf;
                        SYSCALL_RET(-ENOTDIR);
                    }

                    INode *node;
                    ssize_t res = vfs->resolve(pathbuf, &node, dirnode, !(flags & AT_SYMLINK_NOFOLLOW), procroot);
                    dirnode->unref();
                    if (procroot) {
                        procroot->unref();
                    }
                    delete[] pathbuf;
                    if (res < 0) {
                        SYSCALL_RET(res);
                    }

                    struct stat st = node->getattr();
                    node->unref();
                    struct ustat ust;
                    ust.st_dev = st.st_dev;
                    ust.st_ino = st.st_ino;
                    ust.st_nlink = st.st_nlink;
                    ust.st_mode = st.st_mode;
                    ust.st_uid = st.st_uid;
                    ust.st_gid = st.st_gid;
                    ust.st_rdev = st.st_rdev;
                    ust.st_size = st.st_size;
                    ust.st_blksize = st.st_blksize;
                    ust.st_blocks = st.st_blocks;
                    ust.st_atime = st.st_atime;
                    ust.st_atime_nsec = 0;
                    ust.st_mtime = st.st_mtime;
                    ust.st_mtime_nsec = 0;
                    ust.st_ctime = st.st_ctime;
                    ust.st_ctime_nsec = 0;

                    int res2 = NMem::UserCopy::copyto(statbuf, &ust, sizeof(struct ustat));
                    if (res2 < 0) {
                        SYSCALL_RET(res2);
                    }
                    SYSCALL_RET(0);
                }
            }
            SYSCALL_RET(-EBADF); // Invalid FD.
        }

        extern "C" uint64_t sys_access(int fd, const char *path, size_t len, int mode, int flags) {
            SYSCALL_LOG("sys_access(%d, %s, %lu, %d, %d).\n", fd, path, len, mode, flags);

            ssize_t pathsize = NMem::UserCopy::strnlen(path, len);
            if (pathsize < 0) {
                SYSCALL_RET(pathsize); // Contains errno.
            }

            char *pathbuf = new char[pathsize + 1];
            if (!pathbuf) {
                SYSCALL_RET(-ENOMEM);
            }

            int ret = NMem::UserCopy::strncpyfrom(pathbuf, path, pathsize);
            if (ret < 0) {
                delete[] pathbuf;
                SYSCALL_RET(ret); // Contains errno.
            }

            pathbuf[pathsize] = '\0';

            NSched::Process *proc = NArch::CPU::get()->currthread->process;
            proc->lock.acquire();

            INode *dirnode = NULL;
            if (pathbuf[0] == '/') { // Absolute path invalidates dirfd.
                dirnode = vfs->getroot();
            } else {
                if (fd == AT_FDCWD) { // Special case: FD is CWD.
                    dirnode = proc->cwd;
                    if (!dirnode) { // If the process has no CWD, we use root.
                        dirnode = vfs->getroot();
                    } else {
                        dirnode->ref(); // Increase reference.
                    }
                } else {
                    FileDescriptor *desc = proc->fdtable->get(fd);
                    if (!desc) {
                        delete[] pathbuf;
                        proc->lock.release();
                        SYSCALL_RET(-EBADF);
                    }

                    dirnode = desc->getnode();
                    if (!S_ISDIR(dirnode->getattr().st_mode)) {
                        dirnode->unref();
                        delete[] pathbuf;
                        proc->lock.release();
                        SYSCALL_RET(-ENOTDIR);
                    }
                }
            }

            // Use real UID/GID unless AT_EACCESS is set.
            int uid = (flags & AT_EACCESS) ? proc->euid : proc->uid;
            int gid = (flags & AT_EACCESS) ? proc->egid : proc->gid;
            INode *procroot = proc->root;
            if (procroot) {
                procroot->ref();
            }
            proc->lock.release();

            INode *node;
            ssize_t res = vfs->resolve(pathbuf, &node, dirnode, !(flags & AT_SYMLINK_NOFOLLOW), procroot);
            dirnode->unref();
            if (procroot) {
                procroot->unref();
            }
            delete[] pathbuf;

            if (res < 0) {
                SYSCALL_RET(res); // File not found or other resolution error.
            }

            // F_OK just checks for existence, which we've already verified.
            if (mode == F_OK) {
                node->unref();
                SYSCALL_RET(0);
            }

            struct stat st = node->getattr();
            node->unref();

            // Root always has access (except for execute on non-executable files).
            if (uid == 0) {
                // Root can read/write anything, but execute only if at least one execute bit is set.
                if ((mode & X_OK) && !S_ISDIR(st.st_mode) && !(st.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH))) {
                    SYSCALL_RET(-EACCES);
                }
                SYSCALL_RET(0);
            }

            // Check each requested permission.
            if (mode & R_OK) {
                if (uid == (int)st.st_uid) {
                    if (!(st.st_mode & S_IRUSR)) {
                        SYSCALL_RET(-EACCES);
                    }
                } else if (gid == (int)st.st_gid) {
                    if (!(st.st_mode & S_IRGRP)) {
                        SYSCALL_RET(-EACCES);
                    }
                } else {
                    if (!(st.st_mode & S_IROTH)) {
                        SYSCALL_RET(-EACCES);
                    }
                }
            }

            if (mode & W_OK) {
                if (uid == (int)st.st_uid) {
                    if (!(st.st_mode & S_IWUSR)) {
                        SYSCALL_RET(-EACCES);
                    }
                } else if (gid == (int)st.st_gid) {
                    if (!(st.st_mode & S_IWGRP)) {
                        SYSCALL_RET(-EACCES);
                    }
                } else {
                    if (!(st.st_mode & S_IWOTH)) {
                        SYSCALL_RET(-EACCES);
                    }
                }
            }

            if (mode & X_OK) {
                if (uid == (int)st.st_uid) {
                    if (!(st.st_mode & S_IXUSR)) {
                        SYSCALL_RET(-EACCES);
                    }
                } else if (gid == (int)st.st_gid) {
                    if (!(st.st_mode & S_IXGRP)) {
                        SYSCALL_RET(-EACCES);
                    }
                } else {
                    if (!(st.st_mode & S_IXOTH)) {
                        SYSCALL_RET(-EACCES);
                    }
                }
            }

            SYSCALL_RET(0);
        }

        extern "C" uint64_t sys_pipe(int pipefd[2], int flags) {
            SYSCALL_LOG("sys_pipe(%p).\n", pipefd);

            if (!pipefd) {
                SYSCALL_RET(-EFAULT);
            }

            if (!NMem::UserCopy::valid(pipefd, sizeof(int) * 2)) {
                SYSCALL_RET(-EFAULT);
            }

            // Only O_CLOEXEC and O_NONBLOCK are valid flags for pipe2.
            if (flags & ~(O_CLOEXEC | O_NONBLOCK)) {
                SYSCALL_RET(-EINVAL);
            }

            struct stat attr {
                .st_ino = 1,
                .st_mode = S_IFIFO | 0666
            };

            PipeFS::PipeNode *pipe;
            ssize_t res = PipeFS::pipefs->create("", (INode **)&pipe, attr);
            if (res < 0) {
                SYSCALL_RET(res);
            }

            NSched::Process *proc = NArch::CPU::get()->currthread->process;
            NLib::ScopeIRQSpinlock guard(&proc->lock);

            // Open read end.
            int readfd = proc->fdtable->open(pipe, O_RDONLY | (flags & (O_CLOEXEC | O_NONBLOCK)));
            if (readfd < 0) {
                pipe->unref();
                SYSCALL_RET(readfd);
            }
            pipe->open(O_RDONLY); // Trigger open hook.

            // Open write end.
            int writefd = proc->fdtable->open(pipe, O_WRONLY | (flags & (O_CLOEXEC | O_NONBLOCK)));
            if (writefd < 0) {
                proc->fdtable->close(readfd); // Close and undo pipe->open(O_RDONLY).
                pipe->unref();
                SYSCALL_RET(writefd);
            }
            pipe->open(O_WRONLY); // Trigger open hook.

            pipe->unref(); // FD table holds references now.

            res = NMem::UserCopy::copyto(pipefd, &readfd, sizeof(int));
            if (res < 0) {
                proc->fdtable->close(readfd);
                proc->fdtable->close(writefd);
                SYSCALL_RET(res);
            }
            res = NMem::UserCopy::copyto(pipefd + 1, &writefd, sizeof(int));
            if (res < 0) {
                proc->fdtable->close(readfd);
                proc->fdtable->close(writefd);
                SYSCALL_RET(res);
            }

            SYSCALL_RET(0);
        }

        extern "C" uint64_t sys_readlink(int fd, const char *path, size_t len, char *buf, size_t bufsize) {
            SYSCALL_LOG("sys_readlink(%d, %s, %lu, %p, %lu).\n", fd, path, len, buf, bufsize);

            ssize_t pathsize = NMem::UserCopy::strnlen(path, len);
            if (pathsize < 0) {
                SYSCALL_RET(pathsize); // Contains errno.
            }
            char *pathbuf = new char[pathsize + 1];
            if (!pathbuf) {
                SYSCALL_RET(-ENOMEM);
            }

            int ret = NMem::UserCopy::strncpyfrom(pathbuf, path, pathsize);
            if (ret < 0) {
                delete[] pathbuf;
                SYSCALL_RET(ret); // Contains errno.
            }

            pathbuf[pathsize] = '\0';

            NSched::Process *proc = NArch::CPU::get()->currthread->process;
            proc->lock.acquire();

            INode *dirnode;
            if (fd == AT_FDCWD) {
                dirnode = proc->cwd;
                if (!dirnode) {
                    dirnode = vfs->getroot();
                } else {
                    dirnode->ref();
                }
            } else {
                FileDescriptor *desc = proc->fdtable->get(fd);
                if (!desc) {
                    delete[] pathbuf;
                    proc->lock.release();
                    SYSCALL_RET(-EBADF);
                }

                dirnode = desc->getnode();
                if (!S_ISDIR(dirnode->getattr().st_mode)) {
                    dirnode->unref();
                    delete[] pathbuf;
                    proc->lock.release();
                    SYSCALL_RET(-ENOTDIR);
                }
            }
            INode *procroot = proc->root;
            if (procroot) {
                procroot->ref();
            }
            proc->lock.release();

            INode *node;
            ssize_t res = vfs->resolve(pathbuf, &node, dirnode, false, procroot);
            dirnode->unref();
            if (procroot) {
                procroot->unref();
            }
            delete[] pathbuf;
            if (res < 0) {
                SYSCALL_RET(res);
            }

            ssize_t read = node->readlink(buf, bufsize);
            node->unref();
            if (read < 0) {
                SYSCALL_RET(read); // Return error code.
            }

            SYSCALL_RET(read); // Return number of bytes read.
        }

        extern "C" ssize_t sys_unlink(int fd, const char *path, size_t len, int flags) {
            SYSCALL_LOG("sys_unlink(%d, %s, %lu, %d).\n", fd, path, len, flags);

            ssize_t pathsize = NMem::UserCopy::strnlen(path, len);
            if (pathsize < 0) {
                SYSCALL_RET(pathsize); // Contains errno.
            }
            char *pathbuf = new char[pathsize + 1];
            if (!pathbuf) {
                SYSCALL_RET(-ENOMEM);
            }
            int ret = NMem::UserCopy::strncpyfrom(pathbuf, path, pathsize);
            if (ret < 0) {
                delete[] pathbuf;
                SYSCALL_RET(ret); // Contains errno.
            }
            pathbuf[pathsize] = '\0';

            NSched::Process *proc = NArch::CPU::get()->currthread->process;
            proc->lock.acquire();
            INode *dirnode;
            if (fd == AT_FDCWD) {
                dirnode = proc->cwd;
                if (!dirnode) {
                    dirnode = vfs->getroot();
                } else {
                    dirnode->ref();
                }
            } else {
                FileDescriptor *desc = proc->fdtable->get(fd);
                if (!desc) {
                    delete[] pathbuf;
                    proc->lock.release();
                    SYSCALL_RET(-EBADF);
                }
                dirnode = desc->getnode();
                if (!S_ISDIR(dirnode->getattr().st_mode)) {
                    dirnode->unref();
                    delete[] pathbuf;
                    proc->lock.release();
                    SYSCALL_RET(-ENOTDIR);
                }
            }

            int uid = proc->uid;
            int gid = proc->gid;
            INode *procroot = proc->root;
            if (procroot) {
                procroot->ref();
            }
            proc->lock.release();
            ssize_t res = vfs->unlink(pathbuf, dirnode, flags, uid, gid, procroot);
            dirnode->unref();
            if (procroot) {
                procroot->unref();
            }
            delete[] pathbuf;
            SYSCALL_RET(res); // Return result of unlink operation.
        }

        struct timespec {
            long tv_sec;
            long tv_nsec;
        };

        extern "C" uint64_t sys_ppoll(struct pollfd *fds, size_t nfds, struct timespec *timeout, NLib::sigset_t *sigmask) {
            SYSCALL_LOG("sys_ppoll(%p, %u, %p, %p).\n", fds, nfds, timeout, sigmask);

            struct pollfd *kfds = NULL;
            if (nfds > 0) {
                if (!fds) {
                    SYSCALL_RET(-EFAULT);
                }

                size_t fds_size = sizeof(struct pollfd) * nfds;
                if (!NMem::UserCopy::valid(fds, fds_size)) {
                    SYSCALL_RET(-EFAULT);
                }

                kfds = new struct pollfd[nfds];
                if (!kfds) {
                    SYSCALL_RET(-ENOMEM);
                }

                int res = NMem::UserCopy::copyfrom(kfds, fds, fds_size);
                if (res < 0) {
                    delete[] kfds;
                    SYSCALL_RET(res);
                }
            } else {
                // No fds to poll.
                struct timespec ktmo;
                if (timeout) { // Simply just wait for the timeout period.
                    if (!NMem::UserCopy::valid(timeout, sizeof(struct timespec))) {
                        SYSCALL_RET(-EFAULT);
                    }
                    int res = NMem::UserCopy::copyfrom(&ktmo, timeout, sizeof(struct timespec));
                    if (res < 0) {
                        SYSCALL_RET(res);
                    }

                    if (ktmo.tv_sec < 0 || ktmo.tv_nsec < 0 || ktmo.tv_nsec >= 1000000000) {
                        SYSCALL_RET(-EINVAL);
                    }

                    uint64_t timeoutms = ktmo.tv_sec * 1000 + ktmo.tv_nsec / 1000000;
                    int ret = NSched::sleep(timeoutms);
                    if (ret < 0) {
                        SYSCALL_RET(ret); // Return -EINTR if interrupted.
                    }
                } else {
                    // Infinite wait, so just yield (this acts like a sys_pause would).

                    // XXX: Set thread signal mask?

                    NLib::sigset_t ksigmask;
                    if (sigmask) {
                        if (!NMem::UserCopy::valid(sigmask, sizeof(ksigmask))) {
                            delete[] kfds;
                            SYSCALL_RET(-EFAULT);
                        }
                        int res = NMem::UserCopy::copyfrom(&ksigmask, sigmask, sizeof(ksigmask));
                        if (res < 0) {
                            delete[] kfds;
                            SYSCALL_RET(res);
                        }
                    } else {
                        // Empty signal mask.
                        NLib::memset(&ksigmask, 0, sizeof(ksigmask));
                    }

                    // Apply signal mask for the duration of the poll (per-thread).
                    NSched::Thread *thread = NArch::CPU::get()->currthread;
                    NSched::Process *proc = thread->process;
                    NLib::sigset_t oldmask = __atomic_load_n(&thread->blocked, memory_order_acquire);
                    __atomic_store_n(&thread->blocked, ksigmask, memory_order_release);

                    NArch::CPU::get()->setint(false);
                    // Untracked sleep state, so we won't be woken up until a signal arrives.
                    __atomic_store_n(&NArch::CPU::get()->currthread->tstate, NSched::Thread::PAUSED, memory_order_release);
                    NArch::CPU::get()->setint(true);
                    NSched::yield();

                    // Restore old signal mask before returning (per-thread).
                    __atomic_store_n(&thread->blocked, oldmask, memory_order_release);

                    SYSCALL_RET(-EINTR); // Indicate we were interrupted by a signal.
                }

                SYSCALL_RET(0);
            }


            NLib::sigset_t ksigmask;
            if (sigmask) {
                if (!NMem::UserCopy::valid(sigmask, sizeof(ksigmask))) {
                    delete[] kfds;
                    SYSCALL_RET(-EFAULT);
                }
                int res = NMem::UserCopy::copyfrom(&ksigmask, sigmask, sizeof(ksigmask));
                if (res < 0) {
                    delete[] kfds;
                    SYSCALL_RET(res);
                }
            } else {
                // Empty signal mask.
                NLib::memset(&ksigmask, 0, sizeof(ksigmask));
            }

            struct timespec ktmo;
            if (timeout) { // Simply just wait for the timeout period.
                if (!NMem::UserCopy::valid(timeout, sizeof(struct timespec))) {
                    delete[] kfds;
                    SYSCALL_RET(-EFAULT);
                }
                int res = NMem::UserCopy::copyfrom(&ktmo, timeout, sizeof(struct timespec));
                if (res < 0) {
                    delete[] kfds;
                    SYSCALL_RET(res);
                }

                if (ktmo.tv_sec < 0 || ktmo.tv_nsec < 0 || ktmo.tv_nsec >= 1000000000) {
                    delete[] kfds;
                    SYSCALL_RET(-EINVAL);
                }
            }

            // Apply signal mask for the duration of the poll (per-thread).
            NSched::Thread *thread = NArch::CPU::get()->currthread;
            NSched::Process *proc = thread->process;
            NLib::sigset_t oldmask = __atomic_load_n(&thread->blocked, memory_order_acquire);
            __atomic_store_n(&thread->blocked, ksigmask, memory_order_release);

            size_t eventcount = 0; // How many fds ended up with non-zero revents.

            // Track timeout using monotonic clock for accurate timing.
            uint64_t deadlinens = 0;
            bool hastimeout = (timeout != NULL);
            if (hastimeout) {
                NSys::Clock::timespec now;
                NSys::Clock::Clock *clock = NSys::Clock::getclock(NSys::Clock::CLOCK_MONOTONIC);
                if (clock && clock->gettime(&now) == 0) {
                    deadlinens = (uint64_t)now.tv_sec * 1000000000ULL + (uint64_t)now.tv_nsec;
                    deadlinens += (uint64_t)ktmo.tv_sec * 1000000000ULL + (uint64_t)ktmo.tv_nsec;
                }
            }

            while (true) {
                for (size_t i = 0; i < nfds; i++) {
                    if (kfds[i].fd < 0) {
                        continue; // Ignore negative FDs.
                    }

                    NSched::Process *proc = NArch::CPU::get()->currthread->process;
                    NLib::ScopeIRQSpinlock guard(&proc->lock);

                    FileDescriptor *desc = proc->fdtable->get(kfds[i].fd);
                    if (!desc) {
                        // Restore old signal mask before returning (per-thread).
                        __atomic_store_n(&thread->blocked, oldmask, memory_order_release);
                        delete[] kfds;
                        SYSCALL_RET(-EBADF);
                    }

                    struct pollfd *pfd = &kfds[i];

                    INode *node = desc->getnode();
                    int res = node->poll(pfd->events, &pfd->revents, desc->getflags());
                    node->unref();
                    if (res < 0) {
                        // Restore old signal mask before returning (per-thread).
                        __atomic_store_n(&thread->blocked, oldmask, memory_order_release);
                        delete[] kfds;
                        SYSCALL_RET(res);
                    }

                    if (pfd->revents != 0) {
                        eventcount++;
                    }
                }

                if (eventcount > 0) {
                    // Some events are ready, break and return what we have thus far.
                    break;
                }

                // No events ready yet, check if we have a timeout.
                if (hastimeout) {
                    // Check remaining time.
                    NSys::Clock::timespec now;
                    NSys::Clock::Clock *clock = NSys::Clock::getclock(NSys::Clock::CLOCK_MONOTONIC);
                    uint64_t nowns = 0;
                    if (clock && clock->gettime(&now) == 0) {
                        nowns = (uint64_t)now.tv_sec * 1000000000ULL + (uint64_t)now.tv_nsec;
                    }

                    if (nowns >= deadlinens) {
                        // Timeout expired.
                        break;
                    }

                    // Calculate remaining time in ms.
                    uint64_t remainingns = deadlinens - nowns;
                    uint64_t remainingms = (remainingns + 999999) / 1000000; // Round up to ms.

                    if (remainingms == 0) {
                        break; // Timeout effectively expired.
                    }

                    // Sleep for a small interval (min of remaining time or 10ms) to allow checking for events.
                    uint64_t sleepms = remainingms < 10 ? remainingms : 10;
                    int ret = NSched::sleep(sleepms);
                    if (ret < 0) {
                        // Sleep was interrupted by signal. Restore old mask and return.
                        __atomic_store_n(&thread->blocked, oldmask, memory_order_release);
                        delete[] kfds;
                        SYSCALL_RET(ret);
                    }
                    // Continue loop to re-poll fds after short sleep.
                    continue;
                }

                NSched::yield(); // Yield to avoid thrashing the CPU.
            }
            // Restore old signal mask before returning (per-thread).
            __atomic_store_n(&thread->blocked, oldmask, memory_order_release);

            // Copy results back to userspace.
            if (nfds > 0 && kfds) {
                int res = NMem::UserCopy::copyto(fds, kfds, sizeof(struct pollfd) * nfds);
                delete[] kfds;
                if (res < 0) {
                    SYSCALL_RET(res);
                }
            }

            SYSCALL_RET(eventcount);
        }

        extern "C" uint64_t sys_mknodat(int fd, const char *path, size_t len, int mode, int dev) {
            SYSCALL_LOG("sys_mknodat(%d, %s, %lu, %o, %d).\n", fd, path, len, mode, dev);

            ssize_t pathsize = NMem::UserCopy::strnlen(path, len);
            if (pathsize < 0) {
                SYSCALL_RET(pathsize); // Contains errno.
            }
            char *pathbuf = new char[pathsize + 1];
            if (!pathbuf) {
                SYSCALL_RET(-ENOMEM);
            }
            int ret = NMem::UserCopy::strncpyfrom(pathbuf, path, pathsize);
            if (ret < 0) {
                delete[] pathbuf;
                SYSCALL_RET(ret); // Contains errno.
            }
            pathbuf[pathsize] = '\0';

            NSched::Process *proc = NArch::CPU::get()->currthread->process;
            proc->lock.acquire();
            INode *dirnode;
            if (fd == AT_FDCWD) {
                dirnode = proc->cwd;
                if (!dirnode) {
                    dirnode = vfs->getroot();
                } else {
                    dirnode->ref();
                }
            } else {
                FileDescriptor *desc = proc->fdtable->get(fd);
                if (!desc) {
                    delete[] pathbuf;
                    proc->lock.release();
                    SYSCALL_RET(-EBADF);
                }
                dirnode = desc->getnode();
                if (!S_ISDIR(dirnode->getattr().st_mode)) {
                    dirnode->unref();
                    delete[] pathbuf;
                    proc->lock.release();
                    SYSCALL_RET(-ENOTDIR);
                }
            }

            // Check permissions to create in this directory.
            bool ok = vfs->checkaccess(dirnode, O_WRONLY | O_EXEC, proc->euid, proc->egid);
            if (!ok) {
                dirnode->unref();
                delete[] pathbuf;
                proc->lock.release();
                SYSCALL_RET(-EACCES);
            }

            // Setup basic attributes, specific filesystems fill in the rest.
            struct stat attr {
                .st_mode = mode,
                .st_uid = proc->euid,
                .st_gid = proc->egid,
                .st_rdev = dev
            };

            INode *procroot = proc->root;
            if (procroot) {
                procroot->ref();
            }
            proc->lock.release();

            INode *nodeout = NULL;
            ssize_t res = vfs->create(pathbuf, &nodeout, attr, dirnode, procroot);
            dirnode->unref();
            if (procroot) {
                procroot->unref();
            }
            delete[] pathbuf;
            if (res < 0) {
                SYSCALL_RET(res);
            }

            nodeout->unref();
            SYSCALL_RET(0);
        }

        extern "C" uint64_t sys_chmod(int fd, const char *path, size_t len, int mode, int flags) {
            SYSCALL_LOG("sys_chmod(%d, %s, %lu, %o, %d).\n", fd, path, len, mode, flags);

            // FCHMODAT-like syscall, handles fchmodat, fchmod, and chmod.

            ssize_t res = NMem::UserCopy::valid(path, len);
            if (res < 0) {
                SYSCALL_RET(res); // Contains errno.
            }

            ssize_t pathsize = NMem::UserCopy::strnlen(path, len);
            if (pathsize < 0) {
                SYSCALL_RET(pathsize); // Contains errno.
            }
            char *pathbuf = new char[pathsize + 1];
            if (!pathbuf) {
                SYSCALL_RET(-ENOMEM);
            }

            res = NMem::UserCopy::strncpyfrom(pathbuf, path, pathsize);
            if (res < 0) {
                delete[] pathbuf;
                SYSCALL_RET(res); // Contains errno.
            }

            pathbuf[pathsize] = '\0';

            NSched::Process *proc = NArch::CPU::get()->currthread->process;
            proc->lock.acquire();
            INode *dirnode;
            if (fd == AT_FDCWD) {
                dirnode = proc->cwd;
                if (!dirnode) {
                    dirnode = vfs->getroot();
                } else {
                    dirnode->ref();
                }
            } else {
                FileDescriptor *desc = proc->fdtable->get(fd);
                if (!desc) {
                    delete[] pathbuf;
                    proc->lock.release();
                    SYSCALL_RET(-EBADF);
                }
                dirnode = desc->getnode();
                if (!S_ISDIR(dirnode->getattr().st_mode)) {
                    dirnode->unref();
                    delete[] pathbuf;
                    proc->lock.release();
                    SYSCALL_RET(-ENOTDIR);
                }
            }

            int uid = proc->euid;
            int gid = proc->egid;
            INode *procroot = proc->root;
            if (procroot) {
                procroot->ref();
            }
            proc->lock.release();

            // If AT_EMPTY_PATH is set and path is empty, change mode of dirnode itself.
            INode *targetnode = NULL;
            if ((flags & AT_EMPTY_PATH) && pathsize == 0) {
                targetnode = dirnode;
                targetnode->ref();
            } else {
                res = vfs->resolve(pathbuf, &targetnode, dirnode, !(flags & AT_SYMLINK_NOFOLLOW), procroot);
                if (res < 0) {
                    dirnode->unref();
                    if (procroot) {
                        procroot->unref();
                    }
                    delete[] pathbuf;
                    SYSCALL_RET(res);
                }
            }

            dirnode->unref();
            if (procroot) {
                procroot->unref();
            }
            delete[] pathbuf;
            // Check if we have permission to change the mode.
            bool ok = false;
            struct stat st = targetnode->getattr();
            if (uid == 0) {
                ok = true; // Root can always change mode.
            } else if (uid == st.st_uid) {
                ok = true; // Owner can change mode.
            }

            if (!ok) {
                targetnode->unref();
                SYSCALL_RET(-EACCES);
            }

            struct stat newattr = st;
            newattr.st_mode = (st.st_mode & S_IFMT) | (mode & ~S_IFMT);
            targetnode->setattr(newattr);
            targetnode->unref();
            SYSCALL_RET(0);
        }

        extern "C" uint64_t sys_chown(int fd, const char *path, size_t len, int uid, int gid, int flags) {
            SYSCALL_LOG("sys_chown(%d, %s, %lu, %d, %d, %d).\n", fd, path, len, uid, gid, flags);

            ssize_t res = NMem::UserCopy::valid(path, len);
            if (res < 0) {
                SYSCALL_RET(res); // Contains errno.
            }

            ssize_t pathsize = NMem::UserCopy::strnlen(path, len);
            if (pathsize < 0) {
                SYSCALL_RET(pathsize); // Contains errno.
            }
            char *pathbuf = new char[pathsize + 1];
            if (!pathbuf) {
                SYSCALL_RET(-ENOMEM);
            }

            res = NMem::UserCopy::strncpyfrom(pathbuf, path, pathsize);
            if (res < 0) {
                delete[] pathbuf;
                SYSCALL_RET(res); // Contains errno.
            }

            pathbuf[pathsize] = '\0';

            NSched::Process *proc = NArch::CPU::get()->currthread->process;
            proc->lock.acquire();
            INode *dirnode;
            if (fd == AT_FDCWD) {
                dirnode = proc->cwd;
                if (!dirnode) {
                    dirnode = vfs->getroot();
                } else {
                    dirnode->ref();
                }
            } else {
                FileDescriptor *desc = proc->fdtable->get(fd);
                if (!desc) {
                    delete[] pathbuf;
                    proc->lock.release();
                    SYSCALL_RET(-EBADF);
                }
                dirnode = desc->getnode();
                if (!S_ISDIR(dirnode->getattr().st_mode)) {
                    dirnode->unref();
                    delete[] pathbuf;
                    proc->lock.release();
                    SYSCALL_RET(-ENOTDIR);
                }
            }

            int euid = proc->euid;
            int egid = proc->egid;
            INode *procroot = proc->root;
            if (procroot) {
                procroot->ref();
            }
            proc->lock.release();

            // If AT_EMPTY_PATH is set and path is empty, change owner of dirnode itself.
            INode *targetnode = NULL;
            if ((flags & AT_EMPTY_PATH) && pathsize == 0) {
                targetnode = dirnode;
                targetnode->ref();
            } else {
                res = vfs->resolve(pathbuf, &targetnode, dirnode, !(flags & AT_SYMLINK_NOFOLLOW), procroot);
                if (res < 0) {
                    dirnode->unref();
                    if (procroot) {
                        procroot->unref();
                    }
                    delete[] pathbuf;
                    SYSCALL_RET(res);
                }
            }
            dirnode->unref();
            if (procroot) {
                procroot->unref();
            }
            delete[] pathbuf;
            // Check if we have permission to change the owner.
            bool ok = false;
            struct stat st = targetnode->getattr();
            if (euid == 0) {
                ok = true; // Root can always change owner.
            } else if (euid == st.st_uid) {
                // Non-root can change group to one of their groups.
                if (gid == -1 || gid == st.st_gid) {
                    ok = true;
                }
            }
            if (!ok) {
                targetnode->unref();
                SYSCALL_RET(-EACCES);
            }

            struct stat newattr = st;
            if (uid != -1) {
                newattr.st_uid = uid;
            }
            if (gid != -1) {
                newattr.st_gid = gid;
            }
            targetnode->setattr(newattr);
            targetnode->unref();
            SYSCALL_RET(0);
        }

        extern "C" uint64_t sys_umask(int newmask) {
            SYSCALL_LOG("sys_umask(%o).\n", newmask);

            NSched::Process *proc = NArch::CPU::get()->currthread->process;
            proc->lock.acquire();
            int oldmask = proc->umask;
            proc->umask = newmask & 0777;
            proc->lock.release();

            SYSCALL_RET(oldmask);
        }

        extern "C" ssize_t sys_ftruncate(int fd, off_t len) {
            SYSCALL_LOG("sys_ftruncate(%d, %ld).\n", fd, len);

            if (fd < 0) {
                SYSCALL_RET(-EBADF);
            }

            if (len < 0) {
                SYSCALL_RET(-EINVAL);
            }

            NSched::Process *proc = NArch::CPU::get()->currthread->process;

            FileDescriptor *desc = proc->fdtable->get(fd);
            if (!desc) {
                SYSCALL_RET(-EBADF);
            }

            int accmode = desc->getflags() & O_ACCMODE;
            if (accmode != O_WRONLY && accmode != O_RDWR) {
                SYSCALL_RET(-EINVAL); // POSIX: must be open for writing.
            }

            INode *node = desc->getnode();

            struct stat st = node->getattr();
            if (!S_ISREG(st.st_mode)) {
                node->unref();
                SYSCALL_RET(-EINVAL); // Can only truncate regular files.
            }

            int res = node->truncate(len);
            node->unref();
            SYSCALL_RET(res);
        }

        extern "C" ssize_t sys_sync(void) {
            SYSCALL_LOG("sys_sync().\n");

            vfs->syncall();

            SYSCALL_RET(0);
        }

        extern "C" ssize_t sys_fsync(int fd, int opt) {
            SYSCALL_LOG("sys_fsync(%d, %d).\n", fd, opt);

            NSched::Process *proc = NArch::CPU::get()->currthread->process;

            FileDescriptor *desc = proc->fdtable->get(fd);
            if (!desc) {
                SYSCALL_RET(-EBADF);
            }

            INode *node = desc->getnode();
            int res = node->sync((opt == 0) ? INode::SYNC_FULL : INode::SYNC_DATA);
            node->unref();
            SYSCALL_RET(res);
        }

        extern "C" ssize_t sys_mount(const char *source, const char *target, const char *fstype, uint64_t flags, const void *data) {
            SYSCALL_LOG("sys_mount(%s, %s, %s, %lu, %p).\n", source, target, fstype, flags, data);

            ssize_t srclen = NMem::UserCopy::strnlen(source, 4096);
            if (srclen < 0) {
                SYSCALL_RET(srclen); // Contains errno.
            }

            ssize_t tgtlen = NMem::UserCopy::strnlen(target, 4096);
            if (tgtlen < 0) {
                SYSCALL_RET(tgtlen); // Contains errno.
            }

            ssize_t fstlen = NMem::UserCopy::strnlen(fstype, 256);
            if (fstlen < 0) {
                SYSCALL_RET(fstlen); // Contains errno.
            }

            char *srcbuf = new char[srclen + 1];
            if (!srcbuf) {
                SYSCALL_RET(-ENOMEM);
            }

            char *tgtbuf = new char[tgtlen + 1];
            if (!tgtbuf) {
                delete[] srcbuf;
                SYSCALL_RET(-ENOMEM);
            }

            char *fstbuf = new char[fstlen + 1];
            if (!fstbuf) {
                delete[] srcbuf;
                delete[] tgtbuf;
                SYSCALL_RET(-ENOMEM);
            }

            int res = NMem::UserCopy::strncpyfrom(srcbuf, source, srclen);
            if (res < 0) {
                delete[] srcbuf;
                delete[] tgtbuf;
                delete[] fstbuf;
                SYSCALL_RET(res); // Contains errno.
            }

            res = NMem::UserCopy::strncpyfrom(tgtbuf, target, tgtlen);
            if (res < 0) {
                delete[] srcbuf;
                delete[] tgtbuf;
                delete[] fstbuf;
                SYSCALL_RET(res); // Contains errno.
            }

            res = NMem::UserCopy::strncpyfrom(fstbuf, fstype, fstlen);
            if (res < 0) {
                delete[] srcbuf;
                delete[] tgtbuf;
                delete[] fstbuf;
                SYSCALL_RET(res); // Contains errno.
            }

            srcbuf[srclen] = '\0';
            tgtbuf[tgtlen] = '\0';
            fstbuf[fstlen] = '\0';

            // Perform the mount operation.
            res = vfs->mount(srcbuf, tgtbuf, fstbuf, flags, data);
            delete[] srcbuf;
            delete[] tgtbuf;
            delete[] fstbuf;
            SYSCALL_RET(res);
        }

        extern "C" ssize_t sys_umount(const char *target, int flags) {
            SYSCALL_LOG("sys_umount(%s, %d).\n", target, flags);
            ssize_t tgtlen = NMem::UserCopy::strnlen(target, 4096);
            if (tgtlen < 0) {
                SYSCALL_RET(tgtlen); // Contains errno.
            }

            char *tgtbuf = new char[tgtlen + 1];
            if (!tgtbuf) {
                SYSCALL_RET(-ENOMEM);
            }

            int res = NMem::UserCopy::strncpyfrom(tgtbuf, target, tgtlen);
            if (res < 0) {
                delete[] tgtbuf;
                SYSCALL_RET(res); // Contains errno.
            }

            tgtbuf[tgtlen] = '\0';
            // Perform the unmount operation.
            res = vfs->umount(tgtbuf, flags);
            delete[] tgtbuf;
            SYSCALL_RET(res);
        }

        extern "C" ssize_t sys_rename(int oldfd, const char *oldpath, size_t oldlen, int newfd, const char *newpath, size_t newlen) {
            SYSCALL_LOG("sys_rename(%d, %s, %lu, %d, %s, %lu).\n", oldfd, oldpath, oldlen, newfd, newpath, newlen);

            // Validate and copy old path from userspace.
            ssize_t oldpathsize = NMem::UserCopy::strnlen(oldpath, oldlen);
            if (oldpathsize < 0) {
                SYSCALL_RET(oldpathsize);
            }
            char *oldpathbuf = new char[oldpathsize + 1];
            if (!oldpathbuf) {
                SYSCALL_RET(-ENOMEM);
            }
            int ret = NMem::UserCopy::strncpyfrom(oldpathbuf, oldpath, oldpathsize);
            if (ret < 0) {
                delete[] oldpathbuf;
                SYSCALL_RET(ret);
            }
            oldpathbuf[oldpathsize] = '\0';

            // Validate and copy new path from userspace.
            ssize_t newpathsize = NMem::UserCopy::strnlen(newpath, newlen);
            if (newpathsize < 0) {
                delete[] oldpathbuf;
                SYSCALL_RET(newpathsize);
            }
            char *newpathbuf = new char[newpathsize + 1];
            if (!newpathbuf) {
                delete[] oldpathbuf;
                SYSCALL_RET(-ENOMEM);
            }
            ret = NMem::UserCopy::strncpyfrom(newpathbuf, newpath, newpathsize);
            if (ret < 0) {
                delete[] oldpathbuf;
                delete[] newpathbuf;
                SYSCALL_RET(ret);
            }
            newpathbuf[newpathsize] = '\0';

            NSched::Process *proc = NArch::CPU::get()->currthread->process;
            proc->lock.acquire();

            // Resolve old directory.
            INode *olddirnode;
            if (oldpathbuf[0] == '/') {
                olddirnode = vfs->getroot();
            } else if (oldfd == AT_FDCWD) {
                olddirnode = proc->cwd;
                if (!olddirnode) {
                    olddirnode = vfs->getroot();
                } else {
                    olddirnode->ref();
                }
            } else {
                FileDescriptor *desc = proc->fdtable->get(oldfd);
                if (!desc) {
                    delete[] oldpathbuf;
                    delete[] newpathbuf;
                    proc->lock.release();
                    SYSCALL_RET(-EBADF);
                }
                olddirnode = desc->getnode();
                if (!S_ISDIR(olddirnode->getattr().st_mode)) {
                    olddirnode->unref();
                    delete[] oldpathbuf;
                    delete[] newpathbuf;
                    proc->lock.release();
                    SYSCALL_RET(-ENOTDIR);
                }
            }

            // Resolve new directory.
            INode *newdirnode;
            if (newpathbuf[0] == '/') {
                newdirnode = vfs->getroot();
            } else if (newfd == AT_FDCWD) {
                newdirnode = proc->cwd;
                if (!newdirnode) {
                    newdirnode = vfs->getroot();
                } else {
                    newdirnode->ref();
                }
            } else {
                FileDescriptor *desc = proc->fdtable->get(newfd);
                if (!desc) {
                    olddirnode->unref();
                    delete[] oldpathbuf;
                    delete[] newpathbuf;
                    proc->lock.release();
                    SYSCALL_RET(-EBADF);
                }
                newdirnode = desc->getnode();
                if (!S_ISDIR(newdirnode->getattr().st_mode)) {
                    newdirnode->unref();
                    olddirnode->unref();
                    delete[] oldpathbuf;
                    delete[] newpathbuf;
                    proc->lock.release();
                    SYSCALL_RET(-ENOTDIR);
                }
            }

            int uid = proc->uid;
            int gid = proc->gid;
            INode *procroot = proc->root;
            if (procroot) {
                procroot->ref();
            }
            proc->lock.release();

            // Actual work is done by VFS, of course.
            ssize_t res = vfs->rename(oldpathbuf, olddirnode, newpathbuf, newdirnode, uid, gid, procroot);
            olddirnode->unref();
            newdirnode->unref();
            if (procroot) {
                procroot->unref();
            }
            delete[] oldpathbuf;
            delete[] newpathbuf;
            SYSCALL_RET(res);
        }

        extern "C" ssize_t sys_symlink(int dirfd, const char *target, size_t targetlen, const char *linkpath, size_t linklen) {
            SYSCALL_LOG("sys_symlink(%d, %s, %lu, %s, %lu).\n", dirfd, target, targetlen, linkpath, linklen);

            // Validate and copy target path from userspace.
            ssize_t targetsize = NMem::UserCopy::strnlen(target, targetlen);
            if (targetsize < 0) {
                SYSCALL_RET(targetsize);
            }
            if (targetsize == 0) {
                SYSCALL_RET(-ENOENT); // Empty target is invalid.
            }
            char *targetbuf = new char[targetsize + 1];
            if (!targetbuf) {
                SYSCALL_RET(-ENOMEM);
            }
            int ret = NMem::UserCopy::strncpyfrom(targetbuf, target, targetsize);
            if (ret < 0) {
                delete[] targetbuf;
                SYSCALL_RET(ret);
            }
            targetbuf[targetsize] = '\0';

            // Validate and copy link path from userspace.
            ssize_t linkpathsize = NMem::UserCopy::strnlen(linkpath, linklen);
            if (linkpathsize < 0) {
                delete[] targetbuf;
                SYSCALL_RET(linkpathsize);
            }
            char *linkpathbuf = new char[linkpathsize + 1];
            if (!linkpathbuf) {
                delete[] targetbuf;
                SYSCALL_RET(-ENOMEM);
            }
            ret = NMem::UserCopy::strncpyfrom(linkpathbuf, linkpath, linkpathsize);
            if (ret < 0) {
                delete[] targetbuf;
                delete[] linkpathbuf;
                SYSCALL_RET(ret);
            }
            linkpathbuf[linkpathsize] = '\0';

            NSched::Process *proc = NArch::CPU::get()->currthread->process;
            proc->lock.acquire();

            // Resolve directory for symlink creation.
            INode *dirnode;
            if (linkpathbuf[0] == '/') {
                dirnode = vfs->getroot();
            } else if (dirfd == AT_FDCWD) {
                dirnode = proc->cwd;
                if (!dirnode) {
                    dirnode = vfs->getroot();
                } else {
                    dirnode->ref();
                }
            } else {
                FileDescriptor *desc = proc->fdtable->get(dirfd);
                if (!desc) {
                    delete[] targetbuf;
                    delete[] linkpathbuf;
                    proc->lock.release();
                    SYSCALL_RET(-EBADF);
                }
                dirnode = desc->getnode();
                if (!S_ISDIR(dirnode->getattr().st_mode)) {
                    dirnode->unref();
                    delete[] targetbuf;
                    delete[] linkpathbuf;
                    proc->lock.release();
                    SYSCALL_RET(-ENOTDIR);
                }
            }

            // Get parent directory path of the symlink to check write permission.
            INode *procroot = proc->root;
            if (procroot) {
                procroot->ref();
            }
            proc->lock.release();

            Path linkpobj = Path(linkpathbuf);
            const char *parentpath = linkpobj.dirname();
            INode *parent = NULL;
            ssize_t res = vfs->resolve(parentpath, &parent, dirnode, true, procroot);
            delete parentpath;
            if (res < 0) {
                dirnode->unref();
                if (procroot) {
                    procroot->unref();
                }
                delete[] targetbuf;
                delete[] linkpathbuf;
                SYSCALL_RET(res);
            }

            // Get process credentials.
            proc->lock.acquire();
            int peuid = proc->euid;
            int pegid = proc->egid;
            proc->lock.release();

            // Check write permission on parent directory.
            bool ok = vfs->checkaccess(parent, O_WRONLY | O_EXEC, peuid, pegid);
            if (!ok) {
                parent->unref();
                dirnode->unref();
                if (procroot) {
                    procroot->unref();
                }
                delete[] targetbuf;
                delete[] linkpathbuf;
                SYSCALL_RET(-EACCES);
            }
            parent->unref();

            // Setup symlink attributes.
            struct stat attr {
                .st_mode = static_cast<uint32_t>(S_IFLNK | 0777), // Symlinks typically have 0777 permissions (actual permission determined by target).
                .st_uid = peuid,
                .st_gid = pegid
            };

            // Create the symlink node.
            INode *nodeout = NULL;
            res = vfs->create(linkpathbuf, &nodeout, attr, dirnode, procroot);
            dirnode->unref();
            if (procroot) {
                procroot->unref();
            }
            delete[] linkpathbuf;
            if (res < 0) {
                delete[] targetbuf;
                SYSCALL_RET(res);
            }

            ssize_t written = nodeout->setsymlinkdata(targetbuf, targetsize);
            delete[] targetbuf;

            if (written < 0) {
                nodeout->unref();
                SYSCALL_RET(written);
            }

            nodeout->unref();
            SYSCALL_RET(0);
        }

        extern "C" ssize_t sys_pivotroot(const char *newroot, size_t newlen, const char *putold, size_t putoldlen) {
            SYSCALL_LOG("sys_pivotroot(%s, %lu, %s, %lu).\n", newroot, newlen, putold, putoldlen);

            // Only root (euid == 0) can call pivotroot.
            NSched::Process *proc = NArch::CPU::get()->currthread->process;
            proc->lock.acquire();
            int euid = proc->euid;
            INode *procroot = proc->root;
            if (procroot) {
                procroot->ref(); // Hold reference while we check.
            }
            proc->lock.release();

            if (euid != 0) {
                if (procroot) {
                    procroot->unref();
                }
                SYSCALL_RET(-EPERM);
            }

            // Copy new_root path from userspace.
            ssize_t newrootsize = NMem::UserCopy::strnlen(newroot, newlen);
            if (newrootsize < 0) {
                if (procroot) {
                    procroot->unref();
                }
                SYSCALL_RET(newrootsize);
            }

            char *newrootbuf = new char[newrootsize + 1];
            if (!newrootbuf) {
                if (procroot) {
                    procroot->unref();
                }
                SYSCALL_RET(-ENOMEM);
            }

            int ret = NMem::UserCopy::strncpyfrom(newrootbuf, newroot, newrootsize);
            if (ret < 0) {
                delete[] newrootbuf;
                if (procroot) {
                    procroot->unref();
                }
                SYSCALL_RET(ret);
            }
            newrootbuf[newrootsize] = '\0';

            // Copy put_old path from userspace.
            ssize_t putoldsize = NMem::UserCopy::strnlen(putold, putoldlen);
            if (putoldsize < 0) {
                delete[] newrootbuf;
                if (procroot) {
                    procroot->unref();
                }
                SYSCALL_RET(putoldsize);
            }

            char *putoldbuf = new char[putoldsize + 1];
            if (!putoldbuf) {
                delete[] newrootbuf;
                if (procroot) {
                    procroot->unref();
                }
                SYSCALL_RET(-ENOMEM);
            }

            ret = NMem::UserCopy::strncpyfrom(putoldbuf, putold, putoldsize);
            if (ret < 0) {
                delete[] newrootbuf;
                delete[] putoldbuf;
                if (procroot) {
                    procroot->unref();
                }
                SYSCALL_RET(ret);
            }
            putoldbuf[putoldsize] = '\0';

            // Validate paths are absolute.
            if (newrootbuf[0] != '/' || putoldbuf[0] != '/') {
                delete[] newrootbuf;
                delete[] putoldbuf;
                if (procroot) {
                    procroot->unref();
                }
                SYSCALL_RET(-EINVAL);
            }

            // Normalize paths.
            Path newrootpath = Path(newrootbuf);
            const char *newrootnorm = newrootpath.construct();
            if (!newrootnorm) {
                delete[] newrootbuf;
                delete[] putoldbuf;
                if (procroot) {
                    procroot->unref();
                }
                SYSCALL_RET(-ENOMEM);
            }

            Path putoldpath = Path(putoldbuf);
            const char *putoldnorm = putoldpath.construct();
            if (!putoldnorm) {
                delete[] newrootnorm;
                delete[] newrootbuf;
                delete[] putoldbuf;
                if (procroot) {
                    procroot->unref();
                }
                SYSCALL_RET(-ENOMEM);
            }

            delete[] newrootbuf;
            delete[] putoldbuf;

            // Verify putold path would be under newroot (so it doesn't just poof into thin air).
            size_t newrootnormlen = NLib::strlen(newrootnorm);
            if (NLib::strncmp(putoldnorm, newrootnorm, newrootnormlen) != 0) {
                if (procroot) {
                    procroot->unref();
                }
                delete[] newrootnorm;
                delete[] putoldnorm;
                SYSCALL_RET(-EINVAL);
            }

            // Also verify there's a path separator after (unless newroot is "/").
            if (newrootnormlen > 1 && putoldnorm[newrootnormlen] != '/' && putoldnorm[newrootnormlen] != '\0') {
                if (procroot) {
                    procroot->unref();
                }
                delete[] newrootnorm;
                delete[] putoldnorm;
                SYSCALL_RET(-EINVAL);
            }

            // Resolve putold BEFORE acquiring mount lock (resolve() uses findmount() which takes the lock).
            INode *putoldnode = NULL;
            ssize_t res = vfs->resolve(putoldnorm, &putoldnode, NULL, true, NULL);
            if (res < 0) {
                if (procroot) {
                    procroot->unref();
                }
                delete[] newrootnorm;
                delete[] putoldnorm;
                SYSCALL_RET(res);
            }

            if (!S_ISDIR(putoldnode->getattr().st_mode)) {
                putoldnode->unref();
                if (procroot) {
                    procroot->unref();
                }
                delete[] newrootnorm;
                delete[] putoldnorm;
                SYSCALL_RET(-ENOTDIR);
            }

            // Now acquire mount lock for the rest of the operation.
            NLib::ScopeSpinlock mountguard(&vfs->mountlock);

            // Verify the calling process's root is *actually* the current root (and not something else, or a fake root through chroot).
            INode *currentvfsroot = vfs->getroot();
            if (procroot && procroot != currentvfsroot) {
                procroot->unref();
                delete[] newrootnorm;
                delete[] putoldnorm;
                SYSCALL_RET(-EINVAL);
            }
            if (procroot) {
                procroot->unref();
                procroot = NULL;
            }

            // Find newroot and oldroot mount points.
            struct VFS::mntpoint *newrootmnt = NULL;
            struct VFS::mntpoint *oldrootmnt = NULL;

            NLib::DoubleList<struct VFS::mntpoint>::Iterator it = vfs->mounts.begin();
            for (; it.valid(); it.next()) {
                struct VFS::mntpoint *mnt = it.get();
                if (!NLib::strcmp(mnt->path, newrootnorm)) {
                    newrootmnt = mnt;
                }
                if (!NLib::strcmp(mnt->path, "/")) {
                    oldrootmnt = mnt;
                }
            }

            if (!newrootmnt) {
                // newroot is not a mount point.
                putoldnode->unref();
                delete[] newrootnorm;
                delete[] putoldnorm;
                SYSCALL_RET(-EINVAL);
            }

            if (!oldrootmnt) {
                // No root mount? This shouldn't happen.
                putoldnode->unref();
                delete[] newrootnorm;
                delete[] putoldnorm;
                SYSCALL_RET(-EINVAL);
            }

            // Cannot pivot to current root.
            if (newrootmnt == oldrootmnt) {
                putoldnode->unref();
                delete[] newrootnorm;
                delete[] putoldnorm;
                SYSCALL_RET(-EBUSY);
            }

            // Calculate the relative path from newroot to putold.
            const char *putoldrelative = putoldnorm + newrootnormlen;
            if (*putoldrelative == '/') {
                putoldrelative++; // Skip leading slash.
            }

            // Build the new path for the old root mount. /mnt/oldroot -> /oldroot
            size_t putoldrellen = NLib::strlen(putoldrelative);
            char *oldrootnewpath = new char[putoldrellen + 2]; // +2 for leading "/" and null terminator.
            if (!oldrootnewpath) {
                putoldnode->unref();
                delete[] newrootnorm;
                delete[] putoldnorm;
                SYSCALL_RET(-ENOMEM);
            }
            NLib::memset(oldrootnewpath, 0, putoldrellen + 2); // Ensure null-termination.
            oldrootnewpath[0] = '/';
            NLib::strcpy(oldrootnewpath + 1, (char *)putoldrelative);

            // Update mount paths:
            // 1. All mounts under "/" (except newroot subtree) get prefixed with putold relative path.
            // 2. newroot mount becomes "/".
            // 3. Old root mount becomes putold path (relative to newroot, i.e., "/putold_relative").

            // Pre-allocate all new mount paths to ensure atomicity.
            // Count mounts and allocate path storage.
            size_t mountcount = 0;
            it = vfs->mounts.begin();
            for (; it.valid(); it.next()) {
                mountcount++;
            }

            char **newpaths = new char*[mountcount];
            if (!newpaths) {
                delete[] oldrootnewpath;
                putoldnode->unref();
                delete[] newrootnorm;
                delete[] putoldnorm;
                SYSCALL_RET(-ENOMEM);
            }

            // Initialize to NULL for safe cleanup.
            for (size_t i = 0; i < mountcount; i++) {
                newpaths[i] = NULL;
            }

            // Calculate and allocate all new paths.
            size_t idx = 0;
            bool allocfailed = false;
            it = vfs->mounts.begin();
            for (; it.valid() && !allocfailed; it.next(), idx++) {
                struct VFS::mntpoint *mnt = it.get();

                if (mnt == newrootmnt) {
                    // newroot becomes "/".
                    newpaths[idx] = NLib::strdup("/");
                    if (!newpaths[idx]) {
                        allocfailed = true;
                    }
                } else if (mnt == oldrootmnt) {
                    // Old root becomes the putold path.
                    newpaths[idx] = NLib::strdup(oldrootnewpath);
                    if (!newpaths[idx]) {
                        allocfailed = true;
                    }
                } else {
                    // Check if this mount was under newroot.
                    if (!NLib::strncmp(mnt->path, newrootnorm, newrootnormlen) &&
                        (mnt->path[newrootnormlen] == '/' || mnt->path[newrootnormlen] == '\0')) {
                        // This mount is under newroot, make it relative to newroot.
                        const char *relpath = mnt->path + newrootnormlen;
                        if (*relpath == '\0') {
                            // Keep original path (will be handled specially).
                            newpaths[idx] = NULL;
                        } else {
                            // relpath starts with "/", so it's already absolute-style relative to newroot.
                            newpaths[idx] = NLib::strdup(relpath);
                            if (!newpaths[idx]) {
                                allocfailed = true;
                            }
                        }
                    } else {
                        // This mount was under old root (not under newroot).
                        size_t newpathlen = NLib::strlen(oldrootnewpath) + NLib::strlen(mnt->path) + 1;
                        newpaths[idx] = new char[newpathlen];
                        if (!newpaths[idx]) {
                            allocfailed = true;
                        } else {
                            NLib::strcpy(newpaths[idx], oldrootnewpath);
                            NLib::strcat(newpaths[idx], (char *)mnt->path);
                        }
                    }
                }
            }

            if (allocfailed) {
                // Clean up all allocated paths.
                for (size_t i = 0; i < mountcount; i++) {
                    if (newpaths[i]) {
                        delete[] newpaths[i];
                    }
                }
                delete[] newpaths;
                delete[] oldrootnewpath;
                putoldnode->unref();
                delete[] newrootnorm;
                delete[] putoldnorm;
                SYSCALL_RET(-ENOMEM);
            }

            // Now atomically apply all path updates.
            idx = 0;
            it = vfs->mounts.begin();
            for (; it.valid(); it.next(), idx++) {
                struct VFS::mntpoint *mnt = it.get();
                if (newpaths[idx]) {
                    delete[] mnt->path;
                    mnt->path = newpaths[idx];
                }
            }
            delete[] newpaths;


            INode *newvfsroot = newrootmnt->fs->getroot();
            INode *oldvfsroot = vfs->setroot(newvfsroot);

            INode *oldmntdir = NULL;
            if (putoldrellen > 0) {
                // Traverse each component of the putoldrelative path within the new root filesystem.
                Path relpath = Path(putoldrelative);
                NLib::DoubleList<const char *>::Iterator pathit = relpath.iterator();
                INode *current = newvfsroot;
                current->ref();

                while (pathit.valid()) {
                    const char *comp = *pathit.get();
                    INode *next = current->lookup(comp);
                    current->unref();
                    if (!next) {
                        current = NULL;
                        break;
                    }
                    current = next;
                    pathit.next();
                }
                oldmntdir = current; // May be NULL if lookup failed.
            }

            if (oldrootmnt->mntnode) {
                oldrootmnt->mntnode->unref();
            }
            if (oldmntdir) {
                oldrootmnt->mntnode = oldmntdir; // lookup() returns a referenced node.
            } else {
                // Fallback: if we can't find the directory, use putoldnode (may not work correctly).
                putoldnode->ref();
                oldrootmnt->mntnode = putoldnode;
            }

            if (newrootmnt->mntnode) {
                newrootmnt->mntnode->unref();
            }
            newrootmnt->mntnode = NULL;

            // Now update all processes' root and cwd if they pointed to old root.
            NSched::pidtablelock.acquire();
            NLib::KVHashMap<size_t, NSched::Process *>::Iterator pit = NSched::pidtable->begin();
            for (; pit.valid(); pit.next()) {
                NSched::Process *p = *pit.value();
                p->lock.acquire();

                // If process root was the old VFS root, update to new root.
                if (p->root == oldvfsroot || p->root == NULL) {
                    newvfsroot->ref();
                    if (newvfsroot->fs) {
                        newvfsroot->fs->fsref();  // New filesystem gets a reference
                    }
                    if (p->root) {
                        if (p->root->fs) {
                            p->root->fs->fsunref();  // Old filesystem loses a reference
                        }
                        p->root->unref();
                    }
                    p->root = newvfsroot;
                }

                // If process cwd was the old VFS root, update to new root.
                if (p->cwd == oldvfsroot) {
                    newvfsroot->ref();
                    if (newvfsroot->fs) {
                        newvfsroot->fs->fsref();  // New filesystem gets a reference
                    }
                    if (p->cwd->fs) {
                        p->cwd->fs->fsunref();  // Old filesystem loses a reference
                    }
                    p->cwd->unref();
                    p->cwd = newvfsroot;
                }

                p->lock.release();
            }
            NSched::pidtablelock.release();

            // Release old VFS root reference.
            if (oldvfsroot) {
                oldvfsroot->unref();
            }

            delete[] oldrootnewpath;
            putoldnode->unref();
            delete[] newrootnorm;
            delete[] putoldnorm;

            SYSCALL_RET(0);
        }
    }
}
