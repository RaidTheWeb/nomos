#include <fs/vfs.hpp>

namespace NFS {
    namespace VFS {

        VFS::~VFS(void) {
            if (this->root) {
                this->root->unref();
            }
        }

        int VFS::mount(const char *path, IFileSystem *fs) {
            NLib::ScopeSpinlock guard(&this->mountlock);

            this->mounts.push((struct VFS::mntpoint) { path, fs, NULL });
            if (fs->mount() != 0) {
                this->umount(path);
                return -1;
            }

            Path mntpath = Path(path);

            if (!mntpath.depth() && !this->root) { // Attempt to assign root if we haven't already.
                this->root = fs->getroot();
            }
            return 0;
        }

        int VFS::umount(const char *path) {
            NLib::ScopeSpinlock guard(&this->mountlock);

            bool worked = this->mounts.remove([](struct mntpoint mnt, void *udata) {
                const char *p = (const char *)udata;
                if (!NLib::strcmp(mnt.path, p)) {
                    mnt.fs->unmount();
                    return true;
                }
                return false;
            }, (void *)path);

            if (worked) {
                Path mntpath = Path(path);
                if (!mntpath.depth() && this->root) { // If this is assigned on the root, we should remove the root reference.
                    this->root = NULL;
                }
            }

            return worked ? 0 : -1;
        }

        struct VFS::mntpoint *VFS::findmount(Path *path) {
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

                // Handle special case of '/' mounting point.
                if (!mntpath.depth() && mntpath.isabsolute()) { // Mount path is probably '/'.
                    if (path->isabsolute()) { // Search path is probably '/'. Add it as a potential match.
                        best = it.get();
                        depth = 0;
                        continue;
                    }
                }

                if (matches && mntpath.depth() > depth) {
                    best = it.get();
                    depth = mntpath.depth();
                }
            }

            return best;
        }

        INode *VFS::resolve(const char *path, INode *relativeto) {
            Path pobj = Path(path);

            if (!pobj.depth()) { // Empty path, we're referring to our current directory.
                return relativeto ? relativeto : this->root; // If we're working relative to a specific directory, we should return it, otherwise, root.
            }

            struct mntpoint *mount = this->findmount(&pobj);
            if (!mount) {
                return NULL; // Path is invalid. No mountpoint handles this path.
            }

            Path mntpath = Path(mount->path);
            size_t skip = mntpath.depth(); // How many components of the main path should we skip to just get the path relative to the mount path?

            NLib::DoubleList<const char *>::Iterator it = pobj.iterator();
            for (size_t i = 0; i < skip && it.valid(); i++) {
                it.next(); // Skip over components relevant to the mount path.
            }

            INode *current = mount->fs->getroot();

            while (it.valid()) {
                INode *next = current->lookup(*it.get());
                current->unref(); // Unreference old

                if (!next) {
                    return NULL;
                }

                it.next();
                current = next;
            }

            return current;
        }

        INode *VFS::create(const char *path, struct stat attr) {
            Path pobj = Path(path);

            if (!pobj.depth()) {
                return NULL; // Cannot create root.
            }


            const char *parentpath = pobj.dirname();
            INode *parent = this->resolve(parentpath);
            if (!parent) {
                return NULL; // Parent doesn't already exist.
            }

            struct mntpoint *mount = this->findmount(&pobj);
            if (!mount) {
                return NULL; // Invalid mounting point.
            }

            INode *node = mount->fs->create(pobj.basename(), attr);
            parent->add(node);
            parent->unref();

            if (node) {
                node->unref();
            }

            return node;
        }
    }
}
