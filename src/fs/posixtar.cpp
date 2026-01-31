#include <fs/posixtar.hpp>
#include <fs/vfs.hpp>
#include <lib/align.hpp>
#include <lib/errno.hpp>
#include <lib/string.hpp>
#include <util/kprint.hpp>
#include <std/stddef.h>
#include <arch/x86_64/pmm.hpp>

namespace NFS {
    namespace POSIXTAR {

        // Read buffer size for streaming tar data (256KB for better throughput).
        static constexpr size_t READBUFSIZE = 256 * 1024;

        int POSIXTARFileSystem::mount(const char *src, const char *path, VFS::INode *mntnode, uint64_t flags, const void *data) {
            (void)src;
            (void)flags;
            (void)data;
            int super = this->RAMFS::RAMFileSystem::mount(NULL, path, mntnode, 0, NULL); // Super.
            if (super != 0) {
                return super;
            }

            // Get the content size (decompressed size for LZ4, raw size otherwise).
            ssize_t contentlen = this->modinfo->contentsize();
            if (contentlen <= 0) {
                NUtil::printf("[fs/ustar]: Failed to determine module content size.\n");
                return -EINVAL;
            }
            size_t size = (size_t)contentlen;

            NUtil::printf("[fs/ustar]: Enumerating USTAR module `%s` with size %lu%s.\n", this->modinfo->path, size, this->modinfo->iscompressed() ? " (LZ4)" : "");

            // Allocate read buffer for streaming.
            uint8_t *readbuf = new uint8_t[READBUFSIZE];
            if (!readbuf) {
                NUtil::printf("[fs/ustar]: Failed to allocate read buffer.\n");
                return -ENOMEM;
            }

            size_t pos = 0; // Current position in the decompressed stream.
            char longpath[4096] = {0}; // Buffer to store long paths (GNU tar extension).
            char longlink[4096] = {0}; // Buffer to store long link names (GNU tar extension).
            bool haslongpath = false; // Track if we have a pending long path.
            bool haslonglink = false; // Track if we have a pending long link name.

            // Read the first header.
            struct info header;
            while (pos + sizeof(struct info) <= size) {
                // Print progress indicator every 10 percent of archive processed.
                static size_t lastpercent = (size_t)-1;
                size_t percent = (pos * 100) / size;
                if (percent != lastpercent && percent % 10 == 0) {
                    NUtil::printf("[fs/ustar]: Mount progress: %lu%%.\n", percent);
                    lastpercent = percent;
                }

                // Read tar header.
                ssize_t hdrread = this->modinfo->read(&header, sizeof(struct info), pos);
                if (hdrread != (ssize_t)sizeof(struct info)) {
                    break; // End of archive or read error.
                }

                // Check for USTAR magic.
                if (NLib::strncmp(header.magic, "ustar", 5)) {
                    break; // End of archive.
                }

                char basename[4096] = {0};
                char *lname = header.linkname;

                if (haslongpath) { // Use the long path previously stored.
                    NLib::strncpy(basename, longpath, sizeof(basename) - 1);
                    haslongpath = false;
                } else { // Use the name field.
                    size_t namelen = 0;
                    while (namelen < sizeof(header.name) && header.name[namelen] != '\0') {
                        namelen++;
                    }
                    NLib::memcpy(basename, header.name, namelen);
                    basename[namelen] = '\0';
                }

                if (!NLib::strcmp(basename, "./")) {
                    uint64_t skipsize = oct2int(header.size, sizeof(header.size));
                    pos += 512 + NLib::alignup(skipsize, 512);
                    continue;
                }

                char name[8192];
                NUtil::snprintf(name, sizeof(name), "%s/%s", path, basename);

                uint64_t fsize = oct2int(header.size, sizeof(header.size));
                uint64_t mtime = oct2int(header.mtime, sizeof(header.mtime));
                uint64_t mode = oct2int(header.mode, sizeof(header.mode));
                uint64_t uid = oct2int(header.uid, sizeof(header.uid));
                uint64_t gid = oct2int(header.gid, sizeof(header.gid));

                size_t datapos = pos + 512; // File data starts after header.

                VFS::INode *node = NULL;
                switch (header.type) {
                    case type::FILE: {
                        if (datapos + fsize > size) {
                            NUtil::printf("[fs/ustar]: Invalid file size %lu exceeding archive bounds.\n", fsize);
                            delete[] readbuf;
                            return -EINVAL;
                        }

                        struct VFS::stat attr;
                        attr.st_mode = mode | VFS::S_IFREG;
                        attr.st_uid = uid;
                        attr.st_gid = gid;
                        attr.st_mtime = mtime;
                        attr.st_blksize = 512;
                        attr.st_atime = mtime;
                        attr.st_ctime = mtime;
                        ssize_t res = VFS::vfs->create(name, &node, attr);
                        assert(res == 0, "Failed to allocate VFS node.\n");

                        // Stream file data in chunks.
                        size_t remaining = fsize;
                        size_t fileoff = 0;
                        while (remaining > 0) {
                            size_t chunk = (remaining < READBUFSIZE) ? remaining : READBUFSIZE;
                            ssize_t nread = this->modinfo->read(readbuf, chunk, datapos + fileoff);
                            if (nread <= 0) {
                                NUtil::printf("[fs/ustar]: Failed to read file data for `%s`.\n", name);
                                break;
                            }
                            size_t written = node->write(readbuf, nread, fileoff, 0);
                            assert(written == (size_t)nread, "Failed to write VFS node data.\n");
                            fileoff += nread;
                            remaining -= nread;
                        }
                        node->unref();
                        break;
                    }
                    case type::DIR: {
                        struct VFS::stat attr;
                        attr.st_mode = mode | VFS::S_IFDIR;
                        attr.st_uid = uid;
                        attr.st_gid = gid;
                        attr.st_mtime = mtime;
                        attr.st_atime = mtime;
                        attr.st_ctime = mtime;
                        attr.st_nlink = 2; // Directories start with 2 links (self and parent).
                        ssize_t res = VFS::vfs->create(name, &node, attr);
                        assert(res == 0, "Failed to allocate VFS node.\n");
                        node->unref();
                        break;
                    }
                    case type::SYMLINK: {
                        struct VFS::stat attr;
                        attr.st_mode = mode | VFS::S_IFLNK;
                        attr.st_uid = uid;
                        attr.st_gid = gid;
                        attr.st_mtime = mtime;
                        ssize_t res = VFS::vfs->create(name, &node, attr);
                        assert(res == 0, "Failed to allocate VFS node.\n");

                        // Use long link name if available, otherwise use linkname field.
                        const char *linktarget;
                        size_t len;
                        if (haslonglink) {
                            linktarget = longlink;
                            len = NLib::strlen(longlink);
                            haslonglink = false;
                        } else {
                            linktarget = lname;
                            len = 0;
                            while (len < sizeof(header.linkname) && lname[len] != '\0') {
                                len++;
                            }
                        }

                        size_t count = node->write(linktarget, len + 1, 0, 0);
                        assert(count == len + 1, "Failed to write link to VFS node.\n");
                        node->unref();
                        break;
                    }
                    case type::PATH: {
                        if (datapos + fsize > size) {
                            NUtil::printf("[fs/ustar]: Invalid long path size %lu exceeding archive bounds.\n", fsize);
                            delete[] readbuf;
                            return -EINVAL;
                        }
                        if (fsize >= sizeof(longpath)) {
                            NUtil::printf("[fs/ustar]: Long path too large (%lu >= %lu).\n", fsize, sizeof(longpath));
                            delete[] readbuf;
                            return -E2BIG;
                        }
                        // Read the long path data into our buffer.
                        ssize_t nread = this->modinfo->read(longpath, fsize, datapos);
                        if (nread != (ssize_t)fsize) {
                            NUtil::printf("[fs/ustar]: Failed to read long path.\n");
                            delete[] readbuf;
                            return -EIO;
                        }
                        longpath[fsize] = '\0';
                        haslongpath = true;
                        break;
                    }
                    case type::LINK: {
                        if (datapos + fsize > size) {
                            NUtil::printf("[fs/ustar]: Invalid long link size %lu exceeding archive bounds.\n", fsize);
                            delete[] readbuf;
                            return -EINVAL;
                        }
                        if (fsize >= sizeof(longlink)) {
                            NUtil::printf("[fs/ustar]: Long link too large (%lu >= %lu).\n", fsize, sizeof(longlink));
                            delete[] readbuf;
                            return -E2BIG;
                        }
                        // Read the long link data into our buffer.
                        ssize_t nread = this->modinfo->read(longlink, fsize, datapos);
                        if (nread != (ssize_t)fsize) {
                            NUtil::printf("[fs/ustar]: Failed to read long link.\n");
                            delete[] readbuf;
                            return -EIO;
                        }
                        longlink[fsize] = '\0';
                        haslonglink = true;
                        break;
                    }

                    default:
                        NUtil::printf("[fs/ustar]: Unsupported file type `%c` for file `%s`, skipping.\n", header.type, name);
                        break;
                    case type::HARDLINK: {
                        const char *linktarget;
                        if (haslonglink) {
                            linktarget = longlink;
                            haslonglink = false;
                        } else {
                            // Copy linkname to a null-terminated buffer.
                            static char linkbuf[101];
                            size_t len = 0;
                            while (len < sizeof(header.linkname) && lname[len] != '\0') {
                                len++;
                            }
                            NLib::memcpy(linkbuf, lname, len);
                            linkbuf[len] = '\0';
                            linktarget = linkbuf;
                        }

                        // Build full path to the target.
                        char targetpath[8192];
                        NUtil::snprintf(targetpath, sizeof(targetpath), "%s/%s", path, linktarget);

                        // Resolve the target node.
                        VFS::INode *target = NULL;
                        ssize_t res = VFS::vfs->resolve(targetpath, &target, NULL, false);
                        if (res < 0 || target == NULL) {
                            NUtil::printf("[fs/ustar]: Hard link target `%s` not found for `%s`.\n", targetpath, name);
                            break;
                        }

                        // Get target's attributes and data.
                        struct VFS::stat targetattr;
                        target->stat(&targetattr);

                        // Create a new node with the same attributes.
                        struct VFS::stat attr;
                        attr.st_mode = targetattr.st_mode;
                        attr.st_uid = uid;
                        attr.st_gid = gid;
                        attr.st_mtime = mtime;
                        attr.st_atime = mtime;
                        attr.st_ctime = mtime;
                        attr.st_blksize = targetattr.st_blksize;

                        res = VFS::vfs->create(name, &node, attr);
                        if (res != 0) {
                            NUtil::printf("[fs/ustar]: Failed to create hard link `%s`.\n", name);
                            target->unref();
                            break;
                        }

                        // Copy data from target to new node in chunks (reuse read buffer).
                        if (targetattr.st_size > 0) {
                            size_t remaining = targetattr.st_size;
                            size_t offset = 0;
                            while (remaining > 0) {
                                size_t chunk = (remaining < READBUFSIZE) ? remaining : READBUFSIZE;
                                ssize_t readcount = target->read(readbuf, chunk, offset, 0);
                                if (readcount <= 0) {
                                    break;
                                }
                                node->write(readbuf, readcount, offset, 0);
                                offset += readcount;
                                remaining -= readcount;
                            }
                        }

                        target->unref();
                        node->unref();
                        break;
                    }
                }

                pos += 512 + NLib::alignup(fsize, 512);
            }

            delete[] readbuf;
            return 0;
        }

        void POSIXTARFileSystem::reclaim(void) {
            // For compressed modules, reclaim any remaining unreclaimed memory.
            if (this->modinfo->iscompressed()) {
                auto *cmod = static_cast<NArch::Module::CompressedModule *>(this->modinfo);
                NUtil::printf("[fs/ustar]: Reclaiming remaining compressed initramfs memory.\n");
                cmod->reclaimremaining();
            } else {
                // For uncompressed modules, reclaim all memory at once.
                NUtil::printf("[fs/ustar]: Reclaiming initramfs memory at %p with length %lu.\n", this->modinfo->loc, this->modinfo->size);
                NArch::PMM::newzone(this->modinfo->loc, this->modinfo->size);
            }
        }

    }
}
