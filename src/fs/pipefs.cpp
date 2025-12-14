#include <fs/pipefs.hpp>
#include <lib/errno.hpp>
#include <sched/event.hpp>
#include <sched/signal.hpp>
#include <mm/ucopy.hpp>

#ifdef __x86_64__
#include <arch/x86_64/cpu.hpp>
#endif

namespace NFS {
    namespace PipeFS {
        PipeFileSystem *pipefs = NULL;

        int PipeFileSystem::sync(void) {
            return 0;
        }

        PipeNode::PipeNode(VFS::IFileSystem *fs, const char *name, struct VFS::stat attr, bool file) : VFS::INode(fs, name, attr), databuffer(PIPEBUFSIZE) {
            this->file = file;
        }

        int PipeNode::open(int flags) {
            this->datalock.acquire();

            if ((flags & VFS::O_ACCMODE) == VFS::O_WRONLY) {
                this->writers++;
            } else if ((flags & VFS::O_ACCMODE) == VFS::O_RDONLY) {
                this->readers++;
            } else if ((flags & VFS::O_ACCMODE) == VFS::O_RDWR) { // FIFO file special case.
                this->writers++;
                this->readers++;
            }

            int ret = 0;
            // If we have both readers and writers, or this is not a FIFO special file, we can proceed.
            if ((this->writers > 0 && this->readers > 0) || !this->file) {
                goto leave;
            }

            if (flags & VFS::O_NONBLOCK) {
                ret = -ENXIO;
                goto leave;
            }

            if ((flags & VFS::O_ACCMODE) == VFS::O_WRONLY) {
                // Unconditional wait for event.
                ret = this->readopenwq.waitinterruptiblelocked(&this->datalock);
                if (ret < 0) {
                    goto leave;
                }
            } else if ((flags & VFS::O_ACCMODE) == VFS::O_RDONLY) {
                // Unconditional wait for event.
                ret = this->writeopenwq.waitinterruptiblelocked(&this->datalock);
                if (ret < 0) {
                    goto leave;
                }
            }
leave:
            if (ret != 0) {
                // Undo increments.
                if ((flags & VFS::O_ACCMODE) == VFS::O_WRONLY) {
                    if (this->writers > 0) {
                        this->writers--;
                    }
                } else if ((flags & VFS::O_ACCMODE) == VFS::O_RDONLY) {
                    if (this->readers > 0) {
                        this->readers--;
                    }
                } else if ((flags & VFS::O_ACCMODE) == VFS::O_RDWR) { // FIFO file special case.
                    if (this->writers > 0) {
                        this->writers--;
                    }
                    if (this->readers > 0) {
                        this->readers--;
                    }
                }
            } else {
                // Wake any waiting open() calls.
                if ((flags & VFS::O_ACCMODE) == VFS::O_WRONLY) {
                    this->writeopenwq.wake();
                } else if ((flags & VFS::O_ACCMODE) == VFS::O_RDONLY) {
                    this->readopenwq.wake();
                }
            }
            this->datalock.release();
            return ret;
        }

        int PipeNode::poll(short events, short *revents, int fdflags) {
            (void)fdflags;
            NLib::ScopeSpinlock guard(&this->datalock);

            *revents = 0;

            if (events & VFS::POLLIN) {
                if (!this->databuffer.empty() || this->writers == 0) {
                    // Data is available to read, or no writers (EOF).
                    *revents |= VFS::POLLIN;
                }
            }

            if (events & VFS::POLLOUT) {
                if (!this->databuffer.full() && this->readers > 0) {
                    // Space is available to write, and there are readers.
                    *revents |= VFS::POLLOUT;
                } else if (this->readers == 0) {
                    // Write would fail with EPIPE.
                    *revents |= VFS::POLLERR;
                }
            }

            if (this->writers == 0 && this->databuffer.empty()) {
                *revents |= VFS::POLLHUP; // EOF condition.
            }

            return 0;
        }

        int PipeNode::close(int fdflags) {
            this->datalock.acquire();

            if ((fdflags & VFS::O_ACCMODE) == VFS::O_WRONLY) {
                if (this->writers > 0) {
                    this->writers--;
                }
            } else if ((fdflags & VFS::O_ACCMODE) == VFS::O_RDONLY) {
                if (this->readers > 0) {
                    this->readers--;
                }
            } else if ((fdflags & VFS::O_ACCMODE) == VFS::O_RDWR) { // FIFO file special case.
                if (this->writers > 0) {
                    this->writers--;
                }
                if (this->readers > 0) {
                    this->readers--;
                }
            }

            this->datalock.release();

            // Wake any waiting threads so they can check for EOF or broken pipe.
            this->readwq.wake();
            this->writewq.wake();

            return 0;
        }

        ssize_t PipeNode::read(void *buf, size_t count, off_t offset, int fdflags) {
            (void)offset; // Pipes ignore offset.

            if (count == 0) {
                return 0;
            }

            if (!NMem::UserCopy::valid(buf, count)) {
                return -EFAULT;
            }

            uint8_t *ubuf = (uint8_t *)buf;
            size_t bytesread = 0;

            this->datalock.acquire();
            while (bytesread < count) {

                if (!this->databuffer.empty()) {
                    // Read as much as possible from buffer.
                    size_t toread = count - bytesread;
                    size_t available = this->databuffer.size();
                    if (toread > available) {
                        toread = available;
                    }

                    uint8_t kbuf[256]; // Read in chunks to avoid large stack usage.
                    size_t copied = 0;
                    while (copied < toread) {
                        size_t chunk = toread - copied;
                        if (chunk > sizeof(kbuf)) {
                            chunk = sizeof(kbuf);
                        }

                        for (size_t i = 0; i < chunk; i++) {
                            kbuf[i] = this->databuffer.pop();
                        }

                        this->datalock.release();

                        // Copy to user space.
                        int ret = NMem::UserCopy::copyto(ubuf + bytesread + copied, kbuf, chunk);
                        if (ret < 0) {
                            // Push back to front to restore original order.
                            this->datalock.acquire();
                            for (size_t i = chunk; i > 0; i--) {
                                this->databuffer.pushfront(kbuf[i - 1]);
                            }
                            this->datalock.release();

                            // Return error or bytes read so far.
                            if (bytesread + copied > 0) {
                                return bytesread + copied;
                            }
                            return ret;
                        }

                        copied += chunk;
                        this->datalock.acquire();
                    }

                    bytesread += toread;
                    this->datalock.release();

                    // Wake any waiting writers.
                    this->writewq.wake();

                    this->datalock.acquire();
                    continue; // Check if we can read more.
                }

                if (this->writers == 0) {
                    this->datalock.release();
                    return bytesread; // Return what we've read so far.
                }

                if (fdflags & VFS::O_NONBLOCK) {
                    this->datalock.release();
                    if (bytesread > 0) {
                        return bytesread;
                    }
                    return -EAGAIN; // No data, so we return EAGAIN and leave it up to the caller to try again later.
                }

                // Wait for data or writers to close.
                int ret;
                waiteventinterruptiblelocked(&this->readwq, (!this->databuffer.empty() || this->writers == 0), &this->datalock, ret);
                if (ret < 0) {
                    this->datalock.release();
                    if (bytesread > 0) {
                        return bytesread; // Return partial read.
                    }
                    return ret; // Return -EINTR.
                }
            }

            this->datalock.release();
            return bytesread;
        }

        ssize_t PipeNode::write(const void *buf, size_t count, off_t offset, int fdflags) {
            (void)offset; // Pipes ignore offset.

            if (count == 0) {
                return 0;
            }

            if (!NMem::UserCopy::valid(buf, count)) {
                return -EFAULT;
            }

            const uint8_t *ubuf = (const uint8_t *)buf;
            size_t byteswritten = 0;

            // For writes <= PIPE_BUF, ensure atomicity by not releasing lock until complete.
            bool atomic_write = (count <= PIPE_BUF);

            this->datalock.acquire();
            while (byteswritten < count) {
                if (this->readers == 0) {
                    this->datalock.release();
                    // Send SIGPIPE to current process for writing to pipe with no readers.
                    NSched::signalproc(NArch::CPU::get()->currthread->process, SIGPIPE);
                    return -EPIPE;
                }

                // For atomic writes, wait until entire write can complete.
                if (atomic_write && byteswritten == 0 && this->databuffer.available() < count) {
                    if (fdflags & VFS::O_NONBLOCK) {
                        this->datalock.release();
                        return -EAGAIN;
                    }
                    // Wait for enough space for the entire atomic write.
                    int ret;
                    waiteventinterruptiblelocked(&this->writewq, (this->databuffer.available() >= count || this->readers == 0), &this->datalock, ret);
                    if (ret < 0) {
                        this->datalock.release();
                        return ret; // Return -EINTR for atomic write.
                    }
                    continue;
                }

                if (!this->databuffer.full()) {
                    // Write as much as possible to buffer.
                    size_t towrite = count - byteswritten;
                    size_t space = this->databuffer.available();
                    if (towrite > space) {
                        towrite = space;
                    }

                    uint8_t kbuf[256]; // Write in chunks to avoid large stack usage.
                    size_t copied = 0;
                    while (copied < towrite) {
                        size_t chunk = towrite - copied;
                        if (chunk > sizeof(kbuf)) {
                            chunk = sizeof(kbuf);
                        }

                        // For atomic writes, don't release lock during copy (guarantees no interleaving).
                        if (!atomic_write) {
                            this->datalock.release();
                        }

                        // Copy from user space to kernel buffer.
                        int ret = NMem::UserCopy::copyfrom(kbuf, ubuf + byteswritten + copied, chunk);
                        if (ret < 0) {
                            // Copy failed.
                            if (!atomic_write) {
                                this->datalock.acquire();
                            }
                            if (byteswritten + copied > 0) {
                                this->datalock.release();
                                return byteswritten + copied;
                            }
                            this->datalock.release();
                            return ret;
                        }

                        if (!atomic_write) {
                            this->datalock.acquire();

                            // Check readers still exist after re-acquiring lock.
                            if (this->readers == 0) {
                                this->datalock.release();
                                NSched::signalproc(NArch::CPU::get()->currthread->process, SIGPIPE);
                                if (byteswritten + copied > 0) {
                                    return byteswritten + copied;
                                }
                                return -EPIPE;
                            }
                        }

                        // Push to circular buffer from kernel buffer.
                        for (size_t i = 0; i < chunk; i++) {
                            this->databuffer.push(kbuf[i]);
                        }

                        copied += chunk;
                    }

                    byteswritten += towrite;
                    this->datalock.release();

                    // Wake any waiting readers.
                    this->readwq.wake();

                    // Re-acquire lock for next iteration.
                    this->datalock.acquire();
                    continue;
                }

                if (fdflags & VFS::O_NONBLOCK) {
                    this->datalock.release();
                    if (byteswritten > 0) {
                        return byteswritten;
                    }
                    return -EAGAIN; // No space, so we return EAGAIN and leave it up to the caller to try again later.
                }

                // Wait for space or readers to close.
                int ret;
                waiteventinterruptiblelocked(&this->writewq, (!this->databuffer.full() || this->readers == 0), &this->datalock, ret);
                if (ret < 0) {
                    this->datalock.release();
                    if (byteswritten > 0) {
                        return byteswritten; // Return partial write.
                    }
                    return ret; // Return -EINTR.
                }
            }

            this->datalock.release();
            return byteswritten;
        }
    }
}