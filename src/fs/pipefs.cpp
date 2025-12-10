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

        PipeNode::PipeNode(VFS::IFileSystem *fs, const char *name, struct VFS::stat attr) : VFS::INode(fs, name, attr), databuffer(PIPEBUFSIZE) {

        }

        int PipeNode::open(int flags) {
            this->datalock.acquire();

            if ((flags & VFS::O_ACCMODE) == VFS::O_WRONLY) {
                this->writers++;
            } else if ((flags & VFS::O_ACCMODE) == VFS::O_RDONLY) {
                this->readers++;
            }

            this->datalock.release();
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
            }

            this->datalock.release();

            // Wake any waiting threads so they can check for EOF or broken pipe
            this->wq.wake();

            return 0;
        }

        ssize_t PipeNode::read(void *buf, size_t count, off_t offset, int fdflags) {
            (void)offset; // Pipes ignore offset

            if (count == 0) {
                return 0;
            }

            uint8_t *ubuf = (uint8_t *)buf;
            size_t bytesread = 0;


            this->datalock.acquire();
            while (bytesread < count) {

                // Check if data is available
                if (!this->databuffer.empty()) {
                    // Read as much as possible from buffer
                    size_t toread = count - bytesread;
                    size_t available = this->databuffer.size();
                    if (toread > available) {
                        toread = available;
                    }

                    for (size_t i = 0; i < toread; i++) {
                        ubuf[bytesread + i] = this->databuffer.pop();
                    }

                    bytesread += toread;
                    this->datalock.release();

                    // Wake any waiting writers
                    this->wq.wake();

                    // If we've read at least some data, return it
                    return bytesread;
                }

                // No data available - check if we should return EOF
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

                // Wait for data or writers to close
                waiteventlocked(&this->wq, (!this->databuffer.empty() || this->writers == 0), &this->datalock);
            }

            this->datalock.release();
            return bytesread;
        }

        ssize_t PipeNode::write(const void *buf, size_t count, off_t offset, int fdflags) {
            (void)offset; // Pipes ignore offset

            if (count == 0) {
                return 0;
            }

            const uint8_t *ubuf = (const uint8_t *)buf;
            size_t byteswritten = 0;


            this->datalock.acquire();
            while (byteswritten < count) {

                // Check if any readers exist
                if (this->readers == 0) {
                    this->datalock.release();
                    // Send SIGPIPE to current process for writing to pipe with no readers.
                    NSched::signalproc(NArch::CPU::get()->currthread->process, SIGPIPE);
                    return -EPIPE;
                }

                // Check if space is available in buffer
                if (!this->databuffer.full()) {
                    // Write as much as possible to buffer
                    size_t towrite = count - byteswritten;
                    size_t space = this->databuffer.available();
                    if (towrite > space) {
                        towrite = space;
                    }

                    for (size_t i = 0; i < towrite; i++) {
                        this->databuffer.push(ubuf[byteswritten + i]);
                    }

                    byteswritten += towrite;
                    this->datalock.release();

                    // Wake any waiting readers
                    this->wq.wake();

                    // Continue writing remaining data
                    continue;
                }

                // Buffer is full
                if (fdflags & VFS::O_NONBLOCK) {
                    this->datalock.release();
                    if (byteswritten > 0) {
                        return byteswritten;
                    }
                    return -EAGAIN; // No space, so we return EAGAIN and leave it up to the caller to try again later.
                }

                // Wait for space or readers to close
                waiteventlocked(&this->wq, (!this->databuffer.full() || this->readers == 0), &this->datalock);
            }

            this->datalock.release();
            return byteswritten;
        }
    }
}