#ifdef __x86_64__
#include <arch/x86_64/apic.hpp>
#include <arch/x86_64/cpu.hpp>
#include <arch/x86_64/e9.hpp>
#include <arch/x86_64/smp.hpp>
#include <arch/x86_64/stacktrace.hpp>
#include <arch/x86_64/tsc.hpp>
#include <arch/x86_64/timer.hpp>
#endif
#include <fs/devfs.hpp>
#include <lib/assert.hpp>
#include <mm/slab.hpp>
#include <mm/ucopy.hpp>
#include <sched/event.hpp>
#include <sched/sched.hpp>
#include <std/stdatomic.h>
#include <sys/clock.hpp>
#include <sys/elf.hpp>
#include <sys/syscall.hpp>
#include <sys/timer.hpp>

namespace NSched {
    using namespace NArch;

    static size_t pidcounter = 0;
    Process *kprocess = NULL; // Kernel process.
    NArch::IRQSpinlock pidtablelock; // Lock protecting the PID table.
    NLib::KVHashMap<size_t, Process *> *pidtable = NULL; // PID to Process mapping.


    void Process::init(struct VMM::addrspace *space, NFS::VFS::FileDescriptorTable *fdtable) {
        // Each new process should be initialised with an atomically incremented PID.
        this->id = __atomic_fetch_add(&pidcounter, 1, memory_order_seq_cst);
        this->addrspace = space;
        this->addrspace->lock.acquire();
        this->addrspace->ref++; // Reference address space.
        this->addrspace->lock.release();

        // Initialize signal state to defaults (no pending, all handlers SIG_DFL).
        this->signalstate.pending = 0;
        for (size_t i = 0; i < NSIG; i++) {
            this->signalstate.actions[i].handler = SIG_DFL;
            this->signalstate.actions[i].mask = 0;
            this->signalstate.actions[i].flags = 0;
            this->signalstate.actions[i].restorer = NULL;
        }

        if (space == &VMM::kspace) {
            this->kernel = true; // Mark process as a kernel process if it uses the kernel address space.
        } else { // Only userspace threads should bother creating file descriptor tables.
            if (!fdtable) {
                this->fdtable = new NFS::VFS::FileDescriptorTable();
            } else {
                this->fdtable = fdtable; // Inherit from a forked file descriptor table we were given.
            }
        }
    }

    void Process::zombify(void) {
        this->lock.acquire();

        if (this->fdtable) {
            delete this->fdtable;
        }

        if (this->cwd) {
            if (this->cwd->fs) {
                this->cwd->fs->fsunref();  // Release filesystem reference from cwd
            }
            this->cwd->unref(); // Unreference current working directory (so it isn't marked busy).
        }

        if (this->root) {
            if (this->root->fs) {
                this->root->fs->fsunref();  // Release filesystem reference from root
            }
            this->root->unref(); // Unreference root directory.
        }

        this->addrspace->lock.acquire();
        this->addrspace->ref--;
        size_t ref = this->addrspace->ref;
        this->addrspace->lock.release();

        if (ref == 0) {
            delete this->addrspace;
        }

        this->pstate = Process::state::ZOMBIE;

        Process *parent = this->parent;

        // Release our lock before waking parent and sending SIGCHLD to avoid deadlock.
        this->lock.release();

        if (parent) {
            // Wake parent's exit wait queue so it can reap us.
            // WARNING: After wake(), parent may delete us on another CPU.
            // Do not access 'this' after wake()!
            parent->exitwq.wake();

            // Send SIGCHLD to parent per POSIX: signal sent when child terminates.
            signalproc(parent, SIGCHLD);
        }
    }

    Process::~Process(void) {
        pidtablelock.acquire();
        this->lock.acquire();

        pidtable->remove(this->id);

        ProcessGroup *mypgrp = this->pgrp;
        Session *mysession = this->session;
        this->pgrp = NULL;
        this->session = NULL;

        if (mypgrp) {
            // XXX: Orphan process groups if we're the leader.

            // Release our reference to the process group and session.
            mypgrp->unref();
            if (mysession) {
                mysession->unref();
            }

            mypgrp->lock.acquire();
            mypgrp->procs.remove([](Process *p, void *arg) {
                return p == ((Process *)arg);
            }, (void *)this);

            bool pgrpempty = mypgrp->procs.empty();
            bool pgrpnorefs = (mypgrp->getrefcount() == 0);

            if (pgrpempty && pgrpnorefs) {
                if (mysession) {
                    mysession->lock.acquire();
                    mysession->pgrps.remove([](ProcessGroup *pg, void *arg) {
                        return pg == ((ProcessGroup *)arg);
                    }, (void *)mypgrp);

                    bool sessionempty = mysession->pgrps.empty();
                    bool sessionnorefs = (mysession->getrefcount() == 0);
                    mysession->lock.release();

                    if (sessionempty && sessionnorefs) {
                        delete mysession;
                    }
                }
                mypgrp->lock.release();
                delete mypgrp;
            } else {
                mypgrp->lock.release();
            }
        }

        if (this->parent) {
            this->parent->lock.acquire();
            this->parent->children.remove([](Process *p, void *arg) {
                return p == ((Process *)arg);
            }, (void *)this);
            this->parent->lock.release();
            // Note: SIGCHLD was already sent in zombify() when child terminated.
        }

        // Find init process.
        NSched::Process **pinitproc = pidtable->find(1); // Get init process.
        assert(pinitproc, "Failed to find init process during process destruction.\n");
        Process *initproc = *pinitproc;

        if (children.size() && this != initproc) {
            NLib::DoubleList<Process *>::Iterator it = this->children.begin();
            for (; it.valid(); it.next()) {
                Process *child = *(it.get());
                child->lock.acquire();

                initproc->lock.acquire();
                child->parent = initproc; // Reparent to init.
                initproc->children.push(child);
                initproc->lock.release();

                // Notify init of reparenting, so it can reap if needed.
                signalproc(initproc, SIGCHLD);

                child->lock.release();
            }
        }


        this->lock.release();
        pidtablelock.release();
    }

}