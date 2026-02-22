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

        // Initialise signal state to defaults (no pending, all handlers SIG_DFL).
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
            // Remove ourselves from process group.
            mypgrp->procs.remove([](Process *p, void *arg) {
                return p == ((Process *)arg);
            }, (void *)this);

            bool pgrpempty = mypgrp->procs.empty();
            bool pgrpnorefs = (mypgrp->getrefcount() == 0);

            if (pgrpempty && pgrpnorefs) { // If that group is then empty, we can delete it.
                if (mysession) { // If the group had a session, remove the group from the session and delete the session if it's empty.
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

        if (this->parent) { // If we have a parent (near-universal except for init), remove ourselves from its children list.
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

        if (children.size() && this != initproc) { // If we have children and we aren't init (which reaps itself), we need to reparent them to init.
            NLib::DoubleList<Process *>::Iterator it = this->children.begin();
            for (; it.valid(); it.next()) {
                Process *child = *(it.get());
                child->lock.acquire();

                initproc->lock.acquire();
                child->parent = initproc; // Reparent to init.
                initproc->children.push(child);
                initproc->lock.release();

                // Notify init of reparenting, so it can reap if needed.
                signalproc(initproc, SIGCHLD); // XXX: Is this a potential deadlock location?

                child->lock.release();
            }
        }


        this->lock.release();
        pidtablelock.release();
    }

#define RUSAGE_SELF     0
#define RUSAGE_CHILDREN (-1)
#define RUSAGE_THREAD   1

    struct rusage {
        struct NSys::Clock::timeval ru_utime; // User CPU time.
        struct NSys::Clock::timeval ru_stime; // System CPU time.

        long ru_maxrss;   // Maximum resident set size.
        long ru_ixrss;    // Integral shared memory size.
        long ru_idrss;    // Integral unshared data size.
        long ru_isrss;    // Integral unshared stack size.
        long ru_minflt;   // Page reclaims (soft page faults).
        long ru_majflt;   // Page faults (hard page faults).
        long ru_nswap;    // Swaps.
        long ru_inblock;  // Block input operations.
        long ru_oublock;  // Block output operations.
        long ru_msgsnd;   // Messages sent.
        long ru_msgrcv;   // Messages received.
        long ru_nsignals; // Signals received.
        long ru_nvcsw;    // Voluntary context switches.
        long ru_nivcsw;   // Involuntary context switches.
    };

    static void tickstotimeval(uint64_t ticks, struct NSys::Clock::timeval *tv) {
#ifdef __x86_64__
        uint64_t freq = NArch::TSC::hz;
        if (freq == 0) {
            tv->tv_sec = 0;
            tv->tv_usec = 0;
            return;
        }
        tv->tv_sec = ticks / freq;
        tv->tv_usec = ((ticks % freq) * 1000000) / freq;
#else
        assert(false, "tickstotimeval not implemented on this architecture.");
#endif
    }

    extern "C" int sys_getrusage(int who, struct rusage *rusage) {
        SYSCALL_LOG("sys_getrusage(%d, %p).\n", who, rusage);

        if (!rusage) {
            SYSCALL_RET(-EFAULT);
        }

        Thread *thread = NArch::CPU::get()->currthread;
        Process *proc = thread->process;

        struct rusage krusage;
        NLib::memset(&krusage, 0, sizeof(krusage));

        uint64_t cputicks = 0;

        switch (who) {
            case RUSAGE_SELF:
                // Return resource usage for the calling process.
                cputicks = __atomic_load_n(&proc->cputimeticks, memory_order_relaxed);
                tickstotimeval(cputicks, &krusage.ru_utime);
                // ru_stime is 0 for now (we don't distinguish user/system time).
                break;

            case RUSAGE_THREAD:
                // Return resource usage for the calling thread.
                cputicks = __atomic_load_n(&thread->cputimeticks, memory_order_relaxed);
                tickstotimeval(cputicks, &krusage.ru_utime);
                break;

            case RUSAGE_CHILDREN:
                // Return resource usage for all terminated children.
                // XXX: We don't currently track this. Return zeros.
                break;

            default:
                SYSCALL_RET(-EINVAL);
        }

        // Copy result to userspace.
        int err = NMem::UserCopy::copyto(rusage, &krusage, sizeof(krusage));
        if (err) {
            SYSCALL_RET(-EFAULT);
        }

        SYSCALL_RET(0);
    }

    extern "C" uint64_t sys_fork(void) {
        SYSCALL_LOG("sys_fork().\n");

        Process *current = NArch::CPU::get()->currthread->process;

        struct VMM::addrspace *childspace = VMM::forkcontext(current->addrspace);
        if (!childspace) {
            SYSCALL_RET(-ENOMEM);
        }

        NFS::VFS::FileDescriptorTable *childfdtable = current->fdtable->fork();
        if (!childfdtable) {
            // TODO: Clean up childspace.
            SYSCALL_RET(-ENOMEM);
        }

        NLib::ScopeIRQSpinlock pidguard(&pidtablelock);
        NLib::ScopeIRQSpinlock guard(&current->lock);

        Process *child = new Process(childspace, childfdtable);
        if (!child) {
            SYSCALL_RET(-ENOMEM);
        }

        pidtable->insert(child->id, child);

        child->cwd = current->cwd;
        if (child->cwd) {
            child->cwd->ref(); // Add new reference.
            if (child->cwd->fs) {
                child->cwd->fs->fsref();  // Filesystem reference for forked cwd.
            }
        }

        child->root = current->root;
        if (child->root) {
            child->root->ref(); // Add new reference.
            if (child->root->fs) {
                child->root->fs->fsref();  // Filesystem reference for forked root.
            }
        }

        // Clone for permissions.
        child->euid = current->euid;
        child->egid = current->egid;
        child->suid = current->suid;
        child->sgid = current->sgid;
        child->uid = current->uid;
        child->gid = current->gid;
        child->umask = current->umask;

        // Inherit controlling terminal.
        child->tty = __atomic_load_n(&current->tty, memory_order_relaxed);

        // Establish child<->parent relationship between processes.
        child->parent = current;
        current->children.push(child);

        child->session = current->session;
        child->pgrp = current->pgrp;

        // Increment reference counts for inherited pgrp/session.
        if (child->session) {
            child->session->ref();
        }
        if (child->pgrp) {
            child->pgrp->ref();
        }

        // Add to process group with proper locking.
        {
            NLib::ScopeIRQSpinlock pgrpguard(&child->pgrp->lock);
            child->pgrp->procs.push(child);
        }

        Thread *cthread = new Thread(child, NSched::DEFAULTSTACKSIZE);
        if (!cthread) {
            // Clean up child process on thread allocation failure.
            child->pgrp->lock.acquire();
            child->pgrp->procs.remove([](Process *p, void *arg) {
                return p == ((Process *)arg);
            }, (void *)child);
            child->pgrp->lock.release();

            current->children.remove([](Process *p, void *arg) {
                return p == ((Process *)arg);
            }, (void *)child);

            if (child->cwd) {
                child->cwd->unref();
            }

            if (child->root) {
                if (child->root->fs) {
                    child->root->fs->fsunref();
                }
                child->root->unref();
            }

            if (child->session) {
                child->session->unref();
            }

            if (child->pgrp) {
                child->pgrp->unref();
            }

            pidtable->remove(child->id);
            delete child;
            SYSCALL_RET(-ENOMEM);
        }

#ifdef __x86_64__
        cthread->ctx = *NArch::CPU::get()->currthread->sysctx; // Initialise using system call context.

        cthread->ctx.rax = 0; // Override return to indicate this is the child.


        // Save extra contexts.
        NArch::CPU::savexctx(&cthread->xctx);
        if (NArch::CPU::get()->currthread->fctx.mathused) {
            NArch::CPU::savefctx(&cthread->fctx);
        }


#endif

        for (size_t i = 0; i < NSIG; i++) {
            // Inherit handlers.
            child->signalstate.actions[i] = current->signalstate.actions[i];
        }
        child->signalstate.pending = 0; // Pending signals are NOT inherited.
        cthread->blocked = __atomic_load_n(&NArch::CPU::get()->currthread->blocked, memory_order_acquire); // Copy calling thread's signal mask to child thread.

        NSched::schedulethread(cthread);

        SYSCALL_RET(child->id);
    }

    extern "C" uint64_t sys_setsid(void) {
        SYSCALL_LOG("sys_setsid().\n");

        Process *current = NArch::CPU::get()->currthread->process;
        NLib::ScopeIRQSpinlock guard(&current->lock);

        ProcessGroup *oldpgrp = current->pgrp;
        oldpgrp->lock.acquire();
        if (oldpgrp->id == current->id) {
            oldpgrp->lock.release();
            SYSCALL_RET(-EPERM); // Can't create a new session as group leader.
        }
        oldpgrp->lock.release();

        // We must create a new session.
        Session *session = new Session();
        if (!session) {
            SYSCALL_RET(-ENOMEM);
        }
        session->id = current->id;
        session->ctty = 0;

        // And a new session needs a new process group to be connected to it.
        NSched::ProcessGroup *pgrp = new ProcessGroup();
        if (!pgrp) {
            delete session;
            SYSCALL_RET(-ENOMEM);
        }
        session->ref();

        pgrp->id = current->id;
        pgrp->procs.push(current);
        pgrp->session = session;
        pgrp->ref(); // Reference for current->pgrp

        session->pgrps.push(pgrp);

        // Release references to old pgrp and session.
        Session *oldsession = current->session;
        if (oldsession) {
            oldsession->unref();
        }
        oldpgrp->unref();

        // Remove from old process group and clean up if empty and no refs.
        bool shoulddeleteoldpgrp = false;
        bool shoulddeleteoldsession = false;
        {
            NLib::ScopeIRQSpinlock oldpgrpguard(&oldpgrp->lock);
            oldpgrp->procs.remove([](Process *p, void *arg) {
                return p == ((Process *)arg);
            }, (void *)current);

            if (oldpgrp->procs.empty() && oldpgrp->getrefcount() == 0) {
                shoulddeleteoldpgrp = true;
                if (oldsession) {
                    NLib::ScopeIRQSpinlock sessionguard(&oldsession->lock);
                    oldsession->pgrps.remove([](ProcessGroup *pg, void *arg) {
                        return pg == ((ProcessGroup *)arg);
                    }, (void *)oldpgrp);

                    if (oldsession->pgrps.empty() && oldsession->getrefcount() == 0) {
                        shoulddeleteoldsession = true;
                    }
                }
            }
        }
        if (shoulddeleteoldpgrp) {
            delete oldpgrp;
        }
        if (shoulddeleteoldsession) {
            delete oldsession;
        }

        current->pgrp = pgrp;
        current->session = session;

        SYSCALL_RET(session->id);
    }

    extern "C" uint64_t sys_setpgid(int pid, int pgid) {
        SYSCALL_LOG("sys_setpgid(%d, %d).\n", pid, pgid);

        Process *current = NArch::CPU::get()->currthread->process;

        NLib::ScopeIRQSpinlock pidguard(&pidtablelock);

        if (pid == 0) { // PID 0 means us.
            pid = current->id;
        }

        if (pid < 0) {
            SYSCALL_RET(-EINVAL);
        }

        if (pgid == 0) { // PGID 0 means use pid as pgid.
            pgid = pid;
        }

        // Negative pgid is invalid.
        if (pgid < 0) {
            SYSCALL_RET(-EINVAL);
        }

        // Find the target process.
        Process **ptarget = pidtable->find(pid);
        if (!ptarget) {
            SYSCALL_RET(-ESRCH); // No such process.
        }
        Process *target = *ptarget;

        NLib::ScopeIRQSpinlock targetguard(&target->lock);

        // The target process must be either the calling process or a child of the calling process.
        if (target != current) {
            bool ischild = false;
            NLib::DoubleList<Process *>::Iterator it = current->children.begin();
            for (; it.valid(); it.next()) {
                if (*(it.get()) == target) {
                    ischild = true;
                    break;
                }
            }

            if (!ischild) {
                SYSCALL_RET(-ESRCH); // Not our child.
            }

            if (target->hasexeced) {
                SYSCALL_RET(-EACCES); // Child has already called execve.
            }
        }

        if (target->session && target->id == target->session->id) {
            SYSCALL_RET(-EPERM); // Can't change pgid of a session leader.
        }

        ProcessGroup *newpgrp = NULL;
        if (pgid != target->id) { // We join an existing process group if pgid != target's pid.
            Process **pgleader = pidtable->find(pgid);
            if (!pgleader) { // No leader found.
                SYSCALL_RET(-EPERM); // Process group doesn't exist.
            }
            Process *gleader = *pgleader;

            NLib::ScopeIRQSpinlock gleaderguard(&gleader->lock);

            if (!gleader->pgrp || gleader->pgrp->id != (size_t)pgid) {
                SYSCALL_RET(-EPERM); // Process is not a process group leader.
            }

            // Target and new process group must be in the same session.
            if (!target->session || !gleader->session || target->session != gleader->session) {
                SYSCALL_RET(-EPERM);
            }

            newpgrp = gleader->pgrp;
            newpgrp->ref(); // Take reference for target->pgrp
        } else {
            if (!target->session) { // Must have a session to create a new process group.
                SYSCALL_RET(-EPERM);
            }

            // Create new process group.
            newpgrp = new ProcessGroup();
            if (!newpgrp) {
                SYSCALL_RET(-ENOMEM);
            }
            newpgrp->id = pgid;
            newpgrp->session = target->session;
            newpgrp->ref(); // Reference for target->pgrp

            // Add to session's process group list.
            NLib::ScopeIRQSpinlock sessionguard(&target->session->lock);
            target->session->pgrps.push(newpgrp);
        }

        // Remove from old process group.
        ProcessGroup *oldpgrp = NULL;
        bool shoulddeleteoldpgrp = false;
        if (target->pgrp) {
            oldpgrp = target->pgrp;
            oldpgrp->unref(); // Release reference from target->pgrp
            {
                NLib::ScopeIRQSpinlock oldpgrpguard(&oldpgrp->lock);
                oldpgrp->procs.remove([](Process *p, void *arg) {
                    return p == ((Process *)arg);
                }, (void *)target);

                // If old process group is now empty, has no refs, and it's not the new one, clean it up.
                if (oldpgrp->procs.empty() && oldpgrp->getrefcount() == 0 && oldpgrp != newpgrp) {
                    shoulddeleteoldpgrp = true;
                    Session *oldsession = oldpgrp->session;
                    if (oldsession) {
                        NLib::ScopeIRQSpinlock sessionguard(&oldsession->lock);
                        oldsession->pgrps.remove([](ProcessGroup *pg, void *arg) {
                            return pg == ((ProcessGroup *)arg);
                        }, (void *)oldpgrp);
                    }
                }
            }
            // Delete after releasing lock.
            if (shoulddeleteoldpgrp) {
                delete oldpgrp;
            }
        }

        // Add to new process group.
        {
            NLib::ScopeIRQSpinlock newpgrpguard(&newpgrp->lock);
            target->pgrp = newpgrp;
            newpgrp->procs.push(target);
        }

        SYSCALL_RET(0); // Success.
    }

    extern "C" uint64_t sys_getpgid(int pid) {
        SYSCALL_LOG("sys_getpgid(%d).\n", pid);

        NLib::ScopeIRQSpinlock guard(&pidtablelock);

        if (!pid) {
            // Return current process' process group ID.
            SYSCALL_RET(NArch::CPU::get()->currthread->process->pgrp->id);
        }

        Process **pproc = pidtable->find(pid);
        if (!pproc) {
            SYSCALL_RET(-ESRCH);
        }

        Process *proc = *pproc;
        // Return the process group of whatever we found.
        SYSCALL_RET(proc->pgrp->id);
    }

    extern "C" uint64_t sys_gettid(void) {
        SYSCALL_LOG("sys_gettid().\n");
        SYSCALL_RET(CPU::get()->currthread->id);
    }

    extern "C" uint64_t sys_getpid(void) {
        SYSCALL_LOG("sys_getpid().\n");
        SYSCALL_RET(CPU::get()->currthread->process->id);
    }

    extern "C" uint64_t sys_getppid(void) {
        SYSCALL_LOG("sys_getppid().\n");
        if (CPU::get()->currthread->process->parent) {
            SYSCALL_RET(CPU::get()->currthread->process->parent->id);
        }
        SYSCALL_RET(0); // Default to no parent PID.
    }

    #define WNOHANG     1 // Don't block.
    #define WUNTRACED   2 // Report stopped children.
    #define WCONTINUED  8 // Report continued children.

    // POSIX status encoding macros.
    #define W_EXITCODE(ret, sig) ((ret) << 8 | (sig))
    #define W_STOPCODE(sig) ((sig) << 8 | 0x7f)

    // Find a child matching the pid criteria.
    // If wantstate is ZOMBIE, looks for zombie children to reap.
    // If wantstate is STOPPED, looks for stopped children (for WUNTRACED).
    // If wantstate is RUNNING, just checks existence.
    static Process *findchildbystate(Process *parent, int pid, Process::state wantstate) {
        NLib::DoubleList<Process *>::Iterator it = parent->children.begin();
        for (; it.valid(); it.next()) {
            Process *child = *(it.get());
            bool match = false;

            child->lock.acquire();

            // Check if child state matches what we want.
            if (wantstate == Process::state::ZOMBIE && child->pstate != Process::state::ZOMBIE) {
                child->lock.release();
                continue;
            }
            if (wantstate == Process::state::STOPPED && child->pstate != Process::state::STOPPED) {
                child->lock.release();
                continue;
            }

            if (pid == -1) { // Any child.
                match = true;
            } else if (pid > 0) { // Specific PID.
                if (child->id == (size_t)pid) {
                    match = true;
                }
            } else if (pid == 0) { // Any child in our process group.
                if (child->pgrp == parent->pgrp) {
                    match = true;
                }
            } else { // Negative PID means any child in process group -pid.
                if (child->pgrp->id == (size_t)(-pid)) {
                    match = true;
                }
            }

            if (match) {
                if (wantstate == Process::state::ZOMBIE) {
                    // Atomically claim the zombie by transitioning to REAPING state.
                    child->pstate = Process::state::REAPING;
                }
                child->lock.release();
                return child;
            }

            child->lock.release();
        }
        return NULL;
    }

    static Process *findchild(Process *parent, int pid, bool zombie) {
        NLib::DoubleList<Process *>::Iterator it = parent->children.begin();
        int childcount = 0;
        for (; it.valid(); it.next()) {
            Process *child = *(it.get());
            childcount++;

            bool match = false;

            child->lock.acquire();
            // Skip processes being reaped by another waitpid call.
            if (zombie && child->pstate != Process::state::ZOMBIE) {
                child->lock.release();
                continue; // Wanted zombies, but this is not one (or already being reaped).
            }

            if (pid == -1) { // Any child.
                match = true;
            } else if (pid > 0) { // Specific PID.
                if (child->id == (size_t)pid) {
                    match = true;
                }
            } else if (pid == 0) { // Any child in our process group.
                if (child->pgrp == parent->pgrp) {
                    match = true;
                }
            } else { // Negative PID means any child in process group -pid.
                if (child->pgrp->id == (size_t)(-pid)) {
                    match = true;
                }
            }

            if (match && zombie) {
                // Atomically claim the zombie by transitioning to REAPING state.
                // This prevents other concurrent waitpid calls from reaping the same child.
                child->pstate = Process::state::REAPING;
                child->lock.release();
                return child;
            }

            child->lock.release();

            if (match) {
                return child;
            }
        }
        return NULL;
    }

    extern "C" uint64_t sys_waitpid(int pid, int *status, int options) {
        SYSCALL_LOG("sys_waitpid(%d, %p, %d).\n", pid, status, options);

        if (status && !NMem::UserCopy::valid(status, sizeof(int))) {
            SYSCALL_RET(-EFAULT);
        }

        Process *current = NArch::CPU::get()->currthread->process;
        current->lock.acquire();

        // Check if we have any children that match.
        bool haschildren = findchild(current, pid, false) != NULL;

        if (!haschildren) {
            current->lock.release();
            SYSCALL_RET(-ECHILD); // No matching children.
        }

        Process *found = NULL;
        bool isstopped = false;

        if (options & WNOHANG) {
            // Non-blocking wait, but check for zombies first.
            found = findchild(current, pid, true);
            if (!found && (options & WUNTRACED)) {
                // Check for stopped children.
                found = findchildbystate(current, pid, Process::state::STOPPED);
                if (found) {
                    isstopped = true;
                }
            }
            if (!found) {
                current->lock.release();
                SYSCALL_RET(0); // No matching zombies or stopped children.
            }
        } else {
            // Blocking wait.
            int ret = 0;
            while (true) {
                // Check for zombies.
                found = findchild(current, pid, true);
                if (found != NULL) {
                    break;
                }

                // Check for stopped children if WUNTRACED.
                if (options & WUNTRACED) {
                    found = findchildbystate(current, pid, Process::state::STOPPED);
                    if (found != NULL) {
                        isstopped = true;
                        break;
                    }
                }

                int __ret = current->exitwq.waitinterruptiblelocked(&current->lock);
                if (__ret < 0) {
                    ret = __ret;
                    break;
                }
            }

            if (ret < 0) {
                // Even if interrupted, check if something appeared.
                found = findchild(current, pid, true);
                if (!found && (options & WUNTRACED)) {
                    found = findchildbystate(current, pid, Process::state::STOPPED);
                    if (found) {
                        isstopped = true;
                    }
                }
                if (!found) {
                    current->lock.release();
                    SYSCALL_RET(ret); // Interrupted and no child state change.
                }
                // Fall through to handle the found child.
            }
        }

        current->lock.release();

        if (isstopped) {
            // Report stopped child without reaping.
            found->lock.acquire();
            int stopsig = found->stopsig;
            size_t fid = found->id;
            found->lock.release();

            if (status) {
                int stopstatus = W_STOPCODE(stopsig);
                if (NMem::UserCopy::copyto(status, &stopstatus, sizeof(int)) < 0) {
                    SYSCALL_RET(-EFAULT);
                }
            }

            SYSCALL_RET(fid);
        }

        // The found process is a zombie now in REAPING state (claimed by us in findchild), so no other waitpid can race with us to reap it.
        found->lock.acquire();
        // Verify we still own the zombie (should always be true since we claimed it).
        assert(found->pstate == Process::state::REAPING, "Zombie not in REAPING state after claim");
        int zstatus = found->exitstatus;
        size_t zid = found->id;

        if (status) {
            // Copy status out.
            if (NMem::UserCopy::copyto(status, &zstatus, sizeof(int)) < 0) {
                // Revert to ZOMBIE state so another waiter can try.
                found->pstate = Process::state::ZOMBIE;
                found->lock.release();
                SYSCALL_RET(-EFAULT);
            }
        }

        found->pstate = Process::state::DEAD;
        found->lock.release();

        // Destructor will acquire parent lock to remove from children list.
        // Don't hold it here to avoid double acquisition.
        delete found; // Reap process.

        SYSCALL_RET(zid);
    }

    extern "C" uint64_t sys_getresuid(int *ruid, int *euid, int *suid) {
        SYSCALL_LOG("sys_getresuid(%p, %p, %p).\n", ruid, euid, suid);

        Process *current = NArch::CPU::get()->currthread->process;
        NLib::ScopeIRQSpinlock guard(&current->lock);

        if (ruid) {
            if (!NMem::UserCopy::valid(ruid, sizeof(int))) {
                SYSCALL_RET(-EFAULT);
            }
            int r = current->uid;
            if (NMem::UserCopy::copyto(ruid, &r, sizeof(int)) < 0) {
                SYSCALL_RET(-EFAULT);
            }
        }

        if (euid) {
            if (!NMem::UserCopy::valid(euid, sizeof(int))) {
                SYSCALL_RET(-EFAULT);
            }
            int e = current->euid;
            if (NMem::UserCopy::copyto(euid, &e, sizeof(int)) < 0) {
                SYSCALL_RET(-EFAULT);
            }
        }

        if (suid) {
            if (!NMem::UserCopy::valid(suid, sizeof(int))) {
                SYSCALL_RET(-EFAULT);
            }
            int s = current->suid;
            if (NMem::UserCopy::copyto(suid, &s, sizeof(int)) < 0) {
                SYSCALL_RET(-EFAULT);
            }
        }

        SYSCALL_RET(0);
    }

    extern "C" uint64_t sys_getresgid(int *rgid, int *egid, int *sgid) {
        SYSCALL_LOG("sys_getresgid(%p, %p, %p).\n", rgid, egid, sgid);

        Process *current = NArch::CPU::get()->currthread->process;
        NLib::ScopeIRQSpinlock guard(&current->lock);

        if (rgid) {
            if (!NMem::UserCopy::valid(rgid, sizeof(int))) {
                SYSCALL_RET(-EFAULT);
            }
            int r = current->gid;
            if (NMem::UserCopy::copyto(rgid, &r, sizeof(int)) < 0) {
                SYSCALL_RET(-EFAULT);
            }
        }

        if (egid) {
            if (!NMem::UserCopy::valid(egid, sizeof(int))) {
                SYSCALL_RET(-EFAULT);
            }
            int e = current->egid;
            if (NMem::UserCopy::copyto(egid, &e, sizeof(int)) < 0) {
                SYSCALL_RET(-EFAULT);
            }
        }

        if (sgid) {
            if (!NMem::UserCopy::valid(sgid, sizeof(int))) {
                SYSCALL_RET(-EFAULT);
            }
            int s = current->sgid;
            if (NMem::UserCopy::copyto(sgid, &s, sizeof(int)) < 0) {
                SYSCALL_RET(-EFAULT);
            }
        }

        SYSCALL_RET(0);
    }

    extern "C" uint64_t sys_setresuid(int ruid, int euid, int suid) {
        SYSCALL_LOG("sys_setresuid(%d, %d, %d).\n", ruid, euid, suid);

        Process *current = NArch::CPU::get()->currthread->process;
        NLib::ScopeIRQSpinlock guard(&current->lock);

        bool privileged = (NArch::CPU::get()->currthread->process->euid == 0);
        // setresuid(2):
        // An unprivileged process may change its real UID, effective UID,
        // and saved set-user-ID, each to one of: the current real UID, the
        // current effective UID, or the current saved set-user-ID.

        if (ruid != -1) {
            if (privileged || ruid == current->uid || ruid == current->euid || ruid == current->suid) {
                current->uid = ruid;
            } else {
                SYSCALL_RET(-EPERM);
            }
        }
        if (euid != -1) {
            if (privileged || euid == current->uid || euid == current->euid || euid == current->suid) {
                current->euid = euid;
            } else {
                SYSCALL_RET(-EPERM);
            }
        }
        if (suid != -1) {
            if (privileged || suid == current->uid || suid == current->euid || suid == current->suid) {
                current->suid = suid;
            } else {
                SYSCALL_RET(-EPERM);
            }
        }

        SYSCALL_RET(0);
    }

    extern "C" uint64_t sys_setresgid(int rgid, int egid, int sgid) {
        SYSCALL_LOG("sys_setresgid(%d, %d, %d).\n", rgid, egid, sgid);

        Process *current = NArch::CPU::get()->currthread->process;
        NLib::ScopeIRQSpinlock guard(&current->lock);

        bool privileged = (NArch::CPU::get()->currthread->process->euid == 0);
        // setresgid(2):
        // An unprivileged process may change its real GID, effective GID,
        // and saved set-group-ID, each to one of: the current real GID, the
        // current effective GID, or the current saved set-group-ID.

        if (rgid != -1) {
            if (privileged || rgid == current->gid || rgid == current->egid || rgid == current->sgid) {
                current->gid = rgid;
            } else {
                SYSCALL_RET(-EPERM);
            }
        }
        if (egid != -1) {
            if (privileged || egid == current->gid || egid == current->egid || egid == current->sgid) {
                current->egid = egid;
            } else {
                SYSCALL_RET(-EPERM);
            }
        }
        if (sgid != -1) {
            if (privileged || sgid == current->gid || sgid == current->egid || sgid == current->sgid) {
                current->sgid = sgid;
            } else {
                SYSCALL_RET(-EPERM);
            }
        }

        SYSCALL_RET(0);
    }
}