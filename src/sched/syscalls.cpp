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

    extern "C" uint64_t sys_exit(int status) {
        SYSCALL_LOG("sys_exit(%d).\n", status);

        exit(status); // Exit.
        __builtin_unreachable();
    }

    // XXX: Only guaranteed millisecond precision, as we convert from timespec to milliseconds.
    extern "C" ssize_t sys_sleep(struct NSys::Clock::timespec *req, struct NSys::Clock::timespec *rem) {
        SYSCALL_LOG("sys_sleep(%p, %p)\n", req, rem);

        if (!req) {
            SYSCALL_RET(-EFAULT);
        }

        // Copy timespec from userspace.
        struct NSys::Clock::timespec kreq;
        if (NMem::UserCopy::copyfrom(&kreq, req, sizeof(struct NSys::Clock::timespec)) < 0) {
            SYSCALL_RET(-EFAULT);
        }

        // Validate timespec.
        if (kreq.tv_sec < 0 || kreq.tv_nsec < 0 || kreq.tv_nsec >= NSys::Clock::NSEC_PER_SEC) {
            SYSCALL_RET(-EINVAL);
        }

        // Convert to milliseconds, rounding up.
        uint64_t ms = (uint64_t)kreq.tv_sec * NSys::Clock::MSEC_PER_SEC;
        uint64_t ns_to_ms = (kreq.tv_nsec + 999999) / 1000000; // Round up nanoseconds to milliseconds.
        ms += ns_to_ms;

        // Record start time if we need to compute remaining time.
        struct NSys::Clock::timespec start_time;
        if (rem) {
            NSys::Clock::Clock *clock = NSys::Clock::getclock(NSys::Clock::CLOCK_MONOTONIC);
            if (clock && clock->gettime(&start_time) < 0) {
                SYSCALL_RET(-EFAULT);
            }
        }

        // Perform sleep.
        int ret = sleep(ms);

        // If interrupted and rem is provided, calculate remaining time.
        if (ret == -EINTR && rem) {
            struct NSys::Clock::timespec end_time;
            NSys::Clock::Clock *clock = NSys::Clock::getclock(NSys::Clock::CLOCK_MONOTONIC);
            if (clock && clock->gettime(&end_time) == 0) {
                // Calculate elapsed time in nanoseconds.
                uint64_t elapsed_ns = ((uint64_t)end_time.tv_sec * NSys::Clock::NSEC_PER_SEC + (uint64_t)end_time.tv_nsec) -
                                      ((uint64_t)start_time.tv_sec * NSys::Clock::NSEC_PER_SEC + (uint64_t)start_time.tv_nsec);

                // Calculate requested time in nanoseconds.
                uint64_t requested_ns = (uint64_t)kreq.tv_sec * NSys::Clock::NSEC_PER_SEC + (uint64_t)kreq.tv_nsec;

                // Calculate remaining time.
                uint64_t remaining_ns = (elapsed_ns < requested_ns) ? (requested_ns - elapsed_ns) : 0;

                struct NSys::Clock::timespec krem;
                krem.tv_sec = remaining_ns / NSys::Clock::NSEC_PER_SEC;
                krem.tv_nsec = remaining_ns % NSys::Clock::NSEC_PER_SEC;

                if (NMem::UserCopy::copyto(rem, &krem, sizeof(struct NSys::Clock::timespec)) < 0) {
                    // If we can't copy the remaining time, we still return -EINTR.
                    // POSIX allows this behavior.
                }
            }
        }

        SYSCALL_RET(ret);
    }

    extern "C" uint64_t sys_fork(void) {
        SYSCALL_LOG("sys_fork().\n");

        NLib::ScopeIRQSpinlock pidguard(&pidtablelock);

        Process *current = NArch::CPU::get()->currthread->process;

        NLib::ScopeIRQSpinlock guard(&current->lock);

        Process *child = new Process(VMM::forkcontext(current->addrspace), current->fdtable->fork());
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

    extern "C" uint64_t sys_yield(void) {
        SYSCALL_LOG("sys_yield().\n");
        yield();
        SYSCALL_RET(0);
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

    struct timespec {
        long tv_sec;
        long tv_nsec;
    };

    #define FUTEX_WAIT          0
    #define FUTEX_WAKE          1
    #define FUTEX_PRIVATE_FLAG  128
    #define FUTEX_CMD_MASK      (~FUTEX_PRIVATE_FLAG)

    struct futexentry {
        WaitQueue wq;
        size_t waiters; // Number of threads waiting on this futex.
    };

    // Key is physical address of futex! Pretty neat, actually, since shared memory works correctly.
    static NLib::KVHashMap<uintptr_t, struct futexentry *> *futextable = NULL;
    static NArch::IRQSpinlock futexlock;

    // Get or create a futex entry for a given physical address.
    static struct futexentry *futexget(uintptr_t phys) {
        struct futexentry **entry = futextable->find(phys);
        if (entry) {
            return *entry;
        }

        // Create a new futex entry.
        struct futexentry *newentry = new struct futexentry;
        newentry->waiters = 0;
        futextable->insert(phys, newentry);
        return newentry;
    }

    // Remove futex entry if no more waiters.
    static void futexput(uintptr_t phys, struct futexentry *entry) {
        if (entry->waiters == 0) {
            futextable->remove(phys);
            delete entry;
        }
    }

    // Wait state for sleep()-like interruptible wake with timeout.
    struct futexwaitstate {
        WaitQueue *wq;
        bool timerfired;
        bool threadwoke;
        NArch::IRQSpinlock lock;
    };

    // Timer callback for futex timeout.
    static void futextimeoutwork(void *arg) {
        struct futexwaitstate *state = (struct futexwaitstate *)arg;

        state->lock.acquire();
        state->timerfired = true;
        bool threadwoke = state->threadwoke;
        state->lock.release();

        if (!threadwoke) {
            // Thread is still sleeping. Wake it.
            state->wq->wakeone();
        }

    }

    extern "C" ssize_t sys_futex(int *ptr, int op, int expected, struct timespec *timeout) {
        SYSCALL_LOG("sys_futex(%p, %d, %d, %p).\n", ptr, op, expected, timeout);

        // Lazily initialise the futex table.
        if (!futextable) {
            futexlock.acquire();
            if (!futextable) {
                futextable = new NLib::KVHashMap<uintptr_t, struct futexentry *>();
            }
            futexlock.release();
        }

        // Validate pointer.
        if (!ptr || !NMem::UserCopy::valid(ptr, sizeof(int))) {
            SYSCALL_RET(-EFAULT);
        }

        // Get physical address for futex key (shared memory works correctly).
        Process *proc = NArch::CPU::get()->currthread->process;
        uintptr_t phys = NArch::VMM::virt2phys(proc->addrspace, (uintptr_t)ptr);
        if (phys == 0) {
            SYSCALL_RET(-EFAULT);
        }

        int cmd = op & FUTEX_CMD_MASK;

        switch (cmd) {
            case FUTEX_WAIT: {
                // Copy timeout from userspace if provided.
                uint64_t timeoutms = 0;
                bool hastimeout = false;
                if (timeout) {
                    struct timespec ktimeout;
                    if (NMem::UserCopy::copyfrom(&ktimeout, timeout, sizeof(struct timespec)) < 0) {
                        SYSCALL_RET(-EFAULT);
                    }
                    if (ktimeout.tv_sec < 0 || ktimeout.tv_nsec < 0 || ktimeout.tv_nsec >= NSys::Clock::NSEC_PER_SEC) {
                        SYSCALL_RET(-EINVAL);
                    }
                    // Convert to milliseconds, rounding up.
                    timeoutms = (uint64_t)ktimeout.tv_sec * NSys::Clock::MSEC_PER_SEC;
                    timeoutms += (ktimeout.tv_nsec + 999999) / 1000000;
                    hastimeout = true;
                }

                futexlock.acquire();
                struct futexentry *entry = futexget(phys);

                // Atomically check the futex value.
                int currentval;
                if (NMem::UserCopy::copyfrom(&currentval, ptr, sizeof(int)) < 0) {
                    futexput(phys, entry);
                    futexlock.release();
                    SYSCALL_RET(-EFAULT);
                }

                if (currentval != expected) {
                    futexput(phys, entry);
                    futexlock.release();
                    SYSCALL_RET(-EAGAIN);
                }

                entry->waiters++;
                futexlock.release();

                int ret = 0;

                if (hastimeout && timeoutms > 0) {
                    // Wait with timeout.
                    struct futexwaitstate *state = new struct futexwaitstate;
                    state->wq = &entry->wq;
                    state->timerfired = false;
                    state->threadwoke = false;

                    NSys::Timer::timerlock();
                    NSys::Timer::create(futextimeoutwork, state, timeoutms);
                    NSys::Timer::timerunlock();

                    ret = entry->wq.waitinterruptible();

                    // Mark that we've woken up and check if timer fired.
                    state->lock.acquire();
                    state->threadwoke = true;
                    bool timerfired = state->timerfired;
                    state->lock.release();

                    delete state;

                    if (timerfired && ret == 0) {
                        // Timer woke us, this is a timeout.
                        ret = -ETIMEDOUT;
                    }
                } else if (hastimeout && timeoutms == 0) {
                    // Zero timeout means don't wait at all.
                    ret = -ETIMEDOUT;
                } else {
                    // Wait without timeout.
                    ret = entry->wq.waitinterruptible();
                }

                futexlock.acquire();
                entry->waiters--;
                futexput(phys, entry);
                futexlock.release();

                SYSCALL_RET(ret);
            }

            case FUTEX_WAKE: {
                futexlock.acquire();
                struct futexentry **entryptr = futextable->find(phys);
                if (!entryptr) {
                    futexlock.release();
                    SYSCALL_RET(0); // No waiters.
                }

                struct futexentry *entry = *entryptr;
                int woken = 0;
                int towake = expected; // 'expected' is actually the count for FUTEX_WAKE.

                size_t actualwaiters = entry->waiters;
                while (towake > 0 && actualwaiters > 0) {
                    entry->wq.wakeone(); // Wake up whatever we can.
                    woken++;
                    towake--;
                    actualwaiters--;
                }

                futexlock.release();
                SYSCALL_RET(woken);
            }

            default:
                SYSCALL_RET(-ENOSYS);
        }
    }

    extern "C" ssize_t sys_newthread(void *entry, void *stack) {
        SYSCALL_LOG("sys_newthread(%p, %p).\n", entry, stack);

        Process *proc = NArch::CPU::get()->currthread->process;

        Thread *newthread = new Thread(proc, NSched::DEFAULTSTACKSIZE);
        if (!newthread) {
            SYSCALL_RET(-ENOMEM);
        }

        newthread->ctx.rip = (uint64_t)entry;
        newthread->ctx.rsp = (uint64_t)stack;

        NSched::schedulethread(newthread);
        SYSCALL_RET(newthread->id);
    }

    extern "C" ssize_t sys_exitthread(void) {
        SYSCALL_LOG("sys_exitthread().\n");

        // Mark ourselves as dead and yield.
        NSched::setthreadstate(NArch::CPU::get()->currthread, Thread::state::DEAD, "sys_exitthread");
        yield();

        __builtin_unreachable();
    }

}