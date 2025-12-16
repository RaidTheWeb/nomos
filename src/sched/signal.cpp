#ifdef __x86_64__
#include <arch/x86_64/cpu.hpp>
#include <arch/x86_64/e9.hpp>
#include <arch/x86_64/context.hpp>
#include <arch/x86_64/tsc.hpp>
#endif

#include <lib/errno.hpp>
#include <mm/ucopy.hpp>
#include <sched/sched.hpp>
#include <sched/signal.hpp>
#include <sys/syscall.hpp>

namespace NSched {

#ifdef __x86_64__
    struct sigframe {
        uint64_t restorer;              // __mlibc_sigret's address (assuming sa_restorer isn't screwed up somehow).
        uint64_t signo;                 // Signal number passed to handler.
        uint64_t oldmask;               // Previous signal mask to restore.
        int oldaltstackflags;           // Previous altstack flags to restore.
        struct NArch::CPU::context ctx; // Saved CPU context.
    } __attribute__((packed));
#endif

    // Default actions for each signal number.
    static const enum dflactions dflactions[] = {
        DFL_TERMINATE,              // SIGHUP
        DFL_TERMINATE,              // SIGINT
        DFL_TERMINATE,              // SIGQUIT
        DFL_TERMINATE,              // SIGILL
        DFL_TERMINATE,              // SIGTRAP
        DFL_TERMINATE,              // SIGABRT
        DFL_TERMINATE,              // SIGBUS
        DFL_TERMINATE,              // SIGFPE
        DFL_TERMINATE,              // SIGKILL
        DFL_TERMINATE,              // SIGUSR1
        DFL_TERMINATE,              // SIGSEGV
        DFL_TERMINATE,              // SIGUSR2
        DFL_TERMINATE,              // SIGPIPE
        DFL_TERMINATE,              // SIGALRM
        DFL_TERMINATE,              // SIGTERM
        DFL_TERMINATE,              // SIGSTKFLT
        DFL_IGNORE,                 // SIGCHLD
        DFL_IGNORE,                 // SIGCONT
        DFL_STOP,                   // SIGSTOP
        DFL_STOP,                   // SIGTSTP
        DFL_STOP,                   // SIGTTIN
        DFL_STOP,                   // SIGTTOU
        DFL_IGNORE,                 // SIGURG
        DFL_TERMINATE,              // SIGXCPU
        DFL_TERMINATE,              // SIGXFSZ
        DFL_TERMINATE,              // SIGVTALRM
        DFL_TERMINATE,              // SIGPROF
        DFL_IGNORE,                 // SIGWINCH
        DFL_TERMINATE,              // SIGPOLL
        DFL_TERMINATE,              // SIGPWR
        DFL_TERMINATE,              // SIGSYS
        DFL_TERMINATE,              // SIGCANCEL
        DFL_TERMINATE,              // SIGTIMER
        DFL_TERMINATE,              // SIGRTMIN
    };


    static void deliversignal(Thread *thread, uint8_t sig, struct NArch::CPU::context *ctx, enum callertype caller) {
        if (sig <= 0 || sig >= NSIG) {
            return; // Invalid signal number.
        }

        // Used when indexing into actions array.
        uint8_t signo = sig - 1;

        Process *proc = thread->process;
        struct sigaction *action = &proc->signalstate.actions[signo];

        // Handle default actions.
        if (action->handler == SIG_DFL) {
            enum dflactions dflact = dflactions[signo];
            switch (dflact) {
                case DFL_IGNORE:
                    return; // Do nothing.
                case DFL_TERMINATE:
                    proc->lock.release(); // Explicit lock release, as exit() will try to acquire it again.
                    // Terminate process, the calling thread is part of the process.
                    NSched::exit(1, sig);
                    // Unreachable.
                    __builtin_unreachable();
                case DFL_STOP:
                    // TODO: Implement stop/continue mechanism.
                    return;
            }
        } else if (action->handler == SIG_IGN) {
            return; // Explicitly ignored.
        } else {
#ifdef __x86_64__
            // Save old signal mask to restore later (per-thread).
            uint64_t oldmask = __atomic_load_n(&thread->blocked, memory_order_acquire);

            // Block additional signals during handler execution (per-thread).
            __atomic_fetch_or(&thread->blocked, action->mask, memory_order_acq_rel);
            // Always block the signal being handled (unless SA_NODEFER is set).
            if (!(action->flags & SA_NODEFER)) {
                setblocked(&thread->blocked, sig);
            }

            // Check if we have a restorer (required for proper signal return).
            if (!action->restorer) {
                NUtil::printf("[sched/signal] On %u: No restorer set, cannot deliver to user handler.\n", sig);
                return;
            }

            uint64_t usp = ctx->rsp;

            // Save old altstack flags.
            int oldaltstackflags = thread->altstackflags;

            // Check if we should use the alternate signal stack.
            bool use_altstack = false;
            if ((action->flags & SA_ONSTACK) && thread->altstackbase && thread->altstacksize > 0) {
                // Only use altstack if not already on it and it's not disabled.
                if (!(thread->altstackflags & SS_ONSTACK) && !(thread->altstackflags & SS_DISABLE)) {
                    // Switch to alternate stack (stack grows down, so start at top).
                    usp = (uint64_t)thread->altstackbase + thread->altstacksize;
                    use_altstack = true;
                    // Mark that we're now on the alternate stack.
                    thread->altstackflags |= SS_ONSTACK;
                }
            }

            // Reserve space for signal frame, align to 16 bytes.
            usp -= sizeof(struct sigframe);
            usp &= ~0xFULL; // 16-byte alignment.
            usp -= 8; // Adjust for ABI (return address).

            struct sigframe *frame = (struct sigframe *)usp;

            // Validate user stack pointer.
            if (!NMem::UserCopy::valid(frame, sizeof(struct sigframe))) {
                NUtil::printf("[sched/signal] On %u: Invalid user stack for signal frame.\n", sig);
                // Restore altstack flags on failure.
                if (use_altstack) {
                    thread->altstackflags = oldaltstackflags;
                }
                // Cannot deliver signal safely, terminate process.
                proc->lock.release();
                NSched::exit(1, SIGSEGV); // Terminate due to invalid memory access.
                return; // Unreachable.
            }

            // Build signal frame on user stack.
            struct sigframe kframe;
            kframe.restorer = (uint64_t)action->restorer;
            kframe.signo = sig;
            kframe.oldmask = oldmask;
            kframe.oldaltstackflags = oldaltstackflags;
            kframe.ctx = *ctx; // Cram current context into frame for later restoration.

            // Copy signal frame to user stack.
            int ret = NMem::UserCopy::copyto(frame, &kframe, sizeof(struct sigframe));
            if (ret < 0) {
                NUtil::printf("[sched/signal] On %u: Failed to copy signal frame to user stack.\n", sig);
                // Restore altstack flags on failure.
                if (use_altstack) {
                    thread->altstackflags = oldaltstackflags;
                }
                proc->lock.release();
                NSched::exit(1, SIGSEGV); // Terminate due to invalid memory access.
                return; // Unreachable.
            }

            // Now we need to get the gleeby deeby context set up to jump to the signal handler.

            ctx->rdi = sig; // Set the handler argument to the signal number.
            ctx->rsp = usp; // Point RSP to our signal frame.
            ctx->rip = (uint64_t)action->handler; // And prepare to jump to the handler.

            if (action->flags & SA_RESETHAND) {
                action->handler = SIG_DFL; // Reset to default if SA_RESETHAND is set.
            }
#endif
            return;
        }
    }

    static void signal_checkpending_impl(struct NArch::CPU::context *ctx, enum callertype caller) {
        if (caller == NSched::POSTSYSCALL) {
            NArch::CPU::get()->intstatus = false; // Interrupts disabled in syscall context.
        }

        Thread *currthread = NArch::CPU::get()->currthread;
        if (!currthread || !currthread->process || currthread->process->kernel) {
            if (caller == NSched::POSTSYSCALL) {
                NArch::CPU::get()->intstatus = true; // Restore interrupt status for syscall context.
            }
            return; // Don't deliver signals to kernel threads or if no thread context.
        }

        Process *proc = currthread->process;

        NLib::ScopeIRQSpinlock guard(&proc->lock);

        // Find highest priority pending unblocked signal (check thread mask).
        uint64_t deliverable = proc->signalstate.pending & ~__atomic_load_n(&currthread->blocked, memory_order_acquire);
        if (deliverable == 0) {
            if (caller == NSched::POSTSYSCALL) {
                NArch::CPU::get()->intstatus = true; // Restore interrupt status for syscall context.
            }
            return; // No signals to deliver.
        }

        // Find first set bit (lowest signal number has priority).
        int sig = __builtin_ffsll(deliverable); // Returns 1-indexed position.

        // Clear pending bit.
        clearpending(&proc->signalstate, sig);

        deliversignal(currthread, sig, ctx, caller);

        // Restore interrupt status if we're returning from syscall context.
        if (caller == NSched::POSTSYSCALL) {
            NArch::CPU::get()->intstatus = true;
        }
    }

    // Called by syscall.asm and interrupts.cpp and used to check for pending signals after syscalls/interrupts.
    // In either context, the caller passes the current CPU context and indicates the caller type, letting us pack signal frames if needed.
    extern "C" void signal_checkpending(struct NArch::CPU::context *ctx, enum callertype caller) {
        signal_checkpending_impl(ctx, caller);
    }

    extern "C" int sys_sigaction(int sig, struct sigaction *act, struct sigaction *oact) {
        SYSCALL_LOG("sys_sigaction(%d, %p, %p).\n", sig, act, oact);

        if (sig <= 0 || sig >= (int)NSIG) {
            SYSCALL_RET(-EINVAL);
        }

        // SIGKILL and SIGSTOP cannot have their handlers changed.
        if (sig == SIGKILL || sig == SIGSTOP) {
            SYSCALL_RET(-EINVAL);
        }

        // Copy new action from userspace before acquiring lock.
        struct sigaction newact;
        bool hasact = false;
        if (act) {
            int ret = NMem::UserCopy::copyfrom(&newact, act, sizeof(struct sigaction));
            if (ret < 0) {
                SYSCALL_RET(ret);
            }
            hasact = true;
        }

        Process *proc = NArch::CPU::get()->currthread->process;
        struct sigaction oldact;

        {
            NLib::ScopeIRQSpinlock guard(&proc->lock);

            // Get old action while holding lock.
            oldact = proc->signalstate.actions[sig - 1];

            // Set new action if provided.
            if (hasact) {
                proc->signalstate.actions[sig - 1] = newact;
            }
        }

        // Return old action if requested (copy to userspace outside lock).
        if (oact) {
            int ret = NMem::UserCopy::copyto(oact, &oldact, sizeof(struct sigaction));
            if (ret < 0) {
                SYSCALL_RET(ret);
            }
        }

        SYSCALL_RET(0);
    }

    extern "C" int sys_kill(size_t pid, int sig) {
        SYSCALL_LOG("sys_kill(%u, %d).\n", pid, sig);

        if (sig < 0 || sig >= (int)NSIG) {
            SYSCALL_RET(-EINVAL);
        }

        if (sig == 0) { // Check for existence of process only.
            NLib::ScopeIRQSpinlock guard(&pidtablelock);
            Process **ptarget = pidtable->find(pid);
            if (!ptarget || !*ptarget) {
                SYSCALL_RET(-ESRCH);
            }
            SYSCALL_RET(0);
        }

        if (pid > 0) {
            Process *current = NArch::CPU::get()->currthread->process;
            NLib::ScopeIRQSpinlock guard(&pidtablelock);

            Process **ptarget = pidtable->find(pid);
            if (!ptarget || !*ptarget) {
                SYSCALL_RET(-ESRCH); // No such process.
            }

            Process *target = *ptarget;

            if (target == current) {
                target->lock.acquire();
                // Set pending bit for signal.
                setpending(&target->signalstate, sig);
                target->lock.release();
                SYSCALL_RET(0);
            }

            // Kinda similar to what we do in the scheduler to avoid deadlocks between CPUs, we order process locks by PID.
            Process *first = (current->id < target->id) ? current : target;
            Process *second = (current->id < target->id) ? target : current;
            first->lock.acquire();
            second->lock.acquire();

            if (current->euid != 0 && current->euid != target->uid && current->euid != target->suid) {
                // We're only allowed to kill processes if we're root, or EUID of the processes' real or saved UID.
                second->lock.release();
                first->lock.release();
                SYSCALL_RET(-EPERM);
            }
            second->lock.release();
            first->lock.release();

            signalproc(target, sig);
        } else if (pid == 0) { // Send to process group of current process.
            Process *current = NArch::CPU::get()->currthread->process;

            current->lock.acquire();
            ProcessGroup *pg = current->pgrp;
            if (!pg) {
                current->lock.release();
                SYSCALL_RET(-ESRCH); // No process group.
            }

            int uid = current->euid;
            int gid = current->egid;
            current->lock.release();

            NLib::ScopeIRQSpinlock guard(&pg->lock);

            NLib::DoubleList<Process *>::Iterator it = pg->procs.begin();
            while (it.valid()) {
                Process *proc = *it.get();
                proc->lock.acquire();
                if (uid != 0 && (uid != proc->uid || uid != proc->suid || gid != proc->gid || gid != proc->sgid)) {
                    proc->lock.release();
                    it.next();
                    continue;
                }
                proc->lock.release();
                signalproc(proc, sig); // Send signal.

                it.next();
            }
        } else if (pid == (size_t)-1) { // Send to all processes we have permission to send to.
            // XXX: Figure out how the hell to do this efficiently.
            // This would basically be what is used when shutting down the system.
            SYSCALL_RET(-ENOSYS); // Not implemented.
        } else if (pid < (size_t)-1) { // Send to specific process group.
            Process **ptarget = pidtable->find(-pid); // PID is negative, so invert to get PGID.
            if (!ptarget || !*ptarget) {
                SYSCALL_RET(-ESRCH); // No such process group.
            }

            ProcessGroup *pg = (*ptarget)->pgrp; // Leader process gives us the process group.
            if (!pg) {
                SYSCALL_RET(-ESRCH); // No such process group.
            }

            Process *current = NArch::CPU::get()->currthread->process;
            current->lock.acquire();
            int uid = current->euid;
            int gid = current->egid;
            current->lock.release();

            NLib::ScopeIRQSpinlock guard(&pg->lock);

            NLib::DoubleList<Process *>::Iterator it = pg->procs.begin();
            while (it.valid()) {
                Process *proc = *it.get();
                proc->lock.acquire();
                if (uid != 0 && (uid != proc->uid || uid != proc->suid || gid != proc->gid || gid != proc->sgid)) {
                    proc->lock.release();
                    it.next();
                    continue;
                }
                proc->lock.release();
                signalproc(proc, sig); // Send signal.
                it.next();
            }
        } else {
            SYSCALL_RET(-EINVAL);
        }

        SYSCALL_RET(0);
    }


    extern "C" int sys_sigreturn(void) {
        SYSCALL_LOG("sys_sigreturn().\n");

#ifdef __x86_64__
        Thread *thread = NArch::CPU::get()->currthread;
        Process *proc = thread->process;

        // Our frame is stored at the stack pointer right before syscall entrance.
        struct NArch::CPU::context *sysctx = thread->sysctx;
        uint64_t frameaddr = sysctx->rsp;

        if (!NMem::UserCopy::valid((void *)frameaddr, sizeof(struct sigframe))) {
            SYSCALL_RET(-EFAULT);
        }

        // Copy signal frame from user stack.
        struct sigframe frame;
        int ret = NMem::UserCopy::copyfrom(&frame, (void *)frameaddr, sizeof(struct sigframe));
        if (ret < 0) {
            SYSCALL_RET(ret);
        }

        // Restore signal mask (per-thread).
        NLib::ScopeIRQSpinlock guard(&proc->lock);
        __atomic_store_n(&thread->blocked, frame.oldmask, memory_order_release);
        __atomic_fetch_and(&thread->blocked, ~((1ULL << (SIGKILL - 1)) | (1ULL << (SIGSTOP - 1))), memory_order_acq_rel); // Ensure SIGKILL and SIGSTOP are unblocked.

        // Restore altstack flags.
        thread->altstackflags = frame.oldaltstackflags;

        struct NArch::CPU::context *ctx = &frame.ctx;

        // Validate that we're returning to user mode (CS should be user code segment).
        if ((ctx->cs & 0x3) != 0x3) {
            SYSCALL_RET(-EFAULT);
        }

        // Overwrite sysctx with saved context, so returning from this system call will restore old context.

        sysctx->rax = ctx->rax;
        sysctx->rbx = ctx->rbx;
        sysctx->rcx = ctx->rcx;
        sysctx->rdx = ctx->rdx;
        sysctx->rsi = ctx->rsi;
        sysctx->rdi = ctx->rdi;
        sysctx->rbp = ctx->rbp;
        sysctx->r8 = ctx->r8;
        sysctx->r9 = ctx->r9;
        sysctx->r10 = ctx->r10;
        sysctx->r11 = ctx->r11;
        sysctx->r12 = ctx->r12;
        sysctx->r13 = ctx->r13;
        sysctx->r14 = ctx->r14;
        sysctx->r15 = ctx->r15;
        sysctx->rip = ctx->rip;
        sysctx->rsp = ctx->rsp;
        sysctx->rflags = ctx->rflags;

        // XXX: Investigate potentially incorrect syscall return values.
        NUtil::printf("[sched/signal] sigreturn to RIP %p, RSP %p, RAX %p.\n", ctx->rip, ctx->rsp, ctx->rax);
        return ctx->rax; // Return original RAX so interrupted system calls return their original value.
#else
        SYSCALL_RET(-ENOSYS);
#endif
    }

    extern "C" int sys_sigprocmask(int how, NLib::sigset_t *set, NLib::sigset_t *oldset) {
        SYSCALL_LOG("sys_sigprocmask(%d, %p, %p).\n", how, set, oldset);

        Thread *thread = NArch::CPU::get()->currthread;
        Process *proc = thread->process;

        // Copy newset from userspace before acquiring lock.
        uint64_t newset = 0;
        if (set) {
            int ret = NMem::UserCopy::copyfrom(&newset, set, sizeof(uint64_t));
            if (ret < 0) {
                SYSCALL_RET(ret);
            }
            // Remove SIGKILL and SIGSTOP from the set, if they're there (we can't block them).
            newset &= ~((1ULL << (SIGKILL - 1)) | (1ULL << (SIGSTOP - 1)));
        }

        // Get old mask atomically (no lock needed for atomic load).
        uint64_t oldmask = __atomic_load_n(&thread->blocked, memory_order_acquire);

        // Modify signal mask if requested (per-thread). Atomic operations don't need lock.
        if (set) {
            switch (how) {
                case SIG_BLOCK:
                    __atomic_fetch_or(&thread->blocked, newset, memory_order_acq_rel);
                    break;
                case SIG_UNBLOCK:
                    __atomic_fetch_and(&thread->blocked, ~newset, memory_order_acq_rel);
                    break;
                case SIG_SETMASK:
                    __atomic_store_n(&thread->blocked, newset, memory_order_release);
                    break;
                default:
                    SYSCALL_RET(-EINVAL);
            }
        }

        // Return old signal mask if requested (per-thread). User copy done outside lock.
        if (oldset) {
            int ret = NMem::UserCopy::copyto(oldset, &oldmask, sizeof(uint64_t));
            if (ret < 0) {
                SYSCALL_RET(ret);
            }
        }

        SYSCALL_RET(0);
    }

    extern "C" int sys_sigpending(NLib::sigset_t *set) {
        SYSCALL_LOG("sys_sigpending(%p).\n", set);

        Thread *thread = NArch::CPU::get()->currthread;
        if (!thread) {
            SYSCALL_RET(-EINVAL);
        }

        Process *proc = thread->process;

        NLib::ScopeIRQSpinlock guard(&proc->lock);

        // Get pending signals that are blocked in this thread.
        NLib::sigset_t pending = proc->signalstate.pending & __atomic_load_n(&thread->blocked, memory_order_acquire);

        // Copy to userspace.
        int ret = NMem::UserCopy::copyto(set, &pending, sizeof(NLib::sigset_t));
        if (ret < 0) {
            SYSCALL_RET(ret);
        }

        SYSCALL_RET(0);
    }

    extern "C" int sys_sigaltstack(struct stack_t *ss, struct stack_t *old_ss) {
        SYSCALL_LOG("sys_sigaltstack(%p, %p).\n", ss, old_ss);

        Thread *thread = NArch::CPU::get()->currthread;
        if (!thread) {
            SYSCALL_RET(-EINVAL);
        }

        // Check if we're currently on the alternate stack.
        bool on_altstack = (thread->altstackflags & SS_ONSTACK) != 0;

        // Return old alternate stack info if requested.
        if (old_ss) {
            struct stack_t old_stack;
            old_stack.ss_sp = thread->altstackbase;
            old_stack.ss_size = thread->altstacksize;
            old_stack.ss_flags = thread->altstackflags;

            int ret = NMem::UserCopy::copyto(old_ss, &old_stack, sizeof(struct stack_t));
            if (ret < 0) {
                SYSCALL_RET(ret);
            }
        }

        // Set new alternate stack if provided.
        if (ss) {
            // Cannot change alternate stack while executing on it.
            if (on_altstack) {
                SYSCALL_RET(-EPERM);
            }

            struct stack_t newstack;
            int ret = NMem::UserCopy::copyfrom(&newstack, ss, sizeof(struct stack_t));
            if (ret < 0) {
                SYSCALL_RET(ret);
            }

            // Check for SS_DISABLE flag.
            if (newstack.ss_flags & SS_DISABLE) {
                // Disable the alternate stack.
                thread->altstackbase = NULL;
                thread->altstacksize = 0;
                thread->altstackflags = SS_DISABLE;
            } else {
                // Validate the new stack.
                if (!newstack.ss_sp) {
                    SYSCALL_RET(-EINVAL);
                }

                if (newstack.ss_size < MINSIGSTKSZ) {
                    SYSCALL_RET(-ENOMEM);
                }

                // Validate that the stack memory is accessible.
                if (!NMem::UserCopy::valid(newstack.ss_sp, newstack.ss_size)) {
                    SYSCALL_RET(-EFAULT);
                }

                // Set the new alternate stack.
                thread->altstackbase = newstack.ss_sp;
                thread->altstacksize = newstack.ss_size;
                thread->altstackflags = newstack.ss_flags & ~(SS_ONSTACK | SS_DISABLE);
            }
        }

        SYSCALL_RET(0);
    }

    // Helper to convert microseconds to timeval.
    static void usectimeval(uint64_t usec, struct timeval *tv) {
        tv->tv_sec = usec / 1000000;
        tv->tv_usec = usec % 1000000;
    }

    // Helper to convert timeval to microseconds.
    static uint64_t timevalusec(const struct timeval *tv) {
        return (uint64_t)tv->tv_sec * 1000000 + (uint64_t)tv->tv_usec;
    }

    extern "C" int sys_getitimer(int which, struct itimerval *curr_value) {
        SYSCALL_LOG("sys_getitimer(%d, %p).\n", which, curr_value);

        if (!curr_value) {
            SYSCALL_RET(-EFAULT);
        }

        // Only ITIMER_REAL is implemented for now.
        if (which != ITIMER_REAL) {
            SYSCALL_RET(-EINVAL);
        }

        Thread *thread = NArch::CPU::get()->currthread;
        if (!thread || !thread->process) {
            SYSCALL_RET(-EINVAL);
        }

        Process *proc = thread->process;
        NLib::ScopeIRQSpinlock guard(&proc->lock);

        struct itimerval kval;

        // Calculate remaining time.
        if (proc->itimerdeadline > 0) {
#ifdef __x86_64__
            uint64_t now = NArch::TSC::query();
            if (proc->itimerdeadline > now) {
                // Convert TSC ticks to microseconds.
                uint64_t remaining_ticks = proc->itimerdeadline - now;
                uint64_t remaining_usec = (remaining_ticks * 1000000) / NArch::TSC::hz;
                usectimeval(remaining_usec, &kval.it_value);
            } else {
                // Timer already expired but not yet delivered.
                kval.it_value.tv_sec = 0;
                kval.it_value.tv_usec = 0;
            }
#else
            kval.it_value.tv_sec = 0;
            kval.it_value.tv_usec = 0;
#endif
        } else {
            kval.it_value.tv_sec = 0;
            kval.it_value.tv_usec = 0;
        }

        // Return the interval.
        usectimeval(proc->itimerintv, &kval.it_interval);

        int ret = NMem::UserCopy::copyto(curr_value, &kval, sizeof(struct itimerval));
        if (ret < 0) {
            SYSCALL_RET(ret);
        }

        SYSCALL_RET(0);
    }

    extern "C" int sys_setitimer(int which, const struct itimerval *new_value, struct itimerval *old_value) {
        SYSCALL_LOG("sys_setitimer(%d, %p, %p).\n", which, new_value, old_value);

        // Only ITIMER_REAL is implemented for now.
        if (which != ITIMER_REAL) {
            SYSCALL_RET(-EINVAL);
        }

        Thread *thread = NArch::CPU::get()->currthread;
        if (!thread || !thread->process) {
            SYSCALL_RET(-EINVAL);
        }

        Process *proc = thread->process;
        NLib::ScopeIRQSpinlock guard(&proc->lock);

        // Return old value if requested.
        if (old_value) {
            struct itimerval kold;

            // Calculate remaining time.
            if (proc->itimerdeadline > 0) {
#ifdef __x86_64__
                uint64_t now = NArch::TSC::query();
                if (proc->itimerdeadline > now) {
                    uint64_t remaining_ticks = proc->itimerdeadline - now;
                    uint64_t remaining_usec = (remaining_ticks * 1000000) / NArch::TSC::hz;
                    usectimeval(remaining_usec, &kold.it_value);
                } else {
                    kold.it_value.tv_sec = 0;
                    kold.it_value.tv_usec = 0;
                }
#else
                kold.it_value.tv_sec = 0;
                kold.it_value.tv_usec = 0;
#endif
            } else {
                kold.it_value.tv_sec = 0;
                kold.it_value.tv_usec = 0;
            }

            usectimeval(proc->itimerintv, &kold.it_interval);

            int ret = NMem::UserCopy::copyto(old_value, &kold, sizeof(struct itimerval));
            if (ret < 0) {
                SYSCALL_RET(ret);
            }
        }

        // Set new value if provided.
        if (new_value) {
            struct itimerval knew;
            int ret = NMem::UserCopy::copyfrom(&knew, new_value, sizeof(struct itimerval));
            if (ret < 0) {
                SYSCALL_RET(ret);
            }

            // Validate timeval values.
            if (knew.it_value.tv_usec < 0 || knew.it_value.tv_usec >= 1000000 ||
                knew.it_interval.tv_usec < 0 || knew.it_interval.tv_usec >= 1000000) {
                SYSCALL_RET(-EINVAL);
            }

            uint64_t value_usec = timevalusec(&knew.it_value);
            uint64_t interval_usec = timevalusec(&knew.it_interval);

            proc->itimerintv = interval_usec;

            if (value_usec > 0) {
#ifdef __x86_64__
                // Convert microseconds to TSC ticks and set deadline.
                uint64_t ticks = (value_usec * NArch::TSC::hz) / 1000000;
                proc->itimerdeadline = NArch::TSC::query() + ticks;
#else
                proc->itimerdeadline = 0;
#endif
            } else {
                // Disarm the timer.
                proc->itimerdeadline = 0;
            }

            proc->itimerreal = value_usec;
        }

        SYSCALL_RET(0);
    }

    int signalproc(Process *proc, uint8_t sig) {
        if (!proc || sig <= 0 || sig >= NSIG) {
            return -EINVAL;
        }

        NLib::ScopeIRQSpinlock guard(&proc->lock);
        // Set pending bit for signal.
        setpending(&proc->signalstate, sig);

        // Find a thread to deliver the signal to.
        Thread *paused_candidate = NULL;

        NLib::DoubleList<Thread *>::Iterator it = proc->threads.begin();
        for (; it.valid(); it.next()) {
            Thread *thread = *it.get();
            if (!thread) continue;

            // Check if this thread has the signal blocked (safe under process lock).
            if (isblocked(&thread->blocked, sig)) {
                continue; // This thread has the signal blocked, try next thread.
            }

            enum Thread::state state = (enum Thread::state)__atomic_load_n(&thread->tstate, memory_order_acquire);

            // Prefer threads that are already running or ready.
            if (state == Thread::RUNNING || state == Thread::READY || state == Thread::SUSPENDED) {
                // Signal will be delivered when this thread next checks for pending signals.
                return 0;
            }

            // Remember first paused thread as candidate.
            if (state == Thread::PAUSED && !paused_candidate) {
                paused_candidate = thread;
            }

            if (state == Thread::WAITINGINT && thread->waitingon) { // Only interruptible waits can be woken.
                WaitQueue *wq = thread->waitingon;
                if (wq->dequeue(thread)) {
                    NSched::schedulethread(thread);
                }
                return 0;
            }
        }

        // If we found a paused thread, wake it up.
        if (paused_candidate) {
            NSched::schedulethread(paused_candidate);
        }

        return 0;
    }

    int signalpgrp(ProcessGroup *pgrp, uint8_t sig) {
        if (!pgrp || sig <= 0 || sig >= NSIG) {
            return -EINVAL;
        }

        NUtil::printf("[sched/signal] Sending signal %u to process group %u.\n", sig, pgrp->id);
        NLib::ScopeIRQSpinlock guard(&pgrp->lock);

        // Signal all processes in the group.
        NLib::DoubleList<Process *>::Iterator it = pgrp->procs.begin();
        for (; it.valid(); it.next()) {
            Process *proc = *it.get();
            if (proc) {
                NUtil::printf("[sched/signal] Signaling process %u in group %u with signal %u.\n", proc->id, pgrp->id, sig);
                signalproc(proc, sig);
            }
        }

        return 0;
    }

    int signalthread(Thread *thread, uint8_t sig) {
        if (!thread || !thread->process || sig <= 0 || sig >= NSIG) {
            return -EINVAL;
        }

        Process *proc = thread->process;
        NLib::ScopeIRQSpinlock guard(&proc->lock);

        // Set pending bit for signal at process level.
        setpending(&proc->signalstate, sig);

        // Check if the target thread has this signal blocked.
        if (isblocked(&thread->blocked, sig)) {
            // Signal is blocked in this thread, it will remain pending.
            return 0;
        }

        // Check thread state and wake if necessary.
        enum Thread::state state = (enum Thread::state)__atomic_load_n(&thread->tstate, memory_order_acquire);

        if (state == Thread::RUNNING || state == Thread::READY || state == Thread::SUSPENDED) {
            // Thread is already active, signal will be delivered when it checks.
            return 0;
        }

        if (state == Thread::PAUSED) {
            // Wake the paused thread so it can handle the signal.
            // Paused threads are not in waitqueues, so this is safe.
            NSched::schedulethread(thread);
            return 0;
        }

        if (state == Thread::WAITINGINT && thread->waitingon) { // Only interruptible waits can be woken.
            WaitQueue *wq = thread->waitingon;
            if (wq->dequeue(thread)) { // Threads sitting in waitqueues MUST be dequeued by us.
                NSched::schedulethread(thread);
            }
            return 0;
        }

        return 0;
    }

}
