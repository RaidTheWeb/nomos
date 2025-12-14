#ifdef __x86_64__
#include <arch/x86_64/cpu.hpp>
#include <arch/x86_64/e9.hpp>
#include <arch/x86_64/context.hpp>
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
                case DFL_STOP:
                    // TODO: Implement stop/continue mechanism.
                    return;
            }
        } else if (action->handler == SIG_IGN) {
            return; // Explicitly ignored.
        } else {
            NUtil::printf("Run handler %p.\n", action->handler);
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

            // Reserve space for signal frame, align to 16 bytes.
            usp -= sizeof(struct sigframe);
            usp &= ~0xFULL; // 16-byte alignment.
            usp -= 8; // Adjust for ABI (return address).

            struct sigframe *frame = (struct sigframe *)usp;

            // Validate user stack pointer.
            if (!NMem::UserCopy::valid(frame, sizeof(struct sigframe))) {
                NUtil::printf("[sched/signal] On %u: Invalid user stack for signal frame.\n", sig);
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
            kframe.ctx = *ctx; // Cram current context into frame for later restoration.

            // Copy signal frame to user stack.
            int ret = NMem::UserCopy::copyto(frame, &kframe, sizeof(struct sigframe));
            if (ret < 0) {
                NUtil::printf("[sched/signal] On %u: Failed to copy signal frame to user stack.\n", sig);
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

            if (caller == POSTSYSCALL) {
                NArch::CPU::get()->intstatus = true; // Syscall return context has interrupts enabled.
            }
#endif
            return;
        }
    }

    extern "C" __attribute__((no_caller_saved_registers)) void signal_checkpending(struct NArch::CPU::context *ctx, enum callertype caller) {
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

        Process *proc = NArch::CPU::get()->currthread->process;
        NLib::ScopeIRQSpinlock guard(&proc->lock);

        // Return old action if requested.
        if (oact) {
            int ret = NMem::UserCopy::copyto(oact, &proc->signalstate.actions[sig - 1], sizeof(struct sigaction));
            if (ret < 0) {
                SYSCALL_RET(ret);
            }
        }

        // Set new action if provided.
        if (act) {
            struct sigaction newact;
            int ret = NMem::UserCopy::copyfrom(&newact, act, sizeof(struct sigaction));
            if (ret < 0) {
                SYSCALL_RET(ret);
            }
            proc->signalstate.actions[sig - 1] = newact;
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

        Process *current = NArch::CPU::get()->currthread->process;
        NLib::ScopeIRQSpinlock guard(&pidtablelock);

        Process **ptarget = pidtable->find(pid);
        if (!ptarget || !*ptarget) {
            SYSCALL_RET(-ESRCH); // No such process.
        }

        // XXX: Implement PID == 0 (process group) and PID == -1 (annihilation).

        Process *target = *ptarget;

        if (target == current) {
            target->lock.acquire();
            // Set pending bit for signal.
            setpending(&target->signalstate, sig);
            target->lock.release();
            SYSCALL_RET(0);
        }

        target->lock.acquire();
        current->lock.acquire();
        if (current->euid != 0 && current->euid != target->uid && current->euid != target->suid) {
            // We're only allowed to kill processes if we're root, or EUID of the processes' real or saved UID.
            current->lock.release();
            target->lock.release();
            SYSCALL_RET(-EPERM);
        }
        current->lock.release();

        // Set pending bit for signal.
        setpending(&target->signalstate, sig);
        target->lock.release();

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
        NLib::ScopeIRQSpinlock guard(&proc->lock);

        // Return old signal mask if requested (per-thread).
        if (oldset) {
            int ret = NMem::UserCopy::copyto(oldset, &thread->blocked, sizeof(uint64_t));
            if (ret < 0) {
                SYSCALL_RET(ret);
            }
        }

        // Modify signal mask if requested (per-thread).
        if (set) {
            uint64_t newset;
            int ret = NMem::UserCopy::copyfrom(&newset, set, sizeof(uint64_t));
            if (ret < 0) {
                SYSCALL_RET(ret);
            }

            // Remove SIGKILL and SIGSTOP from the set, if they're there (we can't block them).
            newset &= ~((1ULL << (SIGKILL - 1)) | (1ULL << (SIGSTOP - 1)));

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
                wq->dequeue(thread);
                NSched::schedulethread(thread);
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

        if (state == Thread::WAITING && thread->waitingon) {
            // Dequeue from waitqueue and wake the thread.
            WaitQueue *wq = thread->waitingon;
            wq->dequeue(thread);
            NSched::schedulethread(thread);
            return 0;
        }

        return 0;
    }

}
