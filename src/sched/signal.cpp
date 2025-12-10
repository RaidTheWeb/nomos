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
        DFL_IGNORE,                 // RSVD
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

        Process *proc = thread->process;
        struct sigaction *action = &proc->signalstate.actions[sig];

        // Handle default actions.
        if (action->handler == SIG_DFL) {
            enum dflactions dflact = dflactions[sig];
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
#ifdef __x86_64__
            // Save old signal mask to restore later.
            uint64_t oldmask = proc->signalstate.blocked;

            // Block additional signals during handler execution.
            proc->signalstate.blocked |= action->mask;
            // Always block the signal being handled (unless SA_NODEFER is set).
            if (!(action->flags & SA_NODEFER)) {
                setblocked(&proc->signalstate, sig);
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
            return; // Don't deliver signals to kernel threads or if no thread context.
        }

        Process *proc = currthread->process;
        NLib::ScopeIRQSpinlock guard(&proc->lock);

        // Find highest priority pending unblocked signal.
        uint64_t deliverable = proc->signalstate.pending & ~proc->signalstate.blocked;
        if (deliverable == 0) {
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
            int ret = NMem::UserCopy::copyto(oact, &proc->signalstate.actions[sig], sizeof(struct sigaction));
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
            proc->signalstate.actions[sig] = newact;
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

        // Restore signal mask.
        NLib::ScopeIRQSpinlock guard(&proc->lock);
        proc->signalstate.blocked = frame.oldmask;
        proc->signalstate.blocked &= ~((1ULL << (SIGKILL - 1)) | (1ULL << (SIGSTOP - 1)));

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

        Process *proc = NArch::CPU::get()->currthread->process;
        NLib::ScopeIRQSpinlock guard(&proc->lock);

        // Return old signal mask if requested.
        if (oldset) {
            int ret = NMem::UserCopy::copyto(oldset, &proc->signalstate.blocked, sizeof(uint64_t));
            if (ret < 0) {
                SYSCALL_RET(ret);
            }
        }

        // Modify signal mask if requested.
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
                    proc->signalstate.blocked |= newset;
                    break;
                case SIG_UNBLOCK:
                    proc->signalstate.blocked &= ~newset;
                    break;
                case SIG_SETMASK:
                    proc->signalstate.blocked = newset;
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

        if (isblocked(&proc->signalstate, sig)) {
            return 0; // Signal is blocked, don't wake up any threads.
        }

        // Wake up one of the process' threads to handle the signal.
        NLib::DoubleList<Thread *>::Iterator it = proc->threads.begin();
        for (; it.valid(); it.next()) {
            Thread *thread = *it.get();
            // Wake the first waiting thread we find.
            // XXX: Is there a better way of doing this?
            if (thread && __atomic_load_n(&thread->tstate, memory_order_acquire) == Thread::PAUSED) {
                NSched::schedulethread(thread);
                break;
            }
        }

        return 0;
    }

    int signalpgrp(ProcessGroup *pgrp, uint8_t sig) {
        if (!pgrp || sig <= 0 || sig >= NSIG) {
            return -EINVAL;
        }

        NLib::ScopeIRQSpinlock guard(&pgrp->lock);

        // Signal all processes in the group.
        NLib::DoubleList<Process *>::Iterator it = pgrp->procs.begin();
        for (; it.valid(); it.next()) {
            Process *proc = *it.get();
            if (proc) {
                signalproc(proc, sig);
            }
        }

        return 0;
    }

    int signalthread(Thread *thread, uint8_t sig) {
        if (!thread || !thread->process || sig <= 0 || sig >= NSIG) {
            return -EINVAL;
        }

        // XXX: Figure out how the hell to do per-thread signals properly.

        return signalproc(thread->process, sig);
    }

}
