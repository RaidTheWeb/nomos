#ifdef __x86_64__
#include <arch/x86_64/cpu.hpp>
#include <arch/x86_64/e9.hpp>
#include <arch/x86_64/context.hpp>
#endif

#include <lib/errno.hpp>
#include <sched/sched.hpp>
#include <sched/signal.hpp>
#include <sys/syscall.hpp>

namespace NSched {

    static const enum dflactions actions[] = {
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

    void deliversignal(Thread *thread, uint8_t sig, struct NArch::CPU::context *ctx) {
        if (thread->signal.actions[sig].handler == SIG_IGN) {
            goto cleanup;
        }

        if (thread->signal.actions[sig].handler == SIG_DFL) {
            enum dflactions action = actions[sig];
            switch (action) {
                case DFL_TERMINATE:
                    NUtil::printf("Terminated via signal.\n");
                    exit();
                    break;
                case DFL_STOP:
                    thread->signal.pending &= ~(1ull << sig);
                    __atomic_store_n(&thread->tstate, Thread::state::SUSPENDED, memory_order_release);
                    yield();
                    return;
                default:
                    goto cleanup;
            }
            goto cleanup;
        }

cleanup:
        thread->signal.pending &= ~(1ull << sig);
    }

    extern "C" __attribute__((no_caller_saved_registers)) void signal_checkpending(struct NArch::CPU::context *ctx) {
        NArch::CPU::get()->intstatus = false;

        NSched::Thread *thread = NArch::CPU::get()->currthread;

        for (size_t i = 1; i < SIGMAX; i++) {
            if (thread->signal.pending & (1ull << i) && !(thread->signal.blocked & (1ull << i))) {
                deliversignal(thread, i, ctx);
            }
        }

        NArch::CPU::get()->intstatus = true;
    }

    int signalthread(Thread *thread, uint8_t sig) {
        assert(thread, "Passing signal to NULL thread.\n");
        if (sig < 1 || sig >= SIGMAX) {
            return -EINVAL;
        }

        if (!__atomic_and_fetch(&thread->signal.blocked, 1ull << sig, memory_order_seq_cst)) {
            // Pend the signal. Thread will run signal handler!
            __atomic_or_fetch(&thread->signal.pending, 1ull << sig, memory_order_seq_cst);
        }

        // XXX: If the thread is eepy, we need to wake it so it can handle the signal.
        // Ensure that waiting threads get woken up and removed from wait queues.
        return 0;
    }

    int signalproc(Process *proc, uint8_t sig) {
        assert(proc, "Passing signal to NULL process.\n");
        if (sig < 1 || sig >= SIGMAX) {
            return -EINVAL;
        }

        NLib::ScopeIRQSpinlock guard(&proc->lock);

        NLib::DoubleList<Thread *>::Iterator it = proc->threads.begin();

        long ret = 0;

        while (it.valid()) {
            ret = signalthread(*it.get(), sig);
            if (ret < 0) {
                goto cleanup;
            }
            it.next();
        }
cleanup:
        return ret;
    }

    int signalpgrp(ProcessGroup *pgrp, uint8_t sig) {
        assert(pgrp, "Passing signal to NULL process group.\n");
        if (sig < 1 || sig >= SIGMAX) {
            return -EINVAL;
        }

        NLib::ScopeIRQSpinlock guard(&pgrp->lock);
        NLib::DoubleList<Process *>::Iterator it = pgrp->procs.begin();

        long ret = 0;

        while (it.valid()) {
            ret = signalproc(*it.get(), sig);
            if (ret < 0) {
                goto cleanup;
            }
            it.next();
        }
cleanup:
        return ret;
    }

    extern "C" int sys_sigaction(int sig, const struct sigaction *act, struct sigaction *oact) {
        SYSCALL_LOG("sys_sigaction(%d, %p, %p).\n", sig, act, oact);
        if (sig < 1 || sig >= (int)NSIG) {
            return -EINVAL;
        }
        if (sig == SIGKILL || sig == SIGSTOP) {
            return -EINVAL;
        }
        Thread *t = NArch::CPU::get()->currthread;
        if (oact) {
            *oact = t->signal.actions[sig];
        }
        if (act) {
            t->signal.actions[sig] = *act;
        }
        return 0;
    }

    extern "C" int sys_kill(size_t pid, int sig) {
        SYSCALL_LOG("sys_kill(%u, %d).\n", pid, sig);
        if (!pidtable) {
            return -ENOSYS;
        }
        pidtablelock.acquire();
        Process **pproc = pidtable->find(pid);
        if (!pproc) {
            pidtablelock.release();
            return -ESRCH;
        }
        pidtablelock.release();
        return signalproc(*pproc, sig);
    }

    extern "C" int sys_sigreturn(void) {
        SYSCALL_LOG("sys_sigreturn().\n");
        Thread *t = NArch::CPU::get()->currthread;
        uintptr_t usp = t->sysctx.rsp;
        struct NArch::CPU::context *uctx = (struct NArch::CPU::context *)usp;
        struct NArch::CPU::context ctx = *uctx;
        NArch::CPU::ctx_swap(&ctx);
        return 0;
    }

    extern "C" int sys_sigprocmask(int how, const uint64_t *set, uint64_t *oldset) {
        SYSCALL_LOG("sys_sigprocmask(%d, %p, %p).\n", how, set, oldset);
        if (how != SIG_BLOCK && how != SIG_UNBLOCK && how != SIG_SETMASK) {
            return -EINVAL;
        }

        Thread *t = NArch::CPU::get()->currthread;
        if (oldset) {
            *oldset = t->signal.blocked;
        }
        if (set) {
            uint64_t mask = *set;
            mask &= ~(1ull << SIGKILL);
            mask &= ~(1ull << SIGSTOP);

            switch (how) {
                case SIG_BLOCK:
                    __atomic_or_fetch(&t->signal.blocked, mask, memory_order_seq_cst);
                    break;
                case SIG_UNBLOCK:
                    __atomic_and_fetch(&t->signal.blocked, ~mask, memory_order_seq_cst);
                    break;
                case SIG_SETMASK:
                    __atomic_store_n(&t->signal.blocked, mask, memory_order_seq_cst);
                    break;
                    return -EINVAL;
            }
        }
        return 0;
    }

}
