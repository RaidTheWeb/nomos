#ifdef __x86_64__
#include <arch/x86_64/cpu.hpp>
#endif

#include <sched/sched.hpp>
#include <sched/signal.hpp>

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

    void deliversignal(Thread *thread, uint8_t sig) {
        if (thread->signal.actions[sig].handler == SIG_IGN) {
            goto cleanup;
        }

        if (thread->signal.actions[sig].handler == SIG_DFL) {
            enum dflactions action = actions[sig];
            switch (action) {
                case DFL_TERMINATE:
                    NUtil::printf("SIGINT.\n");
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

        // XXX: Handling user defined signal handler entry.
        // - Mark thread as signal handling -> Save current current.
        // - Force reschedule -> Thread will enter signal context.

cleanup:
        thread->signal.pending &= ~(1ull << sig);
    }

    extern "C" __attribute__((no_caller_saved_registers)) void signal_checkpending(void) {
        NArch::CPU::get()->intstatus = false;

        NSched::Thread *thread = NArch::CPU::get()->currthread;

        for (size_t i = 1; i < SIGMAX; i++) {
            if (thread->signal.pending & (1ull << i) && !(thread->signal.blocked & (1ull << i))) {
                deliversignal(thread, i);
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

        // __atomic_store_n(&thread->tstate, Thread::state::SUSPENDED, memory_order_release);

        // XXX: What now? Do we force the CPU running the thread to halt? Do we *need* the signal to execute *immediately*?
        // We can send an IPI to the CPU to tell it to reschedule.
        // NSched::reschedule(thread);
        return 0;
    }

    int signalproc(Process *proc, uint8_t sig) {
        assert(proc, "Passing signal to NULL process.\n");
        if (sig < 1 || sig >= SIGMAX) {
            return -EINVAL;
        }

        NLib::ScopeSpinlock guard(&proc->lock);

        NLib::DoubleList<Thread *>::Iterator it = proc->threads.begin();

        ssize_t ret = 0;

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

        NLib::ScopeSpinlock guard(&pgrp->lock);
        NLib::DoubleList<Process *>::Iterator it = pgrp->procs.begin();

        ssize_t ret = 0;

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

}
