#ifndef _SCHED__SIGNAL_HPP
#define _SCHED__SIGNAL_HPP

#include <lib/signal.hpp>
#include <stddef.h>
#include <stdint.h>
#include <sys/clock.hpp>

namespace NArch {
    namespace CPU {
        struct context;
    }
}

namespace NSched {
    // Default handler actions -> Handled by the kernel, rather than being passed into userspace.
    enum dflactions {
        DFL_IGNORE,         // Performs no actions.
        DFL_TERMINATE,      // Kills program.
        DFL_STOP            // Sleep thread until woken with SIGCONT.
    };

    #define SIG_ERR ((void (*)(int))-1)
    #define SIG_DFL ((void (*)(int))0)
    #define SIG_IGN ((void (*)(int))1)

    // sigaction flags
    #define SA_NODEFER 0x40000000  // Don't automatically block signal during handler.
    #define SA_RESETHAND 0x80000000 // Reset handler to SIG_DFL after invocation.
    #define SA_ONSTACK 0x08000000  // Use alternate signal stack for handler.

    struct sigaction {
        void (*handler)(int) = SIG_DFL;
        uint64_t flags = 0;
        void (*restorer)(void) = NULL;
        NLib::sigset_t mask = 0; // Signals to block during execution of action.
    };

    #define SS_ONSTACK 1     // Currently executing on alternate stack.
    #define SS_DISABLE 2     // Alternate stack is disabled.

    #define MINSIGSTKSZ 2048  // Minimum stack size.
    #define SIGSTKSZ 8192     // Default stack size.

    struct stack_t {
        void *ss_sp;         // Base of stack.
        int ss_flags;        // Flags.
        size_t ss_size;      // Size of stack.
    };

    // Interval timer types.
    #define ITIMER_REAL    0  // Decrements in real time, delivers SIGALRM.
    #define ITIMER_VIRTUAL 1  // Decrements in process virtual time (user CPU time), delivers SIGVTALRM.
    #define ITIMER_PROF    2  // Decrements in process virtual time (user + system CPU time), delivers SIGPROF.

    struct timeval {
        long tv_sec;   // Seconds.
        long tv_usec;  // Microseconds.
    };

    struct itimerval {
        struct timeval it_interval;  // Timer interval (period for repeating timers).
        struct timeval it_value;     // Current timer value (time until next expiration).
    };

    static const size_t NSIG = 64; // Total number of signals.

    struct signal { // Per-process signal state.
        NLib::sigset_t pending = 0; // Pending signals.
        struct sigaction actions[NSIG];
    };

    static inline void clearpending(struct signal *sigstate, uint8_t sig) {
        // Clear pending bit, sig is 1-indexed.
        sigstate->pending &= ~(1ULL << (sig - 1));
    }

    static inline bool ispending(struct signal *sigstate, uint8_t sig) {
        // Check pending bit, sig is 1-indexed.
        return (sigstate->pending & (1ULL << (sig - 1))) != 0;
    }

    static inline void setpending(struct signal *sigstate, uint8_t sig) {
        // Set pending bit, sig is 1-indexed.
        sigstate->pending |= (1ULL << (sig - 1));
    }

    static inline void setblocked(NLib::sigset_t *sigstate, uint8_t sig) {
        // Set blocked bit, sig is 1-indexed.
        __atomic_fetch_or(sigstate, (1ULL << (sig - 1)), memory_order_acq_rel); // Acquire-release semantics here, because we acquire on fetch, and release on OR.
    }

    static inline bool isblocked(NLib::sigset_t *sigstate, uint8_t sig) {
        // Check blocked bit, sig is 1-indexed.
        return __atomic_load_n(sigstate, memory_order_acquire) & (1ULL << (sig - 1));
    }

    static inline void clearblocked(NLib::sigset_t *sigstate, uint8_t sig) {
        // Clear blocked bit, sig is 1-indexed.
        __atomic_fetch_and(sigstate, ~(1ULL << (sig - 1)), memory_order_acq_rel); // Ditto.
    }

    static inline void (*gethandler(struct signal *sigstate, uint8_t sig))(int) {
        return sigstate->actions[sig - 1].handler;
    }

    class Thread;
    class ProcessGroup;
    class Process;

    enum callertype {
        POSTINT         = 0, // Called after an interrupt.
        POSTSYSCALL     = 1 // Called after a syscall.
    };

    extern "C" void signal_checkpending(struct NArch::CPU::context *ctx, enum callertype caller);

    int signalproc(Process *proc, uint8_t sig);
    int signalpgrp(ProcessGroup *pgrp, uint8_t sig);
    int signalthread(Thread *thread, uint8_t sig);
}

#endif
