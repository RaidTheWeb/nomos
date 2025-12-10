#ifndef _SCHED__SIGNAL_HPP
#define _SCHED__SIGNAL_HPP

#include <lib/signal.hpp>
#include <stddef.h>
#include <stdint.h>

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

    struct sigaction {
        void (*handler)(int) = SIG_DFL;
        uint64_t flags = 0;
        void (*restorer)(void) = NULL;
        NLib::sigset_t mask = 0; // Signals to block during execution of action.
    };

    static const size_t NSIG = 64; // Total number of signals.

    struct signal {
        uint64_t pending = 0; // Pending signals.
        uint64_t blocked = 0; // Signals blocked in general.
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

    static inline void setblocked(struct signal *sigstate, uint8_t sig) {
        // Set blocked bit, sig is 1-indexed.
        sigstate->blocked |= (1ULL << (sig - 1));
    }

    static inline bool isblocked(struct signal *sigstate, uint8_t sig) {
        // Check blocked bit, sig is 1-indexed.
        return (sigstate->blocked & (1ULL << (sig - 1))) != 0;
    }

    static inline void clearblocked(struct signal *sigstate, uint8_t sig) {
        // Clear blocked bit, sig is 1-indexed.
        sigstate->blocked &= ~(1ULL << (sig - 1));
    }

    static inline void (*gethandler(struct signal *sigstate, uint8_t sig))(int) {
        return sigstate->actions[sig].handler;
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
