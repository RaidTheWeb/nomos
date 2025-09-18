#ifndef _SCHED__SIGNAL_HPP
#define _SCHED__SIGNAL_HPP

#include <lib/signal.hpp>
#include <stddef.h>
#include <stdint.h>

namespace NSched {
    // Default handler actions -> Handled by the kernel, rather than being passed into userspace.
    enum dflactions {
        DFL_IGNORE,         // Performs no actions.
        DFL_TERMINATE,      // Kills program.
        DFL_STOP            // Sleep thread until woken with SIGCONT.
    };

    #define SIG_DFL ((void (*)(int))0)
    #define SIG_IGN ((void (*)(int))1)

    struct sigaction {
        void (*handler)(int) = SIG_DFL;
        uint64_t mask = 0; // Signals to block during execution of action.
        int flags = 0;
    };

    static const size_t NSIG = 64;

    struct signal {
        uint64_t pending = 0; // Pending signals.
        uint64_t blocked = 0; // Signals blocked in general.
        struct sigaction actions[NSIG];
    };

    class Thread;
    class ProcessGroup;
    class Process;

    void deliversignal(Thread *thread, uint8_t sig);

    int signalproc(Process *proc, uint8_t sig);
    int signalpgrp(ProcessGroup *pgrp, uint8_t sig);
    int signalthread(Thread *thread, uint8_t sig);
}

#endif
