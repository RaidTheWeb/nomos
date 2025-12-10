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

    // XXX: Scrap all this and start again.

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



    extern "C" __attribute__((no_caller_saved_registers)) void signal_checkpending(struct NArch::CPU::context *ctx) {
        // TODO: Implement.
    }

    extern "C" int sys_sigaction(int sig, const struct sigaction *act, struct sigaction *oact) {
        SYSCALL_LOG("sys_sigaction(%d, %p, %p).\n", sig, act, oact);
        SYSCALL_RET(-ENOSYS);
    }

    extern "C" int sys_kill(size_t pid, int sig) {
        SYSCALL_LOG("sys_kill(%u, %d).\n", pid, sig);
        SYSCALL_RET(-ENOSYS);
    }

    extern "C" int sys_sigreturn(void) {
        SYSCALL_LOG("sys_sigreturn().\n");
        SYSCALL_RET(-ENOSYS);
    }

    extern "C" int sys_sigprocmask(int how, const uint64_t *set, uint64_t *oldset) {
        SYSCALL_LOG("sys_sigprocmask(%d, %p, %p).\n", how, set, oldset);

        SYSCALL_RET(-ENOSYS);
    }

}
