#ifndef _LIB__SIGNAL_HPP
#define _LIB__SIGNAL_HPP

#define SIGHUP          1
#define SIGINT          2
#define SIGQUIT         3
#define SIGILL          4
#define SIGTRAP         5
#define SIGABRT         6
#define SIGIOT          SIGABRT
#define SIGBUS          7
#define SIGFPE          8
#define SIGKILL         9
#define SIGUSR1         10
#define SIGSEGV         11
#define SIGUSR2         12
#define SIGPIPE         13
#define SIGALRM         14
#define SIGTERM         15
#define SIGSTKFLT       16
#define SIGCHLD         17
#define SIGCONT         18
#define SIGSTOP         19
#define SIGTSTP         20
#define SIGTTIN         21
#define SIGTTOU         22
#define SIGURG          23
#define SIGXCPU         24
#define SIGXFSZ         25
#define SIGVTALRM       26
#define SIGPROF         27
#define SIGWINCH        28
#define SIGPOLL         29
#define SIGIO           SIGPOLL
#define SIGPWR          30
#define SIGSYS          31
#define SIGUNUSED       SIGSYS
#define SIGCANCEL       32
#define SIGTIMER        33
#define SIGRTMIN        34
#define SIGRTMAX        63

#define SIG_BLOCK       0
#define SIG_UNBLOCK     1
#define SIG_SETMASK     2

namespace NLib {
    typedef uint64_t sigset_t;

    static inline const char *strsig(int sig) {
        switch (sig) {
            case SIGHUP: return "SIGHUP";
            case SIGINT: return "SIGINT";
            case SIGQUIT: return "SIGQUIT";
            case SIGILL: return "SIGILL";
            case SIGTRAP: return "SIGTRAP";
            case SIGABRT: return "SIGABRT";
            case SIGBUS: return "SIGBUS";
            case SIGFPE: return "SIGFPE";
            case SIGKILL: return "SIGKILL";
            case SIGUSR1: return "SIGUSR1";
            case SIGSEGV: return "SIGSEGV";
            case SIGUSR2: return "SIGUSR2";
            case SIGPIPE: return "SIGPIPE";
            case SIGALRM: return "SIGALRM";
            case SIGTERM: return "SIGTERM";
            case SIGSTKFLT: return "SIGSTKFLT";
            case SIGCHLD: return "SIGCHLD";
            case SIGCONT: return "SIGCONT";
            case SIGSTOP: return "SIGSTOP";
            case SIGTSTP: return "SIGTSTP";
            case SIGTTIN: return "SIGTTIN";
            case SIGTTOU: return "SIGTTOU";
            case SIGURG: return "SIGURG";
            case SIGXCPU: return "SIGXCPU";
            case SIGXFSZ: return "SIGXFSZ";
            case SIGVTALRM: return "SIGVTALRM";
            case SIGPROF: return "SIGPROF";
            case SIGWINCH: return "SIGWINCH";
            case SIGPOLL: return "SIGPOLL";
            case SIGPWR: return "SIGPWR";
            case SIGSYS: return "SIGSYS";
            case SIGCANCEL: return "SIGCANCEL";
            case SIGTIMER: return "SIGTIMER";
            default: return "UNKNOWN";
        }
    }
}

#endif
