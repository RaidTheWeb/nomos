#ifndef _SCHED__SCHED_HPP
#define _SCHED__SCHED_HPP

#ifdef __x86_64__
#include <arch/x86_64/barrier.hpp>
#include <arch/x86_64/context.hpp>
#include <arch/x86_64/sync.hpp>
#include <arch/x86_64/vmm.hpp>
#endif
#include <fs/vfs.hpp>
#include <sched/jobctrl.hpp>
#include <sched/rbtree.hpp>
#include <sched/signal.hpp>
#include <util/kmarker.hpp>
#include <stddef.h>
#include <stdint.h>

namespace NSched {

    // Externally precalculated weights according to the formula 1024 * 1.25^-nice
    static const int NICEWEIGHTS[40] = {
        /* -20 */ 88817, /* -19 */ 71054, /* -18 */ 56843, /* -17 */ 45474, /* -16 */ 36379,
        /* -15 */ 29103, /* -14 */ 23283, /* -13 */ 18626, /* -12 */ 14901, /* -11 */ 11920,
        /* -10 */ 9536,   /* -9 */ 7629,   /* -8 */ 6103,   /* -7 */ 4882,   /* -6 */ 3906,
        /* -5 */  3125,   /* -4 */ 2500,   /* -3 */ 2000,   /* -2 */ 1600,   /* -1 */ 1280,
        /*  0 */  1024,   /*  1 */ 819,    /*  2 */ 655,    /*  3 */ 524,    /*  4 */ 419,
        /*  5 */  335,    /*  6 */ 268,    /*  7 */ 214,    /*  8 */ 171,    /*  9 */ 137,
        /* 10 */  109,    /* 11 */ 87,     /* 12 */ 70,     /* 13 */ 56,     /* 14 */ 45,
        /* 15 */  36,     /* 16 */ 28,     /* 17 */ 23,     /* 18 */ 18,     /* 19 */ 14,
    };

    static const uint64_t STEALTHRESHOLD = 2; // Adds a little extra on top, to consider stealing from another CPU.
    static const uint64_t LOADTHRESHOLD = 2; // Don't attempt load balancing if we exceed this threshold.
    static const uint64_t QUANTUMMS = 10; // 10ms scheduler quantum.

    class Thread;

    enum stdfds {
        STDIN_FILENO = 0,
        STDOUT_FILENO = 1,
        STDERR_FILENO = 2
    };

    class Mutex;

    class WaitQueue {
        private:
            NLib::DoubleList<Thread *> waiting;
        public:

            NArch::IRQSpinlock waitinglock;

            void preparewait(void);
            bool preparewaitinterruptible(void);

            // Finish wait and remove from list if still queued.
            void finishwait(bool locked = false);
            int finishwaitinterruptible(bool locked = false);

            // Non-interruptible wait. If locked=true, waitinglock is already held.
            void wait(bool locked = false);
            // Non-interruptible wait with external lock held.
            void waitlocked(NArch::IRQSpinlock *lock);
            void waitlocked(NArch::Spinlock *lock);
            void waitlocked(NSched::Mutex *lock);

            // Interruptible wait. If locked=true, waitinglock is already held.
            int waitinterruptible(bool locked = false);
            // Interruptible wait with external lock held.
            int waitinterruptiblelocked(NArch::IRQSpinlock *lock);
            int waitinterruptiblelocked(NArch::Spinlock *lock);
            int waitinterruptiblelocked(NSched::Mutex *lock);

            // Wake up all threads waiting on this queue.
            void wake(void);

            // Wake up a single thread waiting on this queue.
            void wakeone(void);

            // Dequeue a specific thread from the waitqueue (used by signal delivery).
            // Returns true if the thread was found and removed.
            bool dequeue(Thread *thread);
    };

    class Process {
        private:
            void init(struct NArch::VMM::addrspace *space, NFS::VFS::FileDescriptorTable *fdtable);
        public:
            struct NArch::VMM::addrspace *addrspace = NULL; // Userspace address space. MUST be first member for easy access from thread.

            enum state {
                RUNNING,
                STOPPED,  // Process is stopped (via SIGSTOP/SIGTSTP/SIGTTIN/SIGTTOU).
                ZOMBIE,
                REAPING, // Being reaped by waitpid - prevents double-reap races.
                DEAD
            };

            enum state pstate = state::RUNNING;
            int exitstatus = 0;
            int stopsig = 0; // Signal that caused the stop (for WUNTRACED reporting).
            WaitQueue exitwq; // Wait queue to await completion of this process.

            bool kernel = false;
            bool hasexeced = false; // Set to true when process calls execve.
            size_t id; // Process ID.
            size_t tidcounter = 1; // Thread ID counter.
            NFS::VFS::FileDescriptorTable *fdtable = NULL;
            NFS::VFS::INode *cwd = NULL;
            NFS::VFS::INode *root = NULL; // Root directory for this process (chroot support).

            // At process creation, these should all be the UID and GID of the runner.

            // Effective UID and GID, manipulated by syscalls.
            int euid = 0;
            int egid = 0;

            // Saved UID and GID. Used for reversion.
            int suid = 0;
            int sgid = 0;

            // Real UID and GID. Who launched the program?
            int uid = 0;
            int gid = 0;

            // Default file creation mask.
            int umask = 022;

            NArch::IRQSpinlock lock;

            Process *parent = NULL;
            NLib::DoubleList<Process *> children;

            ProcessGroup *pgrp = NULL; // Process group ID = PID of leader.
            Session *session = NULL; // Session ID = PID of leader.

            size_t threadcount = 0;
            NLib::DoubleList<Thread *> threads;

            uint64_t tty = 0; // Device ID of process' controlling TTY.

            struct signal signalstate; // Signal state (pending, blocked, handlers).

            uint64_t itimerreal = 0; // Time until next SIGALRM for ITIMER_REAL.
            uint64_t itimerintv = 0; // Interval for ITIMER_REAL.
            uint64_t itimerdeadline = 0; // TSC deadline for ITIMER_REAL.

            // CPU time tracking for CLOCK_PROCESS_CPUTIME_ID.
            volatile uint64_t cputimeticks = 0; // Accumulated CPU time in TSC ticks.

            // ITIMER_VIRTUAL and ITIMER_PROF support.
            uint64_t itimervirtdeadline = 0; // TSC deadline for ITIMER_VIRTUAL (user CPU time).
            uint64_t itimervirtintv = 0;     // Interval for ITIMER_VIRTUAL.
            uint64_t itimerprofdeadline = 0; // TSC deadline for ITIMER_PROF (user + system CPU time).
            uint64_t itimerprofintv = 0;     // Interval for ITIMER_PROF.

            Process(struct NArch::VMM::addrspace *space) {
                this->init(space, NULL);
            }

            Process(struct NArch::VMM::addrspace *space, NFS::VFS::FileDescriptorTable *fdtable) {
                this->init(space, fdtable);
            }

            // Called when there are no more threads in the process, to zombify it (it exited).
            void zombify(void);

            ~Process(void);
    };

    extern NLib::KVHashMap<size_t, Process *> *pidtable;
    extern NArch::IRQSpinlock pidtablelock;

    extern Process *kprocess; // Kernel process.

    static const size_t DEFAULTSTACKSIZE = 16 * NArch::PAGESIZE;

    class Thread {
        public:
            uint8_t *stacktop = NULL; // Top of kernel stack is placed at offset 0, to make it easier to load from system call assembly.
            Process *process = NULL; // Parent process controlling the threads.
            uint8_t *stack = NULL;
            size_t stacksize = DEFAULTSTACKSIZE;

            enum target {
                STRICT, // The thread will ONLY be scheduled onto its target, and will refuse anything else until the target becomes available again.
                RELAXED // The thread would *like* to be placed onto its target if possible, but it's not picky about it.
            };

            enum state {
                READY, // Ready for scheduling (initial state, not in any queue).
                SUSPENDED, // In the runqueue, waiting to be scheduled.
                WAITING, // Blocked on a waitqueue (non-interruptible).
                WAITINGINT, // Blocked on a waitqueue (interruptible by signals).
                PAUSED, // Paused via SIGSTOP or awaiting via sys_pause.
                RUNNING, // Currently executing on a CPU.
                DEAD // Thread has exited and is awaiting cleanup.
            };

            // Get string name of thread state for debugging.
            static const char *statename(enum state s) {
                switch (s) {
                    case READY: return "READY";
                    case SUSPENDED: return "SUSPENDED";
                    case WAITING: return "WAITING";
                    case WAITINGINT: return "WAITINGINT";
                    case PAUSED: return "PAUSED";
                    case RUNNING: return "RUNNING";
                    case DEAD: return "DEAD";
                    default: return "UNKNOWN";
                }
            }

            // Pending wait state. Set before yield, consumed by scheduler after context save.
            // This prevents the race where a thread is woken before its context is saved.
            enum pendingwait {
                PENDING_NONE, // No pending wait.
                PENDING_WAIT, // Wants to enter WAITING state (non-interruptible).
                PENDING_WAITINT // Wants to enter WAITINGINT state (interruptible).
            };

            // Get string name of pending wait state for debugging.
            static const char *pendingwaitname(enum pendingwait pw) {
                switch (pw) {
                    case PENDING_NONE: return "PENDING_NONE";
                    case PENDING_WAIT: return "PENDING_WAIT";
                    case PENDING_WAITINT: return "PENDING_WAITINT";
                    default: return "UNKNOWN";
                }
            }

            struct NArch::CPU::context ctx; // CPU working context (save state).
            struct NArch::CPU::extracontext xctx; // CPU extra context (save state).
            struct NArch::CPU::fpucontext fctx; // CPU fpu context (save state).
            struct NArch::CPU::context *sysctx; // Syscall context (not real context, but provides original values before system call).
        private:
            enum target targetmode = target::RELAXED;
            uint32_t target = 0xffffffff; // Target CPU (for strict mode), ignored for relaxed mode.

            uint64_t vruntime = 0; // Virtual runtime of this thread.
            int nice = 0; // -20 to +19, used for virtual runtime weighting. Lower values mean higher priority.

        public:
            volatile bool rescheduling = false; // Set when thread needs to be rescheduled.

            volatile enum state tstate = state::READY; // Current state of thread. Access atomically.
            volatile enum pendingwait pendingwaitstate = pendingwait::PENDING_NONE; // Pending wait state. Access atomically.
            struct RBTree::node node; // Red-Black tree node for this thread.
            struct Thread *nextzombie = NULL; // Next zombie in the zombie list.
            volatile bool zombiequeued = false; // Set when thread is queued for deletion. Prevents double-queue.
            size_t id = 0; // Thread ID.
            volatile size_t cid = 0; // Current CPU ID. What CPU owns this right now? Access atomically.
            volatile size_t lastcid = 0; // Last CPU ID. What CPU owned it before? Access atomically.

            volatile bool inrunqueue = false; // Is the thread currently in a runqueue? Access atomically.
            volatile bool wokenbeforewait = false; // Set by wake() to prevent scheduler from transitioning to WAITING if wake raced ahead.

            volatile bool migratedisabled = false; // Outright prevent migration of this thread.
            volatile bool inshrink = false; // Thread is currently in page cache shrink. Prevents recursive shrink calls.
            volatile size_t locksheld = 0; // Lock tracking to prevent work stealing from tasks holding locks.

#ifdef TSTATE_DEBUG

            // Debug state tracking.
            volatile uint64_t laststatetransition = 0; // TSC timestamp of last state change.
            volatile enum state laststate = state::READY; // Previous state (for debugging).
            volatile const char *laststateloc = NULL; // Source location of last state transition.
#endif

            NLib::sigset_t blocked = 0; // Signals blocked in this thread.
            NArch::IRQSpinlock waitingonlock; // Lock for waitingon property.
            WaitQueue *waitingon = NULL; // Waitqueue this thread is sleeping on (if any).

            // CPU time tracking for CLOCK_THREAD_CPUTIME_ID (in TSC ticks).
            volatile uint64_t cputimeticks = 0;

            // Alternate signal stack.
            void *altstackbase = NULL;
            size_t altstacksize = 0;
            int altstackflags = 0;

            // Check if this thread can be safely deleted (refcount is zero and queued).
            bool candelete(void) const {
                return  __atomic_load_n(&this->zombiequeued, memory_order_acquire);
            }

            // Called every timeslice, updates weighted vruntime for later scheduling prioritisation.
            void setvruntime(uint64_t delta) {
                uint64_t weight = NICEWEIGHTS[this->nice + 20];
                uint64_t oldvruntime = __atomic_load_n(&this->vruntime, memory_order_acquire);
                uint64_t newvruntime = oldvruntime + (delta * 1024) / weight;
                __atomic_store_n(&this->vruntime, newvruntime, memory_order_release);
            }

            // Set how nice the thread will be to other threads during scheduling. Higher niceness levels will schedule less often.
            void setnice(int nice) {
                this->nice = (nice < -20) ? -20 : (nice > 19) ? 19 : nice;
                NArch::CPU::writemb();
            }

            // Enable migration of this thread to other CPUs.
            void enablemigrate(void) {
                NArch::CPU::writemb();
                __atomic_store_n(&this->migratedisabled, false, memory_order_release);
            }

            // Disable migration of this thread to other CPUs.
            // Highly advised when performing sections of code that expect all logic to be on one CPU (e.g. registering IRQ handlers in drivers).
            void disablemigrate(void) {
                __atomic_store_n(&this->migratedisabled, true, memory_order_release);
                NArch::CPU::writemb();
            }

            int getnice(void) {
                return this->nice;
            }

            uint64_t getvruntime(void) {
                return __atomic_load_n(&this->vruntime, memory_order_acquire);
            }

            // Set vruntime to a specific value (used for normalization and bonuses).
            void setvruntimeabs(uint64_t newvrt) {
                __atomic_store_n(&this->vruntime, newvrt, memory_order_release);
            }

            // Pick which CPU (by ID) this thread should run on.
            void setaffinity(uint32_t target) {
                this->target = target;
            }

            // Get which CPU (by ID) this thread is targeted to run on.
            uint32_t gettarget(void) {
                return this->target;
            }

            // Set targeting mode (STRICT or RELAXED).
            void settmode(enum target mode) {
                this->targetmode = mode;
            }

            // Get targeting mode (STRICT or RELAXED).
            enum target gettargetmode(void) {
                return this->targetmode;
            }

            void savectx(struct NArch::CPU::context *ctx) {
                this->ctx = *ctx; // Copy context over old context. Updating it.
                NArch::CPU::mb();
            }

            void savexctx(void) {
                NArch::CPU::savexctx(&this->xctx); // Ask architecture implementation to save its extra context.
            }

            void init(Process *proc, size_t stacksize, void *entry, void *arg);

            Thread(Process *proc, size_t stacksize, void *entry, void *arg) {
                this->init(proc, stacksize, entry, arg);
            }

            Thread(Process *proc, size_t stacksize, void *entry) {
                this->init(proc, stacksize, entry, NULL);
            }

            Thread(Process *proc, size_t stacksize) {
                this->init(proc, stacksize, NULL, NULL);
            }

            Thread(Process *proc) {
                this->init(proc, DEFAULTSTACKSIZE, NULL, NULL);
            }
            Thread(void) {
                this->init(kprocess, DEFAULTSTACKSIZE, NULL, NULL);
            }
            void destroy(void);

            ~Thread(void) {
                this->destroy();
            }
    };

    // SMP initialisation entry.
    void entry(void);

    // Schedule a thread, targets the idlest CPU.
    void schedulethread(Thread *thread);

    // Voluntarily relinquish access to the CPU. The yielding thread will be rewarded with more opportunities to make up the runtime it lost while yielding.
    void yield();

    // Sleep for a given number of milliseconds. Returns -EINTR if interrupted by a signal, 0 on successful completion.
    int sleep(uint64_t ms);

    // Exit a kernel thread. REQUIRED for ending kernel threads that return eventually.
    void exit(int status, int sig = 0);

    // Await scheduling. This is run on the BSP to jump into the scheduler.
    void await(void);

    // Force CPU of thread to reschedule the thread.
    void reschedule(Thread *thread);

    // Terminate all other threads in a process except the calling thread.
    void termothers(Process *proc);

    // Mark a thread as dead and remove it from waitqueues/runqueues.
    void markdeadandremove(Thread *thread);

    class Mutex {
        private:
            volatile uint32_t locked;
            WaitQueue waitqueue; // Using WaitQueue for proper thread tracking.
        public:
            Mutex(void) {
                this->locked = 0;
            }

            void acquire(void);
            void release(void);
    };

    // Handler called by architecture-specific interrupt handler, will trigger when we need to handle a lazy FPU load.
    void handlelazyfpu(void);

    extern bool initialised;

    // Scheduler initialisation (on BSP).
    void setup(void);

#ifdef TSTATE_DEBUG

    void dumpthreads(void);
    void dumpthread(Thread *thread);

#endif
    void setthreadstate(Thread *thread, Thread::state newstate, const char *loc);
}

#endif
