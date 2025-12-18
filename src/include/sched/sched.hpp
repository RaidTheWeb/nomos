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
#include <sched/signal.hpp>
#include <util/kmarker.hpp>
#include <stddef.h>

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


    // Red-Black tree for fair task queue.
    class RBTree {
        private:
            enum colour {
                RED,
                BLACK
            };

        public:
            struct node {
                uintptr_t parent = 0; // Parent + Colour.
                struct node *left = NULL;
                struct node *right = NULL;
                uint8_t pad[64 - (sizeof(uintptr_t) + (sizeof(struct node *) * 2))]; // Cache alignment. We *could* have used __attribute__((aligned(64))) here, but then aligned new would have to be implemented.

                struct node *getparent(void) {
                    return (struct node *)(this->parent & ~0b11); // Colour is stored within lower bit, we use this to extract only the parent from the node property.
                }

                enum colour getcolour(void) {
                    return (enum colour)(this->parent & 0b01); // Extract colour from last bit.
                }

                // Pack parent of node, given the parent. Uses original colour.
                void packparent(struct node *parent) {
                    this->parent = (uintptr_t)parent | this->getcolour();
                }

                // Pack colour of node, given the colour. Uses original parent.
                void packcolour(enum colour colour) {
                    this->parent = (uintptr_t)this->getparent() | colour;
                }
            };

            template <typename T>
            static T *getentry(struct node *node) {
                return reinterpret_cast<T *>(
                    reinterpret_cast<uint8_t *>(node) - offsetof(T, node)
                );
            }

            NArch::IRQSpinlock lock;
        private:

            size_t nodecount = 0;
            struct node *root = NULL; // Tree root.

            void rebalance(struct node *node);
            void reerase(struct node *child, struct node *parent);

            void rotateleft(struct node *node);
            void rotateright(struct node *node);
            void transplant(struct node *u, struct node *v);
        public:
            RBTree(void) { };

            // Insert into Red-Black tree using cmp to compare left child against right child, for traversal (Unlocked).
            void _insert(struct node *node, int (*cmp)(struct node *, struct node *));

            // Remove a node (Unlocked).
            void _erase(struct node *node);

            // Get first node (Unlocked).
            struct node *_first(void);

            // Get next node (Unlocked).
            struct node *_next(struct node *node);

            // Get previous node (Unlocked).
            struct node *_prev(struct node *node);

            // Get last node (Unlocked).
            struct node *_last(void);

            struct node *_sibling(struct node *node);

            // Insert into Red-Black tree using cmp to compare left child against right child, for traversal.
            void insert(struct node *node, int (*cmp)(struct node *, struct node *)) {
                NLib::ScopeIRQSpinlock guard(&this->lock);
                this->_insert(node, cmp);
            }

            // Remove a node.
            void erase(struct node *node) {
                NLib::ScopeIRQSpinlock guard(&this->lock);
                this->_erase(node);
            }

            // Get first node.
            struct node *first(void) {
                NLib::ScopeIRQSpinlock guard(&this->lock);
                return this->_first();
            }

            // Get last node.
            struct node *last(void) {
                NLib::ScopeIRQSpinlock guard(&this->lock);
                return this->_last();
            }

            // Get next node.
            struct node *next(struct node *node) {
                NLib::ScopeIRQSpinlock guard(&this->lock);
                return this->_next(node);
            }

            struct node *prev(struct node *node) {
                NLib::ScopeIRQSpinlock guard(&this->lock);
                return this->_prev(node);
            }

            // Count the number of nodes within the Red-Black tree.
            size_t count(void);
    };

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
            // Dump current thread into waiting queue, to be woken up upon wake(), if it's its turn. Takes an optional parameter specifying whether the wait queue lock is already held.
            void wait(bool locked = false);
            // Atomic wait on condition with external IRQSpinlock held.
            void waitlocked(NArch::IRQSpinlock *lock);
            // Atomic wait on condition with external Spinlock held.
            void waitlocked(NArch::Spinlock *lock);
            // Atomic wait on condition with external Mutex held.
            void waitlocked(NSched::Mutex *lock);

            // Interruptible wait that returns -EINTR if a signal is pending. Takes an optional parameter specifying whether the wait queue lock is already held.
            int waitinterruptible(bool locked = false);
            // Atomic interruptible wait on condition with external IRQSpinlock held. Returns -EINTR if interrupted.
            int waitinterruptiblelocked(NArch::IRQSpinlock *lock);
            // Atomic interruptible wait on condition with external Spinlock held. Returns -EINTR if interrupted.
            int waitinterruptiblelocked(NArch::Spinlock *lock);
            // Atomic interruptible wait on condition with external Mutex held. Returns -EINTR if interrupted.
            int waitinterruptiblelocked(NSched::Mutex *lock);

            // Wake up sleeping threads in the wait queue, so they'll check if they can run again.
            void wake(void);

            // Dequeue a specific thread from the waitqueue (used by signal delivery).
            bool dequeue(Thread *thread);
    };

    class Process {
        private:
            void init(struct NArch::VMM::addrspace *space, NFS::VFS::FileDescriptorTable *fdtable);
        public:
            struct NArch::VMM::addrspace *addrspace = NULL; // Userspace address space. MUST be first member for easy access from thread.

            enum state {
                RUNNING,
                ZOMBIE,
                DEAD
            };

            enum state pstate = state::RUNNING;
            int exitstatus = 0;
            WaitQueue exitwq; // Wait queue to await completion of this process.

            bool kernel = false;
            bool hasexeced = false; // Set to true when process calls execve.
            size_t id; // Process ID.
            size_t tidcounter = 1; // Thread ID counter.
            NFS::VFS::FileDescriptorTable *fdtable = NULL;
            NFS::VFS::INode *cwd = NULL;

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

            uint64_t tty; // Device ID of process' controlling TTY.

            struct signal signalstate; // Signal state (pending, blocked, handlers).

            uint64_t itimerreal = 0; // Time until next SIGALRM for ITIMER_REAL.
            uint64_t itimerintv = 0; // Interval for ITIMER_REAL.
            uint64_t itimerdeadline = 0; // TSC deadline for ITIMER_REAL.

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

            struct NArch::CPU::context ctx; // CPU working context (save state).
            struct NArch::CPU::extracontext xctx; // CPU extra context (save state).
            struct NArch::CPU::fpucontext fctx; // CPU fpu context (save state).
            struct NArch::CPU::context *sysctx; // Syscall context (not real context, but provides original values before system call).
        private:
            enum target targetmode = target::RELAXED;
            uint16_t target = 0xffff; // Target CPU affinity (ideal).

            uint64_t vruntime = 0; // Virtual runtime of this thread.
            int nice = 0; // -20 to +19, used for virtual runtime weighting. Lower values mean higher priority.

        public:
            volatile bool rescheduling = false; // Set when thread needs to be rescheduled.

            volatile enum state tstate = state::READY; // Current state of thread. Access atomically.
            struct RBTree::node node; // Red-Black tree node for this thread.
            struct Thread *nextzombie = NULL; // Next zombie in the zombie list.
            size_t id = 0; // Thread ID.
            volatile size_t cid = 0; // Current CPU ID. What CPU owns this right now? Access atomically.
            size_t lastcid = 0; // Last CPU ID. What CPU owned it before?

            volatile bool migratedisabled = false; // Outright prevent migration of this thread.
            volatile size_t locksheld = 0; // Lock tracking to prevent work stealing from tasks holding locks.

            NLib::sigset_t blocked = 0; // Signals blocked in this thread.
            WaitQueue *waitingon = NULL; // Waitqueue this thread is sleeping on (if any).

            // Alternate signal stack.
            void *altstackbase = NULL;
            size_t altstacksize = 0;
            int altstackflags = 0;

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

            void enablemigrate(void) {
                NArch::CPU::writemb();
                __atomic_store_n(&this->migratedisabled, false, memory_order_release);
            }

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

            void setaffinity(uint16_t target) {
                this->target = target;
            }

            void settmode(enum target mode) {
                this->targetmode = mode;
            }

            void savectx(struct NArch::CPU::context *ctx) {
                this->ctx = *ctx; // Copy context over old context. Updating it.
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
}

#endif
