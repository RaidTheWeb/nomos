#ifndef _SCHED__SCHED_HPP
#define _SCHED__SCHED_HPP

#ifdef __x86_64__
#include <arch/x86_64/context.hpp>
#include <arch/x86_64/sync.hpp>
#include <arch/x86_64/vmm.hpp>
#endif
#include <fs/vfs.hpp>
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

            NArch::Spinlock lock;
        private:

            size_t nodecount = 0;
            struct node *root = NULL; // Tree root.

            void rebalance(struct node *node);
            void reerase(struct node *child, struct node *parent);

            void rotateleft(struct node *node);
            void rotateright(struct node *node);
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

            // Get last node (Unlocked).
            struct node *_last(void);

            struct node *_sibling(struct node *node);

            // Insert into Red-Black tree using cmp to compare left child against right child, for traversal.
            void insert(struct node *node, int (*cmp)(struct node *, struct node *)) {
                NLib::ScopeSpinlock guard(&this->lock);
                this->_insert(node, cmp);
            }

            // Remove a node.
            void erase(struct node *node) {
                NLib::ScopeSpinlock guard(&this->lock);
                this->_erase(node);
            }

            // Get first node.
            struct node *first(void) {
                NLib::ScopeSpinlock guard(&this->lock);
                return this->_first();
            }

            // Get last node.
            struct node *last(void) {
                NLib::ScopeSpinlock guard(&this->lock);
                return this->_last();
            }

            // Get next node.
            struct node *next(struct node *node) {
                NLib::ScopeSpinlock guard(&this->lock);
                return this->_next(node);
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

    class Process {
        private:
            void init(struct NArch::VMM::addrspace *space, NFS::VFS::FileDescriptorTable *fdtable);
        public:
            struct NArch::VMM::addrspace *addrspace = NULL; // Userspace address space.
            bool kernel = false;
            size_t id; // Process ID.
            NFS::VFS::FileDescriptorTable *fdtable = NULL;
            NFS::VFS::INode *cwd = NULL;
            // Effective UID and GID, manipulated by syscalls.
            int euid = 0;
            int egid = 0;

            // Saved UID and GID. Used for reversion.
            int suid = 0;
            int sgid = 0;

            // Real UID and GID. Who launched the program?
            int uid = 0;
            int gid = 0;

            uint64_t tty; // Device ID of running TTY. XXX: Derive from standard streams? They would typically point to the current TTY themselves.

            Process(struct NArch::VMM::addrspace *space) {
                this->init(space, NULL);
            }

            Process(struct NArch::VMM::addrspace *space, NFS::VFS::FileDescriptorTable *fdtable) {
                this->init(space, fdtable);
            }

            ~Process(void);
    };

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
                READY, // Ready for scheduling.
                SUSPENDED, // Currently sitting in the running queue, but not currently running.
                WAITING, // Waiting on something like a mutex.
                RUNNING, // Currently running.
                DEAD // Thread exited.
            };

            struct NArch::CPU::context ctx; // CPU working context (save state).
            struct NArch::CPU::extracontext xctx; // CPU extra context (save state).
            struct NArch::CPU::fpucontext fctx; // CPU fpu context (save state).
        private:
            enum target targetmode = target::RELAXED;
            uint16_t target = 0xffff; // Target CPU affinity (ideal).

            uint64_t vruntime = 0; // Virtual runtime of this thread.
            int nice = 0; // -20 to +19, used for virtual runtime weighting. Lower values mean higher priority.

        public:
            enum state tstate = state::READY; // Current state of thread.
            struct RBTree::node node; // Red-Black tree node for this thread.
            size_t id = 0; // Thread ID.
            size_t cid = 0; // Current CPU ID. What CPU owns this right now?
            size_t lastcid = 0; // Last CPU ID. What CPU owned it before?

            // Called every timeslice, updates weighted vruntime for later scheduling prioritisation.
            void setvruntime(uint64_t delta) {
                uint64_t weight = NICEWEIGHTS[this->nice + 20];
                this->vruntime += (delta * 1024) / weight; // Lower nice levels will accumulate vruntime slower, leading to them being scheduled more often.
            }

            // Set how nice the thread will be to other threads during scheduling. Higher niceness levels will schedule less often.
            void setnice(int nice) {
                this->nice = (nice < -20) ? -20 : (nice > 19) ? 19 : nice;
            }

            int getnice(void) {
                return this->nice;
            }

            uint64_t getvruntime(void) {
                return this->vruntime;
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
    void yield(void);

    // Exit a kernel thread. REQUIRED for ending kernel threads that return eventually.
    void exit(void);

    // Await scheduling. This is run on the BSP to jump into the scheduler.
    void await(void);

    class Mutex {
        private:
            volatile uint32_t locked;
            NLib::DoubleList<Thread *> waitqueue;
            NArch::Spinlock waitqueuelock;
        public:
            Mutex(void) {
                this->locked = 0;
            }

            void acquire(void);
            void release(void);
    };

    // Handler called by architecture-specific interrupt handler, will trigger when we need to handle a lazy FPU load.
    void handlelazyfpu(void);

    // Scheduler initialisation (on BSP).
    void setup(void);
}

#endif
