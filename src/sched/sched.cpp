#ifdef __x86_64__
#include <arch/x86_64/apic.hpp>
#include <arch/x86_64/cpu.hpp>
#include <arch/x86_64/e9.hpp>
#include <arch/x86_64/smp.hpp>
#include <arch/x86_64/tsc.hpp>
#include <arch/x86_64/timer.hpp>
#endif
#include <fs/devfs.hpp>
#include <lib/assert.hpp>
#include <mm/slab.hpp>
#include <mm/ucopy.hpp>
#include <sched/event.hpp>
#include <sched/sched.hpp>
#include <sys/elf.hpp>
#include <sys/syscall.hpp>
#include <sys/timer.hpp>

namespace NSched {
    using namespace NArch;

    void RBTree::_insert(struct node *node, int (*cmp)(struct node *, struct node *)) {
        struct node *y = NULL;
        struct node *x = this->root;

        while (x != NULL) {
            y = x;
            if (cmp(node, x) < 0) {
                x = x->left;
            } else {
                x = x->right;
            }
        }

        node->packparent(y);
        if (y == NULL) {
            this->root = node;
        } else if (cmp(node, y) < 0) {
            y->left = node;
        } else {
            y->right = node;
        }

        node->left = NULL;
        node->right = NULL;
        node->packcolour(colour::RED);

        this->rebalance(node);

        __atomic_add_fetch(&this->nodecount, 1, memory_order_seq_cst);
    }

    void RBTree::_erase(struct node *z) {
        struct node *y = z;
        struct node *x = NULL;
        struct node *x_parent = NULL;
        enum colour y_original_colour = y->getcolour();

        if (z->left == NULL) {
            x = z->right;
            this->transplant(z, z->right);
            x_parent = z->getparent();
        } else if (z->right == NULL) {
            x = z->left;
            this->transplant(z, z->left);
            x_parent = z->getparent();
        } else {
            y = this->_next(z);
            y_original_colour = y->getcolour();
            x = y->right;

            if (y->getparent() == z) {
                x_parent = y;
            } else {
                x_parent = y->getparent();
                this->transplant(y, y->right);
                y->right = z->right;
                if (y->right) y->right->packparent(y);
            }

            this->transplant(z, y);
            y->left = z->left;
            y->left->packparent(y);
            y->packcolour(z->getcolour());
        }

        if (y_original_colour == colour::BLACK) {
            this->reerase(x, x_parent);
        }

        __atomic_sub_fetch(&this->nodecount, 1, memory_order_seq_cst);
    }

    void RBTree::transplant(struct node *u, struct node *v) {
        if (u->getparent() == NULL) {
            this->root = v;
        } else if (u == u->getparent()->left) {
            u->getparent()->left = v;
        } else {
            u->getparent()->right = v;
        }
        if (v != NULL) {
            v->packparent(u->getparent());
        }
    }

    void RBTree::rotateleft(struct node *x) {
        struct node *y = x->right;
        struct node *t2 = y->left;

        x->right = t2;

        if (y->left) {
            y->left->packparent(x);
        }

        y->packparent(x->getparent());

        if (!x->getparent()) {
            this->root = y; // Has no parent, this will be the top level node.
        } else if (x == x->getparent()->left) { // We are the left path of the parent.
            x->getparent()->left = y;
        } else {
            x->getparent()->right = y;
        }

        y->left = x;
        x->packparent(y); // Y is now the new parent node.
    }

    void RBTree::rotateright(struct node *y) {
        struct node *x = y->left;
        struct node *t2 = x->right;

        y->left = t2;

        if (x->right) {
            x->right->packparent(y);
        }

        x->packparent(y->getparent());

        if (!y->getparent()) {
            this->root = x;
        } else if (y == y->getparent()->right) { // We are the right path of the parent.
            y->getparent()->right = x;
        } else {
            y->getparent()->left = x;
        }

        x->right = y;
        y->packparent(x); // X is now the parent node.
    }

    struct RBTree::node *RBTree::_first(void) {

        struct node *n = this->root;
        if (!n) {
            return NULL; // With no root, there is no node.
        }

        while (n->left) {
            n = n->left; // Traverse left branch.
        }
        return n;
    }

    struct RBTree::node *RBTree::_last(void) {
        // Same as _first(), but we traverse the right branch instead.

        struct node *n = this->root;
        if (!n) {
            return NULL; // With no root, there is no node.
        }

        while (n->right) {
            n = n->right; // Traverse right branch.
        }
        return n;
    }

    struct RBTree::node *RBTree::_next(struct node *node) {

        if (node->right) {
            struct node *n = node->right;
            while (n->left) {
                n = n->left;
            }
            return n;
        }

        struct node *parent = node->getparent();
        while (parent && node == parent->right) {
            node = parent;
            parent = parent->getparent();
        }
        return parent;
    }

    struct RBTree::node *RBTree::_prev(struct node *node) {

        if (node->left) {
            struct node *n = node->left;
            while (n->right) {
                n = n->right;
            }
            return n;
        }

        struct node *parent = node->getparent();
        while (parent && node == parent->left) {
            node = parent;
            parent = parent->getparent();
        }
        return parent;
    }

    void RBTree::rebalance(struct node *z) {
        while (z->getparent() && z->getparent()->getcolour() == colour::RED) {
            if (z->getparent() == z->getparent()->getparent()->left) {
                struct node *y = z->getparent()->getparent()->right;
                if (y && y->getcolour() == colour::RED) {
                    z->getparent()->packcolour(colour::BLACK);
                    y->packcolour(colour::BLACK);
                    z->getparent()->getparent()->packcolour(colour::RED);
                    z = z->getparent()->getparent();
                } else {
                    if (z == z->getparent()->right) {
                        z = z->getparent();
                        this->rotateleft(z);
                    }
                    z->getparent()->packcolour(colour::BLACK);
                    z->getparent()->getparent()->packcolour(colour::RED);
                    this->rotateright(z->getparent()->getparent());
                }
            } else {
                struct node *y = z->getparent()->getparent()->left;
                if (y && y->getcolour() == colour::RED) {
                    z->getparent()->packcolour(colour::BLACK);
                    y->packcolour(colour::BLACK);
                    z->getparent()->getparent()->packcolour(colour::RED);
                    z = z->getparent()->getparent();
                } else {
                    if (z == z->getparent()->left) {
                        z = z->getparent();
                        this->rotateright(z);
                    }
                    z->getparent()->packcolour(colour::BLACK);
                    z->getparent()->getparent()->packcolour(colour::RED);
                    this->rotateleft(z->getparent()->getparent());
                }
            }
        }
        this->root->packcolour(colour::BLACK);
    }

    void RBTree::reerase(struct node *x, struct node *x_parent) {
        struct node *w;
        while (x != this->root && (x == NULL || x->getcolour() == colour::BLACK)) {
            if (x == x_parent->left) {
                w = x_parent->right;
                if (w->getcolour() == colour::RED) {
                    w->packcolour(colour::BLACK);
                    x_parent->packcolour(colour::RED);
                    this->rotateleft(x_parent);
                    w = x_parent->right;
                }
                if ((w->left == NULL || w->left->getcolour() == colour::BLACK) &&
                    (w->right == NULL || w->right->getcolour() == colour::BLACK)) {
                    w->packcolour(colour::RED);
                    x = x_parent;
                    x_parent = x->getparent();
                } else {
                    if (w->right == NULL || w->right->getcolour() == colour::BLACK) {
                        if (w->left) {
                            w->left->packcolour(colour::BLACK);
                        }
                        w->packcolour(colour::RED);
                        this->rotateright(w);
                        w = x_parent->right;
                    }
                    w->packcolour(x_parent->getcolour());
                    x_parent->packcolour(colour::BLACK);
                    if (w->right) {
                        w->right->packcolour(colour::BLACK);
                    }
                    this->rotateleft(x_parent);
                    x = this->root;
                }
            } else {
                w = x_parent->left;
                if (w->getcolour() == colour::RED) {
                    w->packcolour(colour::BLACK);
                    x_parent->packcolour(colour::RED);
                    this->rotateright(x_parent);
                    w = x_parent->left;
                }
                if ((w->right == NULL || w->right->getcolour() == colour::BLACK) &&
                    (w->left == NULL || w->left->getcolour() == colour::BLACK)) {
                    w->packcolour(colour::RED);
                    x = x_parent;
                    x_parent = x->getparent();
                } else {
                    if (w->left == NULL || w->left->getcolour() == colour::BLACK) {
                        if (w->right) {
                            w->right->packcolour(colour::BLACK);
                        }
                        w->packcolour(colour::RED);
                        this->rotateleft(w);
                        w = x_parent->left;
                    }
                    w->packcolour(x_parent->getcolour());
                    x_parent->packcolour(colour::BLACK);
                    if (w->left) {
                        w->left->packcolour(colour::BLACK);
                    }
                    this->rotateright(x_parent);
                    x = this->root;
                }
            }
        }
        if (x) {
            x->packcolour(colour::BLACK);
        }
    }

    size_t RBTree::count(void) {
        // Lockless return of cached value.
        return __atomic_load_n(&this->nodecount, memory_order_seq_cst);
    }

    // Comparison function for insertion logic.
    static int vruntimecmp(struct RBTree::node *a, struct RBTree::node *b) {
        // Get references to threads from Red-Black tree nodes.
        Thread *ta = RBTree::getentry<Thread>(a);
        Thread *tb = RBTree::getentry<Thread>(b);

        // Compare virtual runtimes of threads. -1 and 1 reflect which one has the smaller virtual runtime (lower virtual runtimes will be prioritised during scheduling, over higher virtual runtimes). Here, these are used for sorting into left and right branches.
        // If the node (a) has a smaller virtual runtime than its parent (b), it'll be placed in the left branch of the parent.
        return (ta->getvruntime() < tb->getvruntime()) ? -1 : 1;
    }

    // Attempts to locate a busier CPU (considering STEALTHRESHOLD) to steal tasks from. This is used for load balancing.
    static struct CPU::cpulocal *getstealbusiest(void) {
        // XXX: Calculate within the same NUMA node, to avoid cross-node migrations.

        uint64_t maxload = 0;
        struct CPU::cpulocal *busiest = NULL;
        uint64_t ourload = __atomic_load_n(&CPU::get()->loadweight, memory_order_seq_cst);

        for (size_t i = 0; i < SMP::awakecpus; i++) {
            // Atomically load the load of the CPU. We want to be avoiding using spinlocks, so we don't occupy the instance's state.
            uint64_t load = __atomic_load_n(&SMP::cpulist[i]->loadweight, memory_order_seq_cst);

            if (load > ourload * 2) { // Early exit for severely overloaded CPU.
                return SMP::cpulist[i];
            }

            if (load > maxload && load > ourload + STEALTHRESHOLD) { // If this is the biggest load thus far, *AND* exceeds our threshold, we'll keep this in mind for stealing from.
                maxload = load; // Update maximum load thus far, for comparison against others.
                busiest = SMP::cpulist[i]; // Thus far, this is our busiest CPU.
            }
        }

        return busiest;
    }

    // Attempts to locate the most idle CPU. This is used for scheduling, and for the target of load balancing.
    static struct CPU::cpulocal *getidlest(void) {
        // XXX: Calculate within the same NUMA node, to avoid cross-node migrations.

        uint64_t minload = __UINT64_MAX__; // Start at theoretical maximum, so any lower load will be chosen first.
        struct CPU::cpulocal *idlest = NULL;

        for (size_t i = 0; i < SMP::awakecpus; i++) {
            uint64_t load = __atomic_load_n(&SMP::cpulist[i]->loadweight, memory_order_seq_cst);

            if (load < minload) { // If this CPU has less load than the last, pick it.
                minload = load;
                idlest = SMP::cpulist[i];

                if (load == 0) { // CPU has no work!
                    break; // Break so we choose this one.
                }
            }
        }

        return idlest;
    }

    void updateload(struct CPU::cpulocal *cpu) {
        size_t num = cpu->runqueue.count();
        // Weighted load balancing calculation, considering the number of active tasks.
        __atomic_store_n(&cpu->loadweight,
            (__atomic_load_n(&cpu->loadweight, memory_order_seq_cst)
            * 3 + num * 1024) / 4,
        memory_order_seq_cst);
    }

    void loadbalance(struct CPU::cpulocal *cpu) {
        if (cpu->runqueue.count() <= LOADTHRESHOLD) {
            return; // We're done here.
        }

        // Migrate our tasks to other CPUs to mitigate load.
        struct CPU::cpulocal *target = getidlest();
        if (!target || cpu == target) { // Don't try to load balance to ourselves! We'd just end up deadlocking.
            return;
        }
        size_t quota = (cpu->runqueue.count() - LOADTHRESHOLD) / 4; // Target should be given a quarter of our work.


        // Lock ordering to prevent cyclic deadlocks.
        if (cpu->id < target->id) {
            cpu->runqueue.lock.acquire();
            target->runqueue.lock.acquire();
        } else {
            target->runqueue.lock.acquire();
            cpu->runqueue.lock.acquire();
        }

        struct RBTree::node *node = cpu->runqueue._last();
        while (node && quota > 0) { // If we have work to migrate, and a quota to fulfill, keep working.
            Thread *stolen = RBTree::getentry<Thread>(node);
            struct RBTree::node *prev = cpu->runqueue._prev(node);

            if (__atomic_load_n(&stolen->locksheld, memory_order_seq_cst) > 0 || stolen->migratedisabled) {
                node = prev; // Skip nodes we can't migrate.
                continue;
            }
            cpu->runqueue._erase(node);
            stolen->cid = target->id;

            NArch::CPU::writemb(); // Ensure writes are seen.
            target->runqueue._insert(node, vruntimecmp);
            quota--;

            node = prev;
        }

        if (cpu->id < target->id) {
            target->runqueue.lock.release();
            cpu->runqueue.lock.release();
        } else {
            cpu->runqueue.lock.release();
            target->runqueue.lock.release();
        }

        updateload(target);
        updateload(cpu);
    }

    // Get a hold of a thread from the busiest CPU, migrating it (but not adding it to the new run queue).
    Thread *steal(void) {
        struct CPU::cpulocal *busiest = getstealbusiest(); // Get a handle on the busiest CPU.

        if (!busiest) {
            return NULL; // We're done here, there's nothing we can do.
        }

        busiest->runqueue.lock.acquire();
        struct RBTree::node *node = busiest->runqueue._last(); // Grab node with highest runtime (least deserving of being run), and incur migration penalty.
        if (!node) {
            busiest->runqueue.lock.release();
            return NULL; // We're done here, only one node is in the run queue (it's probably running right now, even).
        }
        Thread *stolen = RBTree::getentry<Thread>(node);
        if (__atomic_load_n(&stolen->locksheld, memory_order_seq_cst) > 0 || stolen->migratedisabled) { // "Stealable" threads either don't currently hold a spinlock, or have migration enabled.
            busiest->runqueue.lock.release();
            return NULL;
        }

        busiest->runqueue._erase(node); // Remove this node from the list.
        busiest->runqueue.lock.release();

        updateload(busiest);

        stolen->cid = CPU::get()->id; // Update CID.
        return stolen;
    }

    Thread *nextthread(void) {
        struct RBTree::node *node = CPU::get()->runqueue._first(); // Get the node with the least virtual runtime (this could mean *either* that it has higher priority, or just hasn't run for very long yet).
        if (node) {
            CPU::get()->runqueue._erase(node); // Remove first.
            return RBTree::getentry<Thread>(node); // Then return the entry.
        }

        return steal(); // We have no work, try to steal something from another CPU.
    }

    void switchthread(Thread *thread, bool needswap) {

        Thread *prev = CPU::get()->currthread;

        CPU::get()->currthread = thread; // Update current thread.

        assert(prev, "Previous thread before context switch should *never* be NULL.\n");

        if (needswap) {
            swaptopml4(thread->process->addrspace->pml4phy);
        }

#ifdef __x86_64__
        CPU::get()->intstatus = thread->ctx.rflags & 0x200; // Restore the interrupt status of the thread.
        CPU::get()->ist.rsp0 = (uint64_t)thread->stacktop;

        thread->fctx.mathused = false; // Start thread not having used maths (so we don't *have* to save the context during this quantum, unless the thread uses the FPU in this time).
        uint64_t cr0 = CPU::rdcr0();
        cr0 |= (1 << 3); // Set TS bit.
        CPU::wrcr0(cr0);

#endif
        __atomic_store_n(&thread->tstate, Thread::state::RUNNING, memory_order_release); // Set state.

        CPU::restorexctx(&thread->xctx); // Restore extra context.
        CPU::ctx_swap(&thread->ctx); // Restore context.

        __builtin_unreachable();
    }

    // Scheduler interrupt entry, handles save.
    void schedule(struct Interrupts::isr *isr, struct CPU::context *ctx) {
        (void)isr;

        APIC::lapicstop();

        struct CPU::cpulocal *cpu = CPU::get(); // Get an easy local reference to our current CPU.

        assert(cpu, "Failed to acquire current CPU.\n");

        cpu->setint(false); // Disable interrupts, we don't want our scheduling work to be interrupted.

        size_t curintr = __atomic_add_fetch(&cpu->schedintr, 1, memory_order_seq_cst); // Increment the number of times this interrupt has been called.

        assert(cpu->currthread, "Current thread should NEVER be NULL.\n");

        uint64_t now = TSC::query();
        uint64_t delta = (((now - CPU::get()->lastschedts) * 1000) / TSC::hz); // Find delta between now and last timestamp. Convert to milliseconds.
        CPU::get()->lastschedts = now;

        cpu->currthread->setvruntime(delta); // Update virtual runtime, using the delta since last timer interrupt. This keeps things fair when a thread yields early.
        // While we "wait" QUANTUMMS between scheduling interrupts, that might not be how long it *actually* takes, so, we accumulate runtime based on how much runtime actually occurred.

        updateload(cpu); // Update current CPU load. For load balancing and scheduling tasks.


        // Load Balance on an interval:
        if (!(curintr % 4)) { // Every fourth schedule interrupt:
            loadbalance(cpu);
        }

        Thread *prev = cpu->currthread; // Currently running thread.
        Thread *next = NULL; // What we're planning to schedule next.


        if (prev->rescheduling) { // Handle migration re-enable on reschedule.
            __atomic_store_n(&prev->rescheduling, false, memory_order_seq_cst);
            prev->enablemigrate();
        }

        {
            NLib::ScopeIRQSpinlock guard(&cpu->runqueue.lock); // Lock run queue, so we can gather and remove the next thread.
            if (prev != cpu->idlethread) {
                if (__atomic_load_n(&prev->tstate, memory_order_acquire) == Thread::state::RUNNING) { // Thread is still "runnable".

                    __atomic_store_n(&prev->tstate, Thread::state::SUSPENDED, memory_order_release);
                    NArch::CPU::writemb(); // Ensure writes are seen.
                    cpu->runqueue._insert(&prev->node, vruntimecmp); // Shove it back onto the run queue for this CPU. It'll be ran later.
                }
            }

            next = nextthread(); // Get the next task to schedule. It'll return NULL if we have nothing to do.
            assert(next != cpu->idlethread, "Next thread should NEVER be the idle thread (it is not supposed to be in the run queue).\n");

            if (prev != next && prev != cpu->idlethread) {
#ifdef __x86_64__
                if (prev->fctx.mathused) {
                    CPU::savefctx(&prev->fctx); // Always save FPU context when the thread used maths.
                }
#endif
                prev->savexctx();
                prev->savectx(ctx); // Use the interrupt context to override the save state of the previous thread.
            }
        }

        if (!next) {
            next = cpu->idlethread; // We have NO work, and can't steal ANY others. Default to idle thread until next schedule().
        }

        prev->lastcid = cpu->id; // Update the previous thread's old CPU ID.
        next->cid = cpu->id; // Update new thread's current CPU ID.

        if (prev != next) { // We need to context switch.
            bool needswap = prev->process->addrspace != next->process->addrspace;
            if (__atomic_load_n(&prev->tstate, memory_order_acquire) == Thread::state::DEAD) {
                delete prev;
            }

            Timer::rearm();
            cpu->quantumdeadline = TSC::query() + TSC::hz / 1000 * QUANTUMMS; // Set quantum deadline based on TSC.

            switchthread(next, needswap); // Swap to context.
        }

        __atomic_store_n(&next->tstate, Thread::state::RUNNING, memory_order_release); // Set state.

        // We haven't changed anything. We were just given our old thread, this happens most commonly when running the idle thread.
        // It'd be a waste to attempt to context switch when we're working on the same code.

        cpu->quantumdeadline = TSC::query() + TSC::hz / 1000 * QUANTUMMS; // Set quantum deadline based on TSC.
        Timer::rearm();
        cpu->setint(true); // Although it'll be re-enabled during the context switch, we may have lost track of the interrupt state here. So, we should explicitly reenable it before rescheduling.

        // If it's the same thread, we'll just be dumped right back to where we are.
    }


    static size_t pidcounter = 0; // Because kernel process is the first process made, it'll be PID0. The first user process (init) will be PID1!
    Process *kprocess = NULL; // Kernel process.
    NArch::IRQSpinlock pidtablelock;
    NLib::KVHashMap<size_t, Process *> *pidtable = NULL;

    void Process::init(struct VMM::addrspace *space, NFS::VFS::FileDescriptorTable *fdtable) {
        // Each new process should be initialised with an atomically incremented PID.
        this->id = __atomic_fetch_add(&pidcounter, 1, memory_order_seq_cst);
        this->addrspace = space;
        this->addrspace->lock.acquire();
        this->addrspace->ref++; // Reference address space.
        this->addrspace->lock.release();
        if (space == &VMM::kspace) {
            this->kernel = true; // Mark process as a kernel process if it uses the kernel address space.
        } else { // Only userspace threads should bother creating file descriptor tables.
            this->tty = NFS::DEVFS::makedev(4, 1);
            if (!fdtable) {
                this->fdtable = new NFS::VFS::FileDescriptorTable();
                NFS::VFS::INode *stdin = NFS::VFS::vfs.resolve("/dev/tty");
                assert(stdin, "Could not resolve standard input.\n");
                stdin->unref();

                this->fdtable->reserve(STDIN_FILENO, stdin, NFS::VFS::O_RDONLY);

                NFS::VFS::INode *stdout = NFS::VFS::vfs.resolve("/dev/tty");
                assert(stdout, "Could not resolve standard output.\n");
                stdout->unref();

                this->fdtable->reserve(STDOUT_FILENO, stdout, NFS::VFS::O_WRONLY | NFS::VFS::O_CLOEXEC);
                NFS::VFS::INode *stderr = NFS::VFS::vfs.resolve("/dev/tty");
                assert(stderr, "Could not resolve standard error.\n");
                stderr->unref();

                this->fdtable->reserve(STDERR_FILENO, stderr, NFS::VFS::O_WRONLY | NFS::VFS::O_NONBLOCK);
            } else {
                this->fdtable = fdtable; // Inherit from a forked file descriptor table we were given.
            }
        }
    }

    void Process::zombify(void) {
        this->lock.acquire();

        if (this->fdtable) {
            delete this->fdtable;
        }


        if (this->cwd) {
            this->cwd->unref(); // Unreference current working directory (so it isn't marked busy).
        }

        this->addrspace->lock.acquire();
        this->addrspace->ref--;
        size_t ref = this->addrspace->ref;
        NUtil::printf("Process %d: Address space ref count is now %d.\n", this->id, ref);
        this->addrspace->lock.release();

        if (ref == 0) {
            NUtil::printf("Process %d: Freeing address space.\n", this->id);
            delete this->addrspace;
        }

        this->pstate = Process::state::ZOMBIE;

        if (this->parent) {
            // XXX: TODO: Use signals for this.
            this->parent->exitwq.wake(); // We're done!
        }

        this->lock.release();
    }

    Process::~Process(void) {
        this->lock.acquire();

        pidtablelock.acquire();
        pidtable->remove(this->id);
        pidtablelock.release();

        if (this->pgrp) {
            // XXX: Orphan process groups if we're the leader.

            this->pgrp->lock.acquire();
            this->pgrp->procs.remove([](Process *p, void *arg) {
                return p == ((Process *)arg);
            }, (void *)this);
            this->pgrp->lock.release();
        }

        if (this->parent) {
            this->parent->lock.acquire();
            this->parent->children.remove([](Process *p, void *arg) {
                return p == ((Process *)arg);
            }, (void *)this);
            this->parent->lock.release();

            NSched::signalproc(this->parent, SIGCHLD); // Signal parent that child exited.
        }

        if (children.size()) {
            // XXX: Reparent now "zombie" processes to init process.
            NLib::DoubleList<Process *>::Iterator it = this->children.begin();
            for (; it.valid(); it.next()) {
                Process *child = *(it.get());
                child->lock.acquire();
                child->parent = NULL;
                child->lock.release();
            }
        }

        this->lock.release();
    }

    void reschedule(Thread *thread) {
        thread->disablemigrate(); // Prevent migration during operation.

        // Re-enable migration during reschedule.
        __atomic_store_n(&thread->rescheduling, true, memory_order_seq_cst);

        // Send IPI to owning CPU.
        APIC::sendipi(NArch::SMP::cpulist[thread->cid]->lapicid, 0xfe, APIC::IPIFIXED, APIC::IPIPHYS, 0);
    }

    void yield(void) {
        APIC::lapicstop();

        CPU::get()->setint(true);

        // Artificially induce a schedule interrupt, using a "loopback" IPI.
        APIC::sendipi(CPU::get()->lapicid, 0xfe, APIC::IPIFIXED, APIC::IPIPHYS, APIC::IPISELF);

        // At this point, we've either been rescheduled (if we were running) or marked dead.
    }

    // Timer callback for sleep().
    static void sleepwork(void *arg) {
        Thread *thread = (Thread *)arg;
        schedulethread(thread);
    }

    void sleep(uint64_t ms) {
        Thread *current = CPU::get()->currthread;
        NSys::Timer::timerlock();
        NArch::CPU::get()->setint(false); // Disable interrupts to prevent preemption during this critical section.

        __atomic_store_n(&current->tstate, Thread::state::WAITING, memory_order_release);
        NSys::Timer::create(sleepwork, current, ms); // XXX: Figure out how to ENSURE we don't get preempted before the yield().

        NSys::Timer::timerunlock();
        NArch::CPU::get()->setint(true); // Re-enable interrupts.
        yield();
    }

    void Mutex::acquire(void) {
#ifdef __x86_64__
        while (__sync_lock_test_and_set(&this->locked, 1)) {
#endif

            this->waitqueuelock.acquire();
            NArch::CPU::get()->setint(false); // Disable interrupts to prevent preemption during this critical section.
            __atomic_store_n(&NArch::CPU::get()->currthread->tstate, Thread::state::WAITING, memory_order_release);
            assert(NArch::CPU::get()->currthread != NArch::CPU::get()->idlethread, "Mutex on idle thread.\n");
            this->waitqueue.pushback(NArch::CPU::get()->currthread);
            this->waitqueuelock.release();
            NArch::CPU::get()->setint(true); // Re-enable interrupts.
            yield(); // Yield into suspend.
            // We're back, try to reacquire, and if we CAN, we're out!
        }
        __atomic_add_fetch(&CPU::get()->currthread->locksheld, 1, memory_order_seq_cst);
    }

    void Mutex::release(void) {
#ifdef __x86_64__
        __sync_lock_release(&this->locked);
#endif
        __atomic_sub_fetch(&CPU::get()->currthread->locksheld, 1, memory_order_seq_cst);
        this->waitqueuelock.acquire();
        if (!this->waitqueue.empty()) {
            Thread *thread = this->waitqueue.pop();
            schedulethread(thread);
        }
        this->waitqueuelock.release();
    }

    void exit(void) {
        // Thread exit.

        __atomic_store_n(&CPU::get()->currthread->tstate, Thread::state::DEAD, memory_order_release); // Kill ourselves. We will NOT be rescheduled.

        yield(); // Yield back to scheduler, so the thread never gets rescheduled.
        assert(false, "Exiting thread was rescheduled!");
    }

    void Thread::init(Process *proc, size_t stacksize, void *entry, void *arg) {
        this->process = proc;

        proc->lock.acquire();
        proc->threads.push(this);
        proc->lock.release();

        __atomic_add_fetch(&proc->threadcount, 1, memory_order_seq_cst); // Add to thread count.

        // Initialise stack within HHDM, from page allocated memory. Stacks need to be unique for each thread.
        this->stack = (uint8_t *)hhdmoff((void *)((uintptr_t)PMM::alloc(stacksize)));
        assert(this->stack, "Failed to allocate thread stack.\n");

        this->stacktop = (uint8_t *)((uintptr_t)this->stack + stacksize); // Determine stack top.

        this->stacksize = stacksize;

        // Allocate thread ID.
        this->id = __atomic_fetch_add(&this->process->tidcounter, 1, memory_order_seq_cst);

        // Zero context.
        NLib::memset(&this->ctx, 0, sizeof(this->ctx));

        // Initialise context:
#ifdef __x86_64__
        uint64_t code = this->process->kernel ? 0x08 : 0x23;
        uint64_t data = this->process->kernel ? 0x10 : 0x1b;
        this->ctx.cs = code; // Kernel Code.

        this->ctx.ds = data; // Kernel Data.
        this->ctx.es = data; // Ditto.
        this->ctx.ss = data; // Ditto.

        this->ctx.rsp = (uint64_t)this->stacktop;
        this->ctx.rip = (uint64_t)entry;
        this->ctx.rdi = (uint64_t)arg; // Pass argument in through RDI (System V ABI first argument).

        this->ctx.rflags = 0x200; // Enable interrupts.

        if (!this->process->kernel) {
            this->fctx.fpustorage = PMM::alloc(CPU::get()->fpusize);
            assert(this->fctx.fpustorage, "Failed to allocate thread's FPU storage.\n");
            this->fctx.fpustorage = NArch::hhdmoff(this->fctx.fpustorage); // Refer to via HHDM offset.
            NLib::memset(this->fctx.fpustorage, 0, CPU::get()->fpusize); // Clear memory.

            if (CPU::get()->hasxsave) {
                uint64_t cr0 = CPU::rdcr0();
                asm volatile("clts");
                // Initialise region.
                asm volatile("xsave (%0)" : : "r"(this->fctx.fpustorage), "a"(0xffffffff), "d"(0xffffffff));
                CPU::wrcr0(cr0); // Restore original CR0 (restores TS).
            }
        }
#endif
    }

    void Thread::destroy(void) {
        PMM::free(hhdmsub(this->stack), this->stacksize); // Free stack.

        this->process->lock.acquire();
        this->process->threads.remove([](Thread *t, void *arg) {
            return t == ((Thread *)arg);
        }, (void *)this);
        this->process->lock.release();

        __atomic_sub_fetch(&this->process->threadcount, 1, memory_order_seq_cst);
        if (__atomic_load_n(&this->process->threadcount, memory_order_seq_cst) == 0) {
            // Zombify the process if this was the last thread.
            this->process->zombify();
        }
    }

    void schedulethread(Thread *thread) {
        struct CPU::cpulocal *cpu = getidlest(); // The most idle CPU should be selected as the target of scheduling.
        cpu->runqueue.insert(&thread->node, vruntimecmp);
        updateload(cpu); // Update current CPU load. For load balancing and scheduling tasks.
    }

    static void idlework(void) {
        for (;;) {
            asm volatile("pause");
        }
    }

    void entry(void) {
        Thread *idlethread = new Thread(kprocess, DEFAULTSTACKSIZE, (void *)idlework); // Create new idle thread, of the kernel process.
        CPU::get()->idlethread = idlethread; // Assign to this CPU.

        CPU::get()->schedstack = (uint8_t *)PMM::alloc(16 * PAGESIZE); // Allocate scheduler stack within HHDM, point to the top of the stack for normal stack operation.

        assertarg(CPU::get()->schedstack, "Failed to allocate scheduler stack for CPU%lu.\n", CPU::get()->id);

        CPU::get()->schedstacktop = (uintptr_t)CPU::get()->schedstack + DEFAULTSTACKSIZE;

        CPU::get()->schedstack = (uint8_t *)hhdmoff((void *)((uintptr_t)CPU::get()->schedstack));

        CPU::get()->currthread = idlethread; // We start as the idle thread, even though we might not actually be running it.

        CPU::get()->lastschedts = TSC::query(); // Initialise timestamp.

        Interrupts::regisr(0xfe, schedule, true); // Register the scheduling interrupt. Mark as needing EOI, because it's through the LAPIC.

        await(); // Jump into scheduler.
    }

    bool initialised; // Is the scheduler working?

    void setup(void) {
        pidtable = new NLib::KVHashMap<size_t, Process *>();

        // Create PID 0 for kernel threading. Uses kernel address space so that the process has access to the entire memory map.
        kprocess = new Process(&VMM::kspace);
        pidtable->insert(kprocess->id, kprocess);

        Thread *idlethread = new Thread(kprocess, DEFAULTSTACKSIZE, (void *)idlework); // Create new idle thread, of the kernel process. We need not set any affinity logic, as this thread is never actually *scheduled*.

        CPU::get()->schedstack = (uint8_t *)PMM::alloc(16 * PAGESIZE); // Allocate scheduler stack within HHDM, point to the top of the stack for normal stack operation.

        assertarg(CPU::get()->schedstack, "Failed to allocate scheduler stack for CPU%lu.\n", CPU::get()->id);

        CPU::get()->schedstacktop = (uintptr_t)CPU::get()->schedstack + DEFAULTSTACKSIZE;

        CPU::get()->schedstack = (uint8_t *)hhdmoff((void *)((uintptr_t)CPU::get()->schedstack));


        CPU::get()->idlethread = idlethread; // Assign to BSP.
        CPU::get()->currthread = idlethread; // We start with the idle thread, even though we may not be using it.

        CPU::get()->lastschedts = TSC::query(); // Initialise timestamp.

        Interrupts::regisr(0xfe, schedule, true); // Register the scheduling interrupt. Mark as needing EOI, because it's through the LAPIC.
    }

    void await(void) {
        CPU::get()->setint(false);

        CPU::get()->quantumdeadline = TSC::query() + TSC::hz / 1000 * QUANTUMMS; // Set quantum deadline based on TSC.
        CPU::get()->preemptdisabled = false; // Enable preemption.
        Timer::rearm();

        CPU::get()->setint(true);

        for (;;) {
            asm volatile("hlt");
        }
    }

    extern "C" __attribute__((no_caller_saved_registers)) void sched_savesysstate(struct NArch::CPU::context *state) {
        NArch::CPU::get()->currthread->sysctx = *state;
        NArch::CPU::get()->intstatus = true;
    }

    extern "C" uint64_t sys_fork(void) {
        SYSCALL_LOG("sys_fork().\n");

        NLib::ScopeIRQSpinlock pidguard(&pidtablelock);

        Process *current = NArch::CPU::get()->currthread->process;

        NLib::ScopeIRQSpinlock guard(&current->lock);

        Process *child = new Process(VMM::forkcontext(current->addrspace), current->fdtable->fork());
        if (!child) {
            return -ENOMEM;
        }

        pidtable->insert(child->id, child);

        child->cwd = current->cwd;
        if (child->cwd) {
            child->cwd->ref(); // Add new reference.
        }

        // Clone for permissions.
        child->euid = current->euid;
        child->egid = current->egid;
        child->suid = current->suid;
        child->sgid = current->sgid;
        child->uid = current->uid;
        child->gid = current->gid;

        // Establish child<->parent relationship between processes.
        child->parent = current;
        current->children.push(child);

        child->session = current->session;
        child->pgrp = current->pgrp;

        child->pgrp->procs.push(child);

        Thread *cthread = new Thread(child, NSched::DEFAULTSTACKSIZE);
        if (!cthread) {
            return -ENOMEM;
        }

#ifdef __x86_64__
        cthread->ctx = NArch::CPU::get()->currthread->sysctx; // Initialise using system call context.

        cthread->ctx.rax = 0; // Override return to indicate this is the child.


        // Save extra contexts.
        NArch::CPU::savexctx(&cthread->xctx);
        if (NArch::CPU::get()->currthread->fctx.mathused) {
            NArch::CPU::savefctx(&cthread->fctx);
        }


#endif
        // XXX: Copy signals?

        NSched::schedulethread(cthread);

        return child->id;
    }

    extern "C" uint64_t sys_setsid(void) {
        SYSCALL_LOG("sys_setsid().\n");

        Process *current = NArch::CPU::get()->currthread->process;
        NLib::ScopeIRQSpinlock guard(&current->lock);

        current->pgrp->lock.acquire();
        if (current->pgrp->id == current->id) {
            current->pgrp->lock.release();
            return -EPERM; // Can't create a new session as group leader.
        }
        current->pgrp->lock.release();

        // We must create a new session.
        Session *session = new Session();
        if (!session) {
            return -ENOMEM;
        }
        session->id = current->id;
        session->ctty = 0;

        // And a new session needs a new process group to be connected to it.
        NSched::ProcessGroup *pgrp = new ProcessGroup();
        pgrp->id = current->id;
        pgrp->procs.push(current);
        pgrp->session = session;

        session->pgrps.push(pgrp);

        current->pgrp = pgrp;
        current->session = session;

        return session->id;
    }

    extern "C" uint64_t sys_setpgid(int pid, int pgid) {
        SYSCALL_LOG("sys_setpgid(%d, %d).\n", pid, pgid);

        if (pgid < 0) {
            return -EINVAL;
        }

        // XXX: Refcount process to prevent it from being freed during work.
        NLib::ScopeIRQSpinlock guard1(&pidtablelock);

        Process *proc = NULL;
        Process *current = NArch::CPU::get()->currthread->process;

        if (pid != 0) { // Non-zero PID means we should actually find one.
            Process **pproc = pidtable->find(pid);
            if (!pproc) {
                return -ESRCH;
            }
            proc = *pproc;
        } else { // Zero PID means we should default to our current process.
            proc = current;
        }

        NLib::ScopeIRQSpinlock guard2(&proc->lock);

        if (!(current->session == proc->session && (current == proc->parent || proc == current))) {
            return -EPERM; // We're not allowed to manipulate processes outside our session, or those where we aren't the parent of the process.
        }

        proc->pgrp->lock.acquire();
        if (proc->pgrp->id == proc->id) {
            proc->pgrp->lock.release();
            return -EPERM; // We can't set the process group of a process that is already the leader of its own process group (we'd lose reference to the process group).
        }
        proc->pgrp->lock.release();

        ProcessGroup *newpgrp = NULL;
        bool canfree = false;
        if (pgid) {
            Process **op = pidtable->find(pgid); // Attempt to find the process that leads this process group.
            if (!op) {
                return -EINVAL;
            }

            newpgrp = (*op)->pgrp;
            newpgrp->lock.acquire();
            if (newpgrp->session != proc->session) { // New process group should *also* be in the current session.
                newpgrp->lock.release();
                return -EPERM;
            }
        } else { // Zero PGID. Create a new one.
            newpgrp = new ProcessGroup();
            if (!newpgrp) {
                return -ENOMEM;
            }
            newpgrp->id = proc->id; // Make sure that this process is the leader.
            newpgrp->session = proc->session;
            canfree = true;
            newpgrp->lock.acquire();
        }

        // Only attempt to add a process that isn't currently waiting to exit (zero threads).
        if (__atomic_load_n(&proc->threadcount, memory_order_seq_cst)) {
            proc->pgrp = newpgrp; // Update process' process group (joins a new one as leader, or joins existing one).
            newpgrp->procs.push(proc);
            newpgrp->lock.release();
        } else {
            if (canfree) {
                newpgrp->lock.release();
                delete newpgrp;
            }

            return -ESRCH;
        }

        return 0;
    }

    extern "C" uint64_t sys_getpgid(int pid) {
        SYSCALL_LOG("sys_getpgid(%d).\n", pid);

        NLib::ScopeIRQSpinlock guard(&pidtablelock);

        if (!pid) {
            // Return current process' process group ID.
            return NArch::CPU::get()->currthread->process->pgrp->id;
        }

        Process **pproc = pidtable->find(pid);
        if (!pproc) {
            return -ESRCH;
        }

        Process *proc = *pproc;
        // Return the process group of whatever we found.
        return proc->pgrp->id;
    }

    extern "C" uint64_t sys_gettid(void) {
        SYSCALL_LOG("sys_gettid().\n");
        return CPU::get()->currthread->id;
    }

    extern "C" uint64_t sys_getpid(void) {
        SYSCALL_LOG("sys_getpid().\n");
        return CPU::get()->currthread->process->id;
    }

    extern "C" uint64_t sys_getppid(void) {
        SYSCALL_LOG("sys_getppid().\n");
        if (CPU::get()->currthread->process->parent) {
            return CPU::get()->currthread->process->parent->id;
        }
        return 0; // Default to no parent PID.
    }

    void handlelazyfpu(void) {
#ifdef __x86_64__
        // Lazily restore FPU context on-demand. This will also get the scheduler to store changes to our context when we swap tasks.

        uint64_t cr0 = CPU::rdcr0();
        if (cr0 & (1 << 3)) {
            asm volatile("clts"); // Clear TS.

            CPU::restorefctx(&CPU::get()->currthread->fctx); // Restore context.
            CPU::get()->currthread->fctx.mathused = true; // Mark as used, so the scheduler knows to save the context later.
            return;
        }
#endif
        assert(false, "Invalid FPU lazy load trigger!\n");
    }

    static void markdeadandremove(Thread *thread) {
        __atomic_store_n(&thread->tstate, Thread::state::DEAD, memory_order_release); // Mark thread as dead.


        struct CPU::cpulocal *cpu = NArch::SMP::cpulist[thread->cid];
        if (cpu) {
            cpu->runqueue.lock.acquire();

            if (__atomic_load_n(&thread->tstate, memory_order_acquire) == Thread::state::SUSPENDED) {
                cpu->runqueue._erase(&thread->node); // Remove from run queue.
            }

            cpu->runqueue.lock.release();
        }

        reschedule(thread); // Reschedule thread to ensure it gets cleaned up.
    }

    void termothers(Process *proc) {
        Thread *me = NArch::CPU::get()->currthread;

        proc->lock.acquire();

        NLib::DoubleList<Thread *>::Iterator it = proc->threads.begin();
        for (; it.valid(); it.next()) {
            Thread *thread = *(it.get());
            if (thread != me) {
                markdeadandremove(thread);
            }
        }

        proc->lock.release(); // Release process lock, letting dying threads proceed.

        while (__atomic_load_n(&proc->threadcount, memory_order_seq_cst) > 1) {
            yield(); // Yield until all other threads are dead.
        }
    }

    extern "C" uint64_t sys_exit(int status) {
        SYSCALL_LOG("sys_exit(%d).\n", status);

        Process *proc = NArch::CPU::get()->currthread->process;

        termothers(proc); // Terminate other threads in this process.

        {
            NLib::ScopeIRQSpinlock guard(&proc->lock);
            proc->exitstatus = (status & 0xff) << 8; // Set exit status.
        }

        exit(); // Exit.
        __builtin_unreachable();
    }

    static void freeargs(char **argv, size_t argc) {
        for (size_t i = 0; i < argc; i++) {
            delete[] argv[i];
        }
        delete[] argv;
    }

    static void freeenvs(char **envp, size_t envc) {
        for (size_t i = 0; i < envc; i++) {
            delete[] envp[i];
        }
        delete[] envp;
    }

    extern "C" uint64_t sys_execve(const char *path, char *const argv[], char *const envp[]) {
        SYSCALL_LOG("sys_execve(%s, %p, %p).\n", path, argv, envp);

        ssize_t pathlen = NMem::UserCopy::strnlen(path, 4096);
        if (pathlen <= 0) {
            return -EFAULT;
        }

        char *pathbuf = new char[pathlen + 1];
        if (!pathbuf) {
            return -ENOMEM;
        }

        ssize_t ret = NMem::UserCopy::copyfrom(pathbuf, path, pathlen + 1);
        if (ret < 0) {
            delete[] pathbuf;
            return -EFAULT;
        }
        pathbuf[pathlen] = 0; // Null terminate.


        if (!NMem::UserCopy::valid(argv, sizeof(char *))) {
            delete[] pathbuf;
            return -EFAULT;
        }

        size_t argc = 0;
        while (true) {
            if (!NMem::UserCopy::valid(&argv[argc], sizeof(char *))) {
                delete[] pathbuf;
                return -EFAULT;
            }
            if (!argv[argc]) {
                break;
            }
            argc++;
            if (argc > 4096) { // XXX: ARGMAX limit.
                delete[] pathbuf;
                return -E2BIG;
            }
        }

        char **aargv = new char *[argc + 1];
        if (!aargv) {
            delete[] pathbuf;
            return -ENOMEM;
        }
        for (size_t i = 0; i < argc; i++) {
            ssize_t arglen = NMem::UserCopy::strnlen(argv[i], 4096);
            if (arglen <= 0) {
                delete[] pathbuf;
                delete[] aargv;
                return -EFAULT;
            }

            aargv[i] = new char[arglen + 1];
            if (!aargv[i]) {
                for (size_t j = 0; j < i; j++) {
                    delete[] aargv[j];
                }
                delete[] pathbuf;
                delete[] aargv;
                return -ENOMEM;
            }

            ssize_t r = NMem::UserCopy::copyfrom(aargv[i], argv[i], arglen + 1);
            if (r < 0) {
                for (size_t j = 0; j <= i; j++) {
                    delete[] aargv[j];
                }
                delete[] pathbuf;
                delete[] aargv;
                return -EFAULT;
            }
            aargv[i][arglen] = 0; // Null terminate.
        }
        aargv[argc] = NULL; // Null terminate.

        if (!NMem::UserCopy::valid(envp, sizeof(char *))) {
            freeargs(aargv, argc);
            delete[] pathbuf;
            return -EFAULT;
        }

        // Copy envp array:
        size_t envc = 0;
        while (true) {
            if (!NMem::UserCopy::valid(&envp[envc], sizeof(char *))) {
                freeargs(aargv, argc);
                delete[] pathbuf;
                return -EFAULT;
            }
            if (!envp[envc]) {
                break;
            }
            envc++;
            if (envc > 4096) { // XXX: ARGMAX limit.
                freeargs(aargv, argc);
                delete[] pathbuf;
                return -E2BIG;
            }
        }

        char **aenvp = new char *[envc + 1];
        if (!aenvp) {
            freeargs(aargv, argc);
            delete[] pathbuf;
            return -ENOMEM;
        }
        for (size_t i = 0; i < envc; i++) {
            ssize_t envlen = NMem::UserCopy::strnlen(envp[i], 4096);
            if (envlen <= 0) {
                freeargs(aargv, argc);
                delete[] pathbuf;
                delete[] aenvp;
                return -EFAULT;
            }
            aenvp[i] = new char[envlen + 1];
            if (!aenvp[i]) {
                for (size_t j = 0; j < i; j++) {
                    delete[] aenvp[j];
                }
                freeargs(aargv, argc);
                delete[] pathbuf;
                delete[] aenvp;
                return -ENOMEM;
            }
            ssize_t r = NMem::UserCopy::copyfrom(aenvp[i], envp[i], envlen + 1);
            if (r < 0) {
                for (size_t j = 0; j <= i; j++) {
                    delete[] aenvp[j];
                }
                freeargs(aargv, argc);
                delete[] pathbuf;
                delete[] aenvp;
                return -EFAULT;
            }
            aenvp[i][envlen] = 0; // Null terminate.
        }
        aenvp[envc] = NULL; // Null terminate.


        Process *current = NArch::CPU::get()->currthread->process;
        current->lock.acquire();

        NFS::VFS::INode *inode = NFS::VFS::vfs.resolve(pathbuf, current->cwd, true);
        if (!inode) {
            current->lock.release();
            freeargs(aargv, argc);
            freeargs(aenvp, envc);
            delete[] pathbuf;
            return -ENOENT;
        }
        delete[] pathbuf;

        // Check permission against EUID/EGID.
        if (!NFS::VFS::vfs.checkaccess(inode, NFS::VFS::O_EXEC, current->euid, current->egid)) {
            inode->unref();
            current->lock.release();
            freeargs(aargv, argc);
            freeargs(aenvp, envc);
            return -EACCES;
        }
        current->lock.release();

        struct NSys::ELF::header elfhdr;
        ssize_t res = inode->read(&elfhdr, sizeof(elfhdr), 0, 0);
        if (res < (ssize_t)sizeof(elfhdr)) {
            inode->unref();
            freeargs(aargv, argc);
            freeargs(aenvp, envc);
            return -ENOEXEC;
        }

        if (!NSys::ELF::verifyheader(&elfhdr)) {
            inode->unref();
            freeargs(aargv, argc);
            freeargs(aenvp, envc);
            return -ENOEXEC;
        }

        if (elfhdr.type != NSys::ELF::ELF_EXECUTABLE) {
            inode->unref();
            freeargs(aargv, argc);
            freeargs(aenvp, envc);
            return -ENOEXEC;
        }

        struct VMM::addrspace *newspace;
        NArch::VMM::uclonecontext(&NArch::VMM::kspace, &newspace); // Start with a clone of the kernel address space.

        void *ent = NULL;
        if (!NSys::ELF::loadfile(&elfhdr, inode, newspace, &ent)) {
            inode->unref();
            freeargs(aargv, argc);
            freeargs(aenvp, envc);
            delete newspace;
            return -ENOEXEC;
        }

        if (!ent || (uintptr_t)ent >= 0x0000800000000000) {
            inode->unref();
            freeargs(aargv, argc);
            freeargs(aenvp, envc);
            delete newspace;
            return -ENOEXEC;
        }

        inode->unref();

        uintptr_t ustackphy = (uintptr_t)PMM::alloc(1 << 20); // This is the physical memory behind the stack.
        if (!ustackphy) {
            freeargs(aargv, argc);
            freeargs(aenvp, envc);
            delete newspace;
            return -ENOMEM;
        }

        uintptr_t ustacktop = 0x0000800000000000 - NArch::PAGESIZE; // Top of user space, minus a page for safety.
        uintptr_t ustackbottom = ustacktop - (1 << 20); // Virtual address of bottom of user stack (where ustackphy starts).

        void *rsp = NSys::ELF::preparestack((uintptr_t)NArch::hhdmoff((void *)(ustackphy + (1 << 20))), aargv, aenvp, &elfhdr, ustacktop);
        freeargs(aargv, argc);
        freeargs(aenvp, envc);

        if (!rsp) {
            PMM::free((void *)ustackphy, 1 << 20);
            delete newspace;
            return -ENOMEM;
        }

        // Reserve user stack region.
        newspace->vmaspace->reserve(ustackbottom, ustacktop, NMem::Virt::VIRT_NX | NMem::Virt::VIRT_RW | NMem::Virt::VIRT_USER);
        newspace->vmaspace->reserve(ustacktop, 0x0000800000000000, 0); // Guard page.

        // Map user stack.
        NArch::VMM::maprange(newspace, ustackbottom, (uintptr_t)ustackphy, NArch::VMM::NOEXEC | NArch::VMM::WRITEABLE | NArch::VMM::USER | NArch::VMM::PRESENT, 1<< 20);

        // Kill other threads and await their death.
        termothers(current);

        {
            NLib::ScopeIRQSpinlock guard(&current->lock);

            current->addrspace->lock.acquire();
            current->addrspace->ref--;
            size_t ref = current->addrspace->ref;
            current->addrspace->lock.release();
            if (ref == 0) {
                delete current->addrspace;
            }

            newspace->ref++;
            current->addrspace = newspace;

            current->fdtable->doexec(); // Close FDs with O_CLOEXEC.

            for (size_t i = 0; i < SIGMAX; i++) {
                if ( NArch::CPU::get()->currthread->signal.actions[i].handler != SIG_IGN) {
                    NArch::CPU::get()->currthread->signal.actions[i].handler = SIG_DFL; // Reset custom signal handlers.
                }
            }


            NLib::memset(&NArch::CPU::get()->currthread->ctx, 0, sizeof(NArch::CPU::get()->currthread->ctx));
#ifdef __x86_64__
            NLib::memset(&NArch::CPU::get()->currthread->xctx, 0, sizeof(NArch::CPU::get()->currthread->xctx));

            NArch::CPU::get()->currthread->ctx.cs = 0x23; // User Code.
            NArch::CPU::get()->currthread->ctx.ds = 0x1b; // User Data.
            NArch::CPU::get()->currthread->ctx.es = 0x1b; // Ditto.
            NArch::CPU::get()->currthread->ctx.ss = 0x1b; // Ditto.

            NArch::CPU::get()->currthread->ctx.rip = (uint64_t)ent;
            NArch::CPU::get()->currthread->ctx.rsp = (uint64_t)rsp;
            NArch::CPU::get()->currthread->ctx.rflags = 0x200; // Enable interrupts.


            NLib::memset(NArch::CPU::get()->currthread->fctx.fpustorage, 0, CPU::get()->fpusize);
            NArch::CPU::get()->currthread->fctx.mathused = false; // Mark as unused.

            if (CPU::get()->hasxsave) {
                uint64_t cr0 = CPU::rdcr0();
                asm volatile("clts");
                // Initialise region.
                asm volatile("xsave (%0)" : : "r"(NArch::CPU::get()->currthread->fctx.fpustorage), "a"(0xffffffff), "d"(0xffffffff));
                CPU::wrcr0(cr0); // Restore original CR0 (restores TS).
            }
#endif

        }
        NArch::VMM::swapcontext(newspace);
        NArch::CPU::ctx_swap(&NArch::CPU::get()->currthread->ctx); // Context switch to new entry point.

        __builtin_unreachable();
    }

    #define WNOHANG     1 // Don't block.
    #define WUNTRACED   2 // Report stopped children.

    static Process *findchild(Process *parent, int pid, bool zombie) {
        NLib::DoubleList<Process *>::Iterator it = parent->children.begin();
        for (; it.valid(); it.next()) {
            Process *child = *(it.get());

            bool match = false;

            child->lock.acquire();
            if (child->pstate != Process::state::ZOMBIE && zombie) {
                child->lock.release();
                continue; // Wanted zombies.
            }

            if (pid == -1) { // Any child.
                match = true;
            } else if (pid > 0) { // Specific PID.
                if (child->id == (size_t)pid) {
                    match = true;
                }
            } else if (pid == 0) { // Any child in our process group.
                if (child->pgrp == parent->pgrp) {
                    match = true;
                }
            } else { // Negative PID means any child in process group -pid.
                if (child->pgrp->id == (size_t)(-pid)) {
                    match = true;
                }
            }

            child->lock.release();

            if (match) {
                return child;
            }
        }
        return NULL;
    }

    extern "C" uint64_t sys_waitpid(int pid, int *status, int options) {
        SYSCALL_LOG("sys_waitpid(%d, %p, %d).\n", pid, status, options);

        if (status && !NMem::UserCopy::valid(status, sizeof(int))) {
            return -EFAULT;
        }

        Process *current = NArch::CPU::get()->currthread->process;
        current->lock.acquire();

        // Check if we have any children that match.
        bool haschildren = findchild(current, pid, false) != NULL;

        if (!haschildren) {
            current->lock.release();
            return -ECHILD; // No matching children.
        }

        Process *zombie = NULL;

        if (options & WNOHANG) {
            // Non-blocking wait.
            zombie = findchild(current, pid, true);
            if (!zombie) {
                current->lock.release();
                return 0; // No matching zombies.
            }
        } else {
            // Blocking wait.
            waiteventlocked(&current->exitwq,
                (zombie = findchild(current, pid, true)) != NULL,
                &current->lock);
        }

        zombie->lock.acquire();
        int zstatus = zombie->exitstatus;
        size_t zid = zombie->id;

        if (status) {
            // Copy status out.
            if (NMem::UserCopy::copyto(status, &zstatus, sizeof(int)) < 0) {
                zombie->lock.release();
                current->lock.release();
                return -EFAULT;
            }
        }

        zombie->pstate = Process::state::DEAD;
        zombie->lock.release();
        current->lock.release();

        delete zombie; // Reap process.

        return zid;
    }
}
