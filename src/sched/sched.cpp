#ifdef __x86_64__
#include <arch/x86_64/apic.hpp>
#include <arch/x86_64/cpu.hpp>
#include <arch/x86_64/smp.hpp>
#include <arch/x86_64/tsc.hpp>
#endif
#include <fs/devfs.hpp>
#include <lib/assert.hpp>
#include <mm/slab.hpp>
#include <sched/sched.hpp>

namespace NSched {
    using namespace NArch;

    void RBTree::_insert(struct node *node, int (*cmp)(struct node *, struct node *)) {

        struct node **newnode = &this->root;
        struct node *parent = NULL;

        while (*newnode) { // Breaks when we reach a undefined path (we can put our node here!).
            parent = *newnode;
            newnode = cmp(node, parent) < 0 ? &parent->left : &parent->right; // Use comparison function to determine what path we should be traversing.
        }

        node->packparent(parent);
        *newnode = node;
        node->left = NULL;
        node->right = NULL;
        node->packcolour(colour::RED);

        if (parent) {
            if (!parent->getparent()) { // Get grandparent.
                this->rebalance(node);
            }
        } else {
            node->packcolour(colour::BLACK);
        }

        // Increment cached count.
        __atomic_add_fetch(&this->nodecount, 1, memory_order_seq_cst);
    }

    void RBTree::_erase(struct node *node) {
        struct node *child = NULL;
        struct node *parent = NULL;

        enum colour colour;

        if (!node->left) {
            child = node->right;
        } else if (!node->right) {
            child = node->left;
        } else {
            struct node *successor = this->_next(node);
            colour = successor->getcolour();

            child = successor->right;
            parent = successor->getparent();

            if (child) {
                child->packparent(parent);
            }

            // Link to right.
            if (parent != node) {
                parent->left = child;
                successor->right = node->right;
                node->right->packparent(successor);
            }

            // Replace node.
            successor->parent = node->parent;
            successor->left = node->left;
            node->left->packparent(successor);
            successor->packcolour(node->getcolour()); // Preserve original colour.

            if (node == this->root) { // If the successor is the root.
                this->root = successor;
            } else {
                *(node == node->getparent()->left ? &node->getparent()->left : &node->getparent()->right) = successor;
            }

            if (colour == colour::BLACK) {
                this->reerase(child, parent);
            }

            // Decrement cached count.
            __atomic_sub_fetch(&this->nodecount, 1, memory_order_seq_cst);
            return;
        }

        parent = node->getparent();
        colour = node->getcolour();
        if (child) {
            child->packparent(parent);
        }

        if (parent) {
            *(node == parent->left ? &parent->left : &parent->right) = child;
        } else {
            this->root = child;
        }

        if (colour == colour::BLACK) {
            this->reerase(child, parent);
        }

        // Decrement cached count.
        __atomic_sub_fetch(&this->nodecount, 1, memory_order_seq_cst);
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

    void RBTree::rebalance(struct node *node) {

        while (node != this->root && node->getparent()->getcolour() == colour::RED) {
            struct node *gparent = node->getparent()->getparent();
            if (node->getparent() == gparent->left) { // Left case.
                struct node *uncle = gparent->right;

                if (uncle->getcolour() == colour::RED) { // RED->RED
                    node->getparent()->packcolour(colour::BLACK);
                    node->packcolour(colour::BLACK);
                    gparent->packcolour(colour::RED);
                    node = gparent;
                } else {
                    if (node == node->getparent()->right) {
                        node = node->getparent();
                        this->rotateleft(node);
                    }
                    node->getparent()->packcolour(colour::BLACK);
                    gparent->packcolour(colour::RED);
                    this->rotateright(gparent);
                }
            } else { // Right case.
                struct node *uncle = gparent->left;

                if (uncle->getcolour() == colour::RED) { // RED->RED
                    node->getparent()->packcolour(colour::BLACK);
                    node->packcolour(colour::BLACK);
                    gparent->packcolour(colour::RED);
                    node = gparent;
                } else {
                    if (node == node->getparent()->left) {
                        node = node->getparent();
                        this->rotateright(node);
                    }
                    node->getparent()->packcolour(colour::BLACK);
                    gparent->packcolour(colour::RED);
                    this->rotateleft(gparent);
                }
            }
        }

        this->root->packcolour(colour::BLACK);
    }

    void RBTree::reerase(struct node *child, struct node *parent) {
        while (child != this->root && (!child || child->getcolour() == colour::BLACK)) {
            if (!parent) {
                break;
            }

            bool isleft = child == parent->left;
            struct node *sibling = isleft ? parent->right : parent->left;
            if (!sibling) {
                break;
            }

            // Sibling is red.
            if (sibling->getcolour() == colour::RED) {
                sibling->packcolour(colour::BLACK);
                parent->packcolour(colour::RED);
                isleft ? this->rotateleft(parent) : this->rotateright(parent);
                sibling = isleft ? parent->right : parent->left;
                if (!sibling) {
                    break;
                }
            }

            // Sibling and nephews are black.
            if ((!sibling->left || sibling->left->getcolour() == colour::BLACK) &&
                (!sibling->right || sibling->right->getcolour() == colour::BLACK)) {

                sibling->packcolour(colour::RED);
                child = parent;
                parent = child->getparent();
                continue;
            }

            if (isleft) {
                // Outer nephew is black.
                if (!sibling->right || sibling->right->getcolour() == colour::BLACK) {

                    if (sibling->left) {
                        sibling->left->packcolour(colour::BLACK);
                    }
                    sibling->packcolour(colour::RED);
                    this->rotateright(sibling);
                    sibling = parent->right;
                }
            } else {
                // Outer nephew is black.
                if (!sibling->left || sibling->left->getcolour() == colour::BLACK) {

                    if (sibling->right) {
                        sibling->right->packcolour(colour::BLACK);
                    }
                    sibling->packcolour(colour::RED);
                    this->rotateleft(sibling);
                    sibling = parent->left;
                }
            }

            // Final rebalance.
            if (sibling) {
                sibling->packcolour(parent->getcolour());
                parent->packcolour(colour::BLACK);

                if (isleft && sibling->right) {
                    sibling->right->packcolour(colour::BLACK);
                } else if (!isleft && sibling->left) {
                    sibling->left->packcolour(colour::BLACK);
                }

                isleft ? this->rotateleft(parent) : this->rotateright(parent);
            }
            child = this->root;
            break;
        }

        if (child) {
            child->packcolour(colour::BLACK);
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
        uint64_t maxload = 0;
        struct CPU::cpulocal *busiest = NULL;
        uint64_t ourload = __atomic_load_n(&CPU::get()->loadweight, memory_order_seq_cst);

        for (size_t i = 0; i < SMP::awakecpus; i++) {
            // Atomically load the load of the CPU. We want to be avoiding using spinlocks, so we don't occupy the instance's state.
            uint64_t load = __atomic_load_n(&SMP::cpulist[i]->loadweight, memory_order_seq_cst);

            if (load > maxload && load > ourload + STEALTHRESHOLD) { // If this is the biggest load thus far, *AND* exceeds our threshold, we'll keep this in mind for stealing from.
                maxload = load; // Update maximum load thus far, for comparison against others.
                busiest = SMP::cpulist[i]; // Thus far, this is our busiest CPU.
            }
        }

        return busiest;
    }

    // Attempts to locate the most idle CPU. This is used for scheduling, and for the target of load balancing.
    static struct CPU::cpulocal *getidlest(void) {
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
    }

    // Get a hold of a thread from the busiest CPU, migrating it (but not adding it to the new run queue).
    Thread *steal(void) {
        struct CPU::cpulocal *busiest = getstealbusiest(); // Get a handle on the busiest CPU.

        busiest = NULL;
        if (!busiest) {
            return NULL; // We're done here, there's nothing we can do.
        }

        busiest->runqueue.lock.acquire(); // We have multiple things we want to be doing, and don't want any race conditions during our work.
        struct RBTree::node *node = busiest->runqueue._last(); // Grab node that is the last to be run (typically, higher virtual runtime).
        if (!node) {
            busiest->runqueue.lock.release();
            return NULL; // We're done here, only one node is in the run queue (it's probably running right now, even).
        }
        Thread *stolen = RBTree::getentry<Thread>(node);
        busiest->runqueue._erase(node); // Remove this node from the list.
        busiest->runqueue.lock.release();

        stolen->cid = CPU::get()->id; // Update CID.
        return stolen; // XXX: Worry about the steal() function stealing from a thread that is referencing a different CPU during operation. Solution: Only steal non-suspended threads.
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

#endif
        __atomic_store_n(&thread->tstate, Thread::state::RUNNING, memory_order_release); // Set state.


        CPU::restorexctx(&thread->xctx); // Restore extra context.
        CPU::ctx_swap(&thread->ctx); // Restore context.

        __builtin_unreachable();
    }

    // Scheduler interrupt entry, handles save.
    void schedule(struct Interrupts::isr *isr, struct CPU::context *ctx) {
        (void)isr;

        APIC::lapicstop(); // Prevent double schedule by stopping any running timer.

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

        {
            NLib::ScopeSpinlock guard(&cpu->runqueue.lock); // Lock run queue, so we can gather and remove the next thread.
            if (prev != cpu->idlethread) {
                if (__atomic_load_n(&prev->tstate, memory_order_acquire) == Thread::state::RUNNING) { // Thread is still "runnable".

                    __atomic_store_n(&prev->tstate, Thread::state::SUSPENDED, memory_order_release);
                    cpu->runqueue._insert(&prev->node, vruntimecmp); // Shove it back onto the run queue for this CPU. It'll be ran later.
                }
            }

            next = nextthread(); // Get the next task to schedule. It'll return NULL if we have nothing to do.
            assert(next != cpu->idlethread, "Next thread should NEVER be the idle thread (it is not supposed to be in the run queue).\n");

            if (prev != next && prev != cpu->idlethread) {
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
                delete prev; // Destroy old thread. XXX: Defer?
            }

            APIC::lapiconeshot(QUANTUMMS * 1000, 0xfe);

            switchthread(next, needswap); // Swap to context.
        }

        __atomic_store_n(&next->tstate, Thread::state::RUNNING, memory_order_release); // Set state.


        // We haven't changed anything. We were just given our old thread, this happens most commonly when running the idle thread.
        // It'd be a waste to attempt to context switch when we're working on the same code.

        APIC::lapiconeshot(QUANTUMMS * 1000, 0xfe);

        // If it's the same thread, we'll just be dumped right back to where we are.
    }


    static size_t pidcounter = 0;
    Process *kprocess = NULL; // Kernel process.

    void Process::init(struct VMM::addrspace *space, NFS::VFS::FileDescriptorTable *fdtable) {
        // Each new process should be initialised with an atomically incremented PID.
        this->id = __atomic_add_fetch(&pidcounter, 1, memory_order_seq_cst);
        this->addrspace = space;
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

    Process::~Process(void) {

        // Dereference address space and free it if there's nothing on it.

        this->addrspace->lock.acquire();
        this->addrspace->ref--;
        size_t ref = this->addrspace->ref;
        this->addrspace->lock.release();

        if (ref == 0) {
            delete this->addrspace;
        }
    }

    void yield(void) {
        APIC::lapicstop(); // Stop currently running timer.

        CPU::get()->setint(true);

        // Artificially induce a schedule interrupt, using a "loopback" IPI.
        APIC::sendipi(CPU::get()->lapicid, 0xfe, APIC::IPIFIXED, APIC::IPIPHYS, APIC::IPISELF);

        // At this point, we've either been rescheduled (if we were running) or marked dead.
    }

    void Mutex::acquire(void) {
#ifdef __x86_64__
        while (__sync_lock_test_and_set(&this->locked, 1)) {
#endif
            __atomic_store_n(&NArch::CPU::get()->currthread->tstate, Thread::state::WAITING, memory_order_release);
            assert(NArch::CPU::get()->currthread != NArch::CPU::get()->idlethread, "Mutex on idle thread.\n");
            this->waitqueuelock.acquire();
            this->waitqueue.pushback(NArch::CPU::get()->currthread);
            this->waitqueuelock.release();
            yield(); // Yield into suspend.
            // We're back, try to reacquire, and if we CAN, we're out!
        }
    }

    void Mutex::release(void) {
#ifdef __x86_64__
        __sync_lock_release(&this->locked);
#endif
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

        // Initialise stack within HHDM, from page allocated memory. Stacks need to be unique for each thread.
        this->stack = (uint8_t *)hhdmoff((void *)((uintptr_t)PMM::alloc(stacksize)));
        assert(this->stack, "Failed to allocate thread stack.\n");

        this->stacktop = (uint8_t *)((uintptr_t)this->stack + stacksize); // Determine stack top.

        this->stacksize = stacksize;

        // Allocate thread ID.
        this->id = __atomic_add_fetch(&pidcounter, 1, memory_order_seq_cst);

        // Zero context.
        NLib::memset(&this->ctx, 0, sizeof(this->ctx));

        // Initialise context:
#ifdef __x86_64__
        // XXX: These would be different segments for userspace:

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
            this->xctx.fpustorage = PMM::alloc(CPU::get()->fpusize);
            assert(this->xctx.fpustorage, "Failed to allocate thread's FPU storage.\n");
            this->xctx.fpustorage = NArch::hhdmoff(this->xctx.fpustorage); // Refer to via HHDM offset.
            NLib::memset(this->xctx.fpustorage, 0, CPU::get()->fpusize); // Clear memory.

            this->xctx.mathused = true;

            if (CPU::get()->hasxsave) {
                // Initialise region.
                asm volatile("xsave (%0)" : : "r"(this->xctx.fpustorage), "a"(0xffffffff), "d"(0xffffffff));
            }
        }
#endif
    }

    void Thread::destroy(void) {
        PMM::free(hhdmsub(this->stack)); // Free stack.
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

        CPU::get()->schedstack = (uint8_t *)hhdmoff((void *)((uintptr_t)PMM::alloc(16 * PAGESIZE))); // Allocate scheduler stack within HHDM, point to the top of the stack for normal stack operation.
        CPU::get()->schedstacktop = (uintptr_t)CPU::get()->schedstack + DEFAULTSTACKSIZE;
        assertarg(CPU::get()->schedstack, "Failed to allocate scheduler stack for CPU%lu.\n", CPU::get()->id);

        CPU::get()->currthread = idlethread; // We start as the idle thread, even though we might not actually be running it.

        CPU::get()->lastschedts = TSC::query(); // Initialise timestamp.

        Interrupts::regisr(0xfe, schedule, true); // Register the scheduling interrupt. Mark as needing EOI, because it's through the LAPIC.

        await(); // Jump into scheduler.
    }

    void setup(void) {
        // Create PID 0 for kernel threading. Uses kernel address space so that the process has access to the entire memory map.
        kprocess = new Process(&VMM::kspace);

        Thread *idlethread = new Thread(kprocess, DEFAULTSTACKSIZE, (void *)idlework); // Create new idle thread, of the kernel process. We need not set any affinity logic, as this thread is never actually *scheduled*.

        CPU::get()->schedstack = (uint8_t *)hhdmoff((void *)((uintptr_t)PMM::alloc(16 * PAGESIZE))); // Allocate scheduler stack within HHDM, point to the top of the stack for normal stack operation.
        CPU::get()->schedstacktop = (uintptr_t)CPU::get()->schedstack + DEFAULTSTACKSIZE;
        assertarg(CPU::get()->schedstack, "Failed to allocate scheduler stack for CPU%lu.\n", CPU::get()->id);


        CPU::get()->idlethread = idlethread; // Assign to BSP.
        CPU::get()->currthread = idlethread; // We start with the idle thread, even though we may not be using it.

        CPU::get()->lastschedts = TSC::query(); // Initialise timestamp.

        Interrupts::regisr(0xfe, schedule, true); // Register the scheduling interrupt. Mark as needing EOI, because it's through the LAPIC.
    }

    void await(void) {
        CPU::get()->setint(false);

        APIC::lapiconeshot(QUANTUMMS * 1000, 0xfe);

        CPU::get()->setint(true);

        for (;;) {
            asm volatile("hlt");
        }
    }

    extern "C" uint64_t sys_exit(int status) {
        NUtil::printf("Exit %d.\n", status);
        exit(); // Exit.
        return 0;
    }
}
