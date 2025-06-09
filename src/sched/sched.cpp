#include <arch/x86_64/cpu.hpp>
#include <arch/x86_64/smp.hpp>
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

/*
    struct RBTree::node *RBTree::_sibling(struct node *node) {
        if (!node->getparent()) {
            return NULL;
        }

        if (node->getparent()->left == node) {
            return node->getparent()->right;
        }
        return node->getparent()->left;
    }

    void RBTree::_erase(struct node *node) {
        struct node *successor = NULL;

        if (node->left && node->right) {
            successor = this->_next(node->right);
        }

        if (!node->left && !node->right) {
            successor =  NULL;
        }

        if (node->left) {
            successor = node->left;
        } else {
            successor = node->right;
        }

        bool bothblack = ((!successor || successor->getcolour() == colour::BLACK) && (node->getcolour() == colour::BLACK));

        struct node *parent = node->getparent();

        if (!successor) {
            if (node == this->root) {
                this->root = NULL;
            } else {
                if (bothblack) {
                    this->fixblackblack(node);
                } else {
                    if (this->_sibling(node)) {
                        this->_sibling(node)->packcolour(colour::RED);
                    }
                }

                // Unreference whatever side on the parent.
                if (node->getparent()->left == node) {
                    node->getparent()->left = NULL;
                } else {
                    node->getparent()->right = NULL;
                }
            }
            // Decrement cached count.
            __atomic_sub_fetch(&this->nodecount, 1, memory_order_seq_cst);
            return;
        }

        if (!node->left || !node->right) {
            if (node == this->root) {
                // Update successor, override reference.
                *(node == node->getparent()->left ? &node->getparent()->left : &node->getparent()->right) = successor;
                node->left = NULL;
                node->right = NULL;
            } else {
                if (node->getparent()->left == node) {
                    node->getparent()->left = successor;
                } else {
                    node->getparent()->right = successor;
                }

                successor->packparent(node->getparent());

                if (bothblack) {
                    this->fixblackblack(successor);
                } else {
                    successor->packcolour(colour::BLACK);
                }
            }
            // Decrement cached count.
            __atomic_sub_fetch(&this->nodecount, 1, memory_order_seq_cst);
            return;
        }

        struct node *old = successor;
        *(successor == successor->getparent()->left ? &successor->getparent()->left : &successor->getparent()->right) = node;
        *(node == node->getparent()->left ? &node->getparent()->left : &node->getparent()->right) = old;


        this->_erase(successor);

decrement:
        // Decrement cached count.
        __atomic_sub_fetch(&this->nodecount, 1, memory_order_seq_cst);
    }
*/

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
            y->getparent()->left = y;
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

        if (node->right) { // If we have a right branch, we want to be traversing it to find the final node.
            node = node->right;
            while (node->left) {
                node = node->left;
            }
            return node;
        }

        struct node *parent = node->getparent(); // Get parent of node.
        while (parent && node == parent->right) { // While we can continue to traverse, and the node is the right branch.
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
    static CPU::CPUInst *getstealbusiest(void) {
        uint64_t maxload = 0;
        CPU::CPUInst *busiest = NULL;
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
    static CPU::CPUInst *getidlest(void) {
        uint64_t minload = __UINT64_MAX__; // Start at theoretical maximum, so any lower load will be chosen first.
        CPU::CPUInst *idlest = NULL;

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

    void updateload(CPU::CPUInst *cpu) {
        size_t num = cpu->runqueue.count();
        // Weighted load balancing calculation, considering the number of active tasks.
        // __atomic_store_n(&cpu->loadweight,
            // (__atomic_load_n(&cpu->loadweight, memory_order_seq_cst)
            // * 3 + num * 1024) / 4,
        // memory_order_seq_cst);
        __atomic_store_n(&cpu->loadweight,
            num,
        memory_order_seq_cst);
    }

    void loadbalance(CPU::CPUInst *cpu) {
        if (cpu->runqueue.count() <= LOADTHRESHOLD) {
            return; // We're done here.
        }
    }

    // Get a hold of a thread from the busiest CPU, migrating it (but not adding it to the new run queue).
    Thread *steal(void) {
        CPU::CPUInst *busiest = getstealbusiest(); // Get a handle on the busiest CPU.

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
        return stolen;
    }

    Thread *nextthread(void) {
        struct RBTree::node *node = CPU::get()->runqueue.first(); // Get the node with the least virtual runtime (this could mean *either* that it has higher priority, or just hasn't run for very long yet).
        if (node) {
            return RBTree::getentry<Thread>(node);
        }

        return steal(); // We have no work, try to steal something from another CPU.
    }

    void switchthread(Thread *thread) {

        Thread *prev = CPU::get()->currthread;

        CPU::get()->currthread = thread; // Update current thread.

        assert(prev, "Previous thread before context switch should *never* be NULL.\n");
        if (prev->process->addrspace != thread->process->addrspace) { // If we need to change address space, change it. We don't want to be swapping contexts if we can help it (expensive TLB flush).
            VMM::swapcontext(thread->process->addrspace); // Swap to VMM context.
        }

#ifdef __x86_64__
        CPU::get()->intstatus = thread->ctx.rflags & 0x200; // Restore the interrupt status of the thread.
        CPU::get()->ist.rsp0 = (uint64_t)thread->stacktop; // Point to top of stack, this is for the TSS.
#endif
        thread->tstate = Thread::state::RUNNING; // Set state.


        CPU::ctx_swap(&thread->ctx); // Restore context.

        // __builtin_unreachable();
    }

#include <arch/x86_64/io.hpp>

    // Scheduler interrupt entry, handles save.
    void schedule(struct Interrupts::isr *isr, struct CPU::context *ctx) {
        (void)isr;
        NArch::outb(0xe9, 'S');

        CPU::CPUInst *cpu = CPU::get(); // Get an easy local reference to our current CPU.

        assert(cpu, "Failed to acquire current CPU.\n");

        cpu->setint(false); // Disable interrupts, we don't want our scheduling work to be interrupted.

        size_t curintr = __atomic_add_fetch(&cpu->schedintr, 1, memory_order_seq_cst); // Increment the number of times this interrupt has been called.

        assert(cpu->currthread, "Current thread should NEVER be NULL.\n");

        cpu->currthread->setvruntime(QUANTUMMS); // Update virtual runtime, using the delta since apprx. last timer interrupt.

        updateload(cpu); // Update current CPU load. For load balancing and scheduling tasks.

        // Load Balance on an interval:
        if (curintr % 4) { // Every fourth schedule interrupt:
            loadbalance(cpu);
        }

        Thread *prev = cpu->currthread; // Currently running thread.
        Thread *next = NULL; // What we're planning to schedule next.

        if (prev->tstate == Thread::state::RUNNING && prev != cpu->idlethread) { // Thread is still "runnable", and it's not the idle thread (WE NEVER WANT TO SCHEDULE THE IDLE THREAD.)

            prev->tstate = Thread::state::SUSPENDED; // Dumped back into running queue.
            cpu->runqueue.insert(&prev->node, vruntimecmp); // Shove it back onto the run queue for this CPU. It'll be ran later.
        }

        next = nextthread(); // Get the next task to schedule. It'll return NULL if we have nothing to do.
        assert(next != cpu->idlethread, "Next thread should NEVER be the idle thread (it is not supposed to be in the run queue).\n");

        if (!next) {
            next = cpu->idlethread; // We have NO work, and can't steal ANY others. Default to idle thread until next schedule().
        }

        prev->lastcid = cpu->id; // Update the previous thread's old CPU ID.
        next->cid = cpu->id; // Update new thread's current CPU ID.

        if (prev != next) { // We need to context switch.
            prev->savectx(ctx); // Use the interrupt context to override the save state of the previous thread.

            cpu->runqueue.erase(&next->node); // Remove what we're scheduling from the run queue, so that it doesn't get load balanced onto something else (which can happen, if it's the only node in the run queue and last() is called), or stolen by another CPU.


            const char *digits = "0123456789";
            NArch::outb(0xe9, digits[next->id % 10]);
            APIC::lapiconeshot(QUANTUMMS * 1000, 0xfe);
            switchthread(next); // Swap to context.
        }

        cpu->runqueue.erase(&next->node);
        next->tstate = Thread::state::RUNNING;

        // We haven't changed anything. We were just given our old thread, this happens most commonly when running the idle thread.
        // It'd be a waste to attempt to context switch when we're working on the same code.

        cpu->setint(true); // Simply just restore initial interrupt state, and move on with our lives.

        APIC::lapiconeshot(QUANTUMMS * 1000, 0xfe);
        // XXX: Consider: With userspace, we'd still have to make sure to restore the userspace context as we move back into ring 3.

        // If it's the same thread, we'll just be dumped right back to where we are.
    }


    static size_t pidcounter = 0;
    Process *kprocess = NULL; // Kernel process.

    Process::Process(struct VMM::addrspace *space) {
        // Each new process should be initialised with an atomically incremented PID.
        this->id = __atomic_add_fetch(&pidcounter, 1, memory_order_seq_cst);
        this->addrspace = space;
    }

    Process::~Process(void) {

        // Dereference address space and free it if there's nothing on it.

        this->addrspace->lock.acquire();
        this->addrspace->ref--;
        size_t ref = this->addrspace->ref;
        this->addrspace->lock.release();

        if (ref == 0) {
            NMem::allocator.free(this->addrspace);
        }
    }

    void Thread::init(Process *proc, size_t stacksize, void *entry) {
        this->process = proc;

        // Initialise stack within HHDM, from page allocated memory. Stacks need to be unique for each thread.
        this->stack = (uint8_t *)hhdmoff((void *)((uintptr_t)PMM::alloc(stacksize) + stacksize));
        assert(this->stack, "Failed to allocate thread stack.\n");

        this->stacktop = (uint8_t *)((uintptr_t)this->stack + stacksize); // Determine stack top.

        this->stacksize = stacksize;

        // Allocate thread ID.
        this->id = __atomic_add_fetch(&pidcounter, 1, memory_order_seq_cst);

        // Initialise context:
#ifdef __x86_64__
        // XXX: These would be different segments for userspace:

        this->ctx.cs = 0x08; // Kernel Code.

        this->ctx.ds = 0x10; // Kernel Data.
        this->ctx.es = 0x10; // Ditto.
        this->ctx.ss = 0x10; // Ditto.

        this->ctx.rsp = (uint64_t)this->stacktop;
        this->ctx.rip = (uint64_t)entry;

        this->ctx.rflags = 0x200; // Enable interrupts.
#endif
    }

    void Thread::destroy(void) {
        PMM::free(hhdmsub(this->stack)); // Free stack.
    }

    void schedulethread(Thread *thread) {
        CPU::CPUInst *cpu = getidlest(); // The most idle CPU should be selected as the target of scheduling.
        cpu->runqueue.insert(&thread->node, vruntimecmp);
        // updateload(cpu); // Update current CPU load. For load balancing and scheduling tasks.
    }

    static void idlework(void) {
        for (;;) {
            MARKER;
            asm volatile("int $0xfe");
            // asm volatile("hlt");
        }
    }

    void entry(void) {
        Thread *idlethread = new Thread(kprocess, DEFAULTSTACKSIZE, (void *)idlework); // Create new idle thread, of the kernel process.
        idlethread->setaffinity(CPU::get()->id); // Prefer this current CPU. Later target mode settings will enforce this preference.
        idlethread->settmode(Thread::target::STRICT); // Prevent load balancing migrations.
        idlethread->setnice(19); // Lowest priority.

        CPU::get()->idlethread = idlethread; // Assign to this CPU.

        CPU::get()->schedstack = (uint8_t *)hhdmoff((void *)((uintptr_t)PMM::alloc(16 * PAGESIZE) + 16 * PAGESIZE)); // Allocate scheduler stack within HHDM, point to the top of the stack for normal stack operation.
        assertarg(CPU::get()->schedstack, "Failed to allocate scheduler stack for CPU%lu.\n", CPU::get()->id);

        CPU::get()->currthread = idlethread; // We start as the idle thread, even though we might not actually be running it.

        Interrupts::regisr(0xfe, schedule, true); // Register the scheduling interrupt. Mark as needing EOI, because it's through the LAPIC.

        await(); // Jump into scheduler.
    }

    void setup(void) {
        // Create PID 0 for kernel threading. Uses kernel address space so that the process has access to the entire memory map.
        kprocess = new Process(&VMM::kspace);

        Thread *idlethread = new Thread(kprocess, DEFAULTSTACKSIZE, (void *)idlework); // Create new idle thread, of the kernel process. We need not set any affinity logic, as this thread is never actually *scheduled*, per se.

        CPU::get()->idlethread = idlethread; // Assign to BSP.
        CPU::get()->currthread = idlethread; // We start with the idle thread, even though we may not be using it.

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
}
