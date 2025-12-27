#ifdef __x86_64__
#include <arch/x86_64/apic.hpp>
#include <arch/x86_64/cpu.hpp>
#include <arch/x86_64/e9.hpp>
#include <arch/x86_64/smp.hpp>
#include <arch/x86_64/stacktrace.hpp>
#include <arch/x86_64/tsc.hpp>
#include <arch/x86_64/timer.hpp>
#endif
#include <fs/devfs.hpp>
#include <lib/assert.hpp>
#include <mm/slab.hpp>
#include <mm/ucopy.hpp>
#include <sched/event.hpp>
#include <sched/sched.hpp>
#include <sys/clock.hpp>
#include <sys/elf.hpp>
#include <sys/syscall.hpp>
#include <sys/timer.hpp>

// NOTE: Lock ordering:
// - When acquiring multiple locks, always acquire in this order to prevent deadlocks:
// 1. pidtablelock
// 2. proc->lock
// 3. session->lock
// 4. runqueue.lock (ordered by CPU ID)
// 5. waitqueue.waitinglock
// 6. thread->waitingonlock
// 7. zombielock

namespace NSched {
    using namespace NArch;

    static int vruntimecmp(struct RBTree::node *a, struct RBTree::node *b);

    // Global zombie list for deferred thread cleanup.
    static NArch::IRQSpinlock zombielock;
    static Thread *zombiehead = NULL;

    // Comparison function for insertion logic.
    static int vruntimecmp(struct RBTree::node *a, struct RBTree::node *b) {
        // Get references to threads from Red-Black tree nodes.
        Thread *ta = RBTree::getentry<Thread>(a);
        Thread *tb = RBTree::getentry<Thread>(b);

        // Compare virtual runtimes of threads.
        uint64_t va = ta->getvruntime();
        uint64_t vb = tb->getvruntime();
        if (va != vb) {
            return (va < vb) ? -1 : 1;
        }
        // When virtual runtimes are equal, we should use the thread ID to figure out the order.
        return (ta->id < tb->id) ? -1 : 1;
    }

    // Locked enqueue, expects state to already be set.
    static void enqueuethread(struct CPU::cpulocal *cpu, Thread *thread) {
        assert(thread != cpu->idlethread, "Cannot enqueue idle thread.\n");
        cpu->runqueue.lock.acquire();
        cpu->runqueue._insert(&thread->node, vruntimecmp);
        cpu->runqueue.lock.release();
    }

    // Caller must hold the runqueue lock.
    static Thread *dequeuethread_locked(struct CPU::cpulocal *cpu) {
        struct RBTree::node *node = cpu->runqueue._first();
        if (!node) {
            return NULL;
        }
        cpu->runqueue._erase(node);
        return RBTree::getentry<Thread>(node);
    }

    // Process any dead threads in the zombie list.
    static void reapzombies(void) {
        if (!__atomic_load_n(&zombiehead, memory_order_acquire)) {
            return; // What? No head?
        }

        zombielock.acquire();
        Thread *zombie = zombiehead;
        zombiehead = NULL;
        zombielock.release();

        while (zombie) {
            Thread *next = zombie->nextzombie;
            zombie->nextzombie = NULL;
            delete zombie;
            zombie = next;
        }
    }

    // Queue a thread for deferred deletion.
    static void queuezombie(Thread *thread) {
        zombielock.acquire();
        thread->nextzombie = zombiehead;
        zombiehead = thread;
        zombielock.release();
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
        // Use exponential moving average for smoother load tracking.
        uint64_t oldload = __atomic_load_n(&cpu->loadweight, memory_order_acquire);
        uint64_t newload = (oldload * 3 + num * 1024) / 4;
        __atomic_store_n(&cpu->loadweight, newload, memory_order_release);
    }

    void loadbalance(struct CPU::cpulocal *cpu) {
        size_t count = cpu->runqueue.count();
        if (count <= LOADTHRESHOLD) {
            return; // We're done here.
        }

        // Migrate our tasks to other CPUs to mitigate load.
        struct CPU::cpulocal *target = getidlest();
        if (!target || cpu == target) { // Don't try to load balance to ourselves! We'd just end up deadlocking.
            return;
        }

        // Only proceed if target actually has less load.
        if (__atomic_load_n(&target->loadweight, memory_order_acquire) >=
            __atomic_load_n(&cpu->loadweight, memory_order_acquire)) {
            return;
        }

        size_t quota = (count - LOADTHRESHOLD) / 4; // Target should be given a quarter of our work.
        if (quota == 0) {
            return;
        }

        // Lock ordering to prevent cyclic deadlocks.
        if (cpu->id < target->id) {
            cpu->runqueue.lock.acquire();
            target->runqueue.lock.acquire();
        } else {
            target->runqueue.lock.acquire();
            cpu->runqueue.lock.acquire();
        }

        struct RBTree::node *node = cpu->runqueue._last();
        size_t migrated = 0;
        while (node && migrated < quota) { // If we have work to migrate, and a quota to fulfill, keep working.
            Thread *candidate = RBTree::getentry<Thread>(node);
            struct RBTree::node *prev = cpu->runqueue._prev(node);

            // Check if thread is eligible for migration and must not have unsaved FPU context (mathused indicates pending save).
            enum Thread::state tstate = (enum Thread::state)__atomic_load_n(&candidate->tstate, memory_order_acquire);
            if (tstate != Thread::state::SUSPENDED ||
                __atomic_load_n(&candidate->locksheld, memory_order_acquire) > 0 ||
                candidate->migratedisabled ||
                candidate->fctx.mathused) { // Don't migrate threads with potentially unsaved FPU state.
                node = prev; // Skip nodes we can't migrate.
                continue;
            }

            cpu->runqueue._erase(node);
            candidate->lastcid = candidate->cid;
            candidate->cid = target->id;
            NArch::CPU::writemb(); // Ensure writes are seen before insertion.
            target->runqueue._insert(node, vruntimecmp);
            migrated++;

            node = prev;
        }

        // Release locks in reverse order of acquisition.
        if (cpu->id < target->id) {
            target->runqueue.lock.release();
            cpu->runqueue.lock.release();
        } else {
            cpu->runqueue.lock.release();
            target->runqueue.lock.release();
        }

        if (migrated > 0) { // Only bother updating load if we actually did anything.
            updateload(target);
            updateload(cpu);
        }
    }

    // Attempt to steal work from a busier CPU.
    static Thread *steal(void) {
        struct CPU::cpulocal *busiest = getstealbusiest();

        if (!busiest || busiest == CPU::get()) {
            return NULL;
        }

        Thread *stolen = NULL;
        busiest->runqueue.lock.acquire();

        // Try to find a stealable thread from the back (highest vruntime = least urgent).
        struct RBTree::node *node = busiest->runqueue._last();
        while (node) {
            Thread *candidate = RBTree::getentry<Thread>(node);
            enum Thread::state tstate = (enum Thread::state)__atomic_load_n(&candidate->tstate, memory_order_acquire);

            // Only steal threads that are actually waiting to run and can be migrated.
            // Also check mathused to avoid stealing threads with potentially unsaved FPU state.
            if (tstate == Thread::state::SUSPENDED &&
                __atomic_load_n(&candidate->locksheld, memory_order_acquire) == 0 &&
                !candidate->migratedisabled &&
                !candidate->fctx.mathused) { // Don't steal threads with potentially unsaved FPU state.
                busiest->runqueue._erase(node);
                stolen = candidate;
                break;
            }
            node = busiest->runqueue._prev(node);
        }

        busiest->runqueue.lock.release();

        if (stolen) {
            updateload(busiest);
            stolen->lastcid = stolen->cid;
            stolen->cid = CPU::get()->id;
        }

        return stolen;
    }

    // Get the next thread to run from the current CPU's runqueue.
    static Thread *_nextthread(struct CPU::cpulocal *cpu) {
        struct RBTree::node *node = cpu->runqueue._first();
        while (node) {
            Thread *candidate = RBTree::getentry<Thread>(node);
            struct RBTree::node *next = cpu->runqueue._next(node);

            enum Thread::state tstate = (enum Thread::state)__atomic_load_n(&candidate->tstate, memory_order_acquire);

            // Skip and clean up dead threads.
            if (tstate == Thread::state::DEAD) {
                cpu->runqueue._erase(node);
                queuezombie(candidate);
                node = next;
                continue;
            }

            // Found a runnable thread.
            if (tstate == Thread::state::SUSPENDED) {
                cpu->runqueue._erase(node);
                return candidate;
            }

            // Thread is in unexpected state, skip it.
            node = next;
        }
        return NULL;
    }

    Thread *nextthread(void) {
        struct CPU::cpulocal *cpu = CPU::get();
        cpu->runqueue.lock.acquire();
        Thread *next = _nextthread(cpu);
        cpu->runqueue.lock.release();

        if (!next) {
            next = steal(); // Try to steal from another CPU.
        }
        return next;
    }

    // Perform the actual context switch to a new thread.
    static void switchthread(Thread *thread, bool needswap) {
        Thread *prev = CPU::get()->currthread;
        CPU::get()->currthread = thread;

        assert(prev, "Previous thread before context switch should *never* be NULL.\n");

        if (needswap) {
            swaptopml4(thread->process->addrspace->pml4phy);
        }

#ifdef __x86_64__
        CPU::get()->intstatus = thread->ctx.rflags & 0x200; // Restore the interrupt status of the thread.
        CPU::get()->ist.rsp0 = (uint64_t)thread->stacktop;

        thread->fctx.mathused = false; // Start thread not having used maths (so we don't *have* to save the context during this quantum, unless the thread uses the FPU in this time).
        uint64_t cr0 = CPU::rdcr0();
        cr0 |= (1 << 3); // Set TS bit for lazy FPU restore.
        CPU::wrcr0(cr0);
#endif
        __atomic_store_n(&thread->tstate, Thread::state::RUNNING, memory_order_release); // Set state.

        CPU::restorexctx(&thread->xctx); // Restore extra context.
        CPU::ctx_swap(&thread->ctx); // Restore context.

        uint64_t rsp = 0;
        __asm__ volatile("mov %%rsp, %0" : "=r"(rsp) : : "memory");


        Thread *current = CPU::get()->currthread;

        // Swap to thread->stacktop for safe error handling.
        __asm__ volatile(
            "mov %0, %%rsp\n"
            "sub $128, %%rsp\n" // Allocate a bit of stack space to avoid issues with immediate errors.
            :
            : "r"(current->stacktop)
            : "memory"
        );

        NUtil::printf("Context switch returned unexpectedly!\n");

        if (current != thread) {
            NUtil::printf("Context switch unreachable reached is to a thread that we did not switch to!.\n");
        }

        Process *proc = current->process;
        NUtil::printf("Unreachable reached occurred in thread %u of process %u.\n", current->id, proc->id);
        NUtil::printf("Printing stack trace of thread that returned:\n");
        printstacktrace(current->ctx.rbp);
        NUtil::printf("Register state:\n");
        NUtil::printf("RIP: 0x%016lx RSP: 0x%016lx RFLAGS: 0x%016lx\n", current->ctx.rip, current->ctx.rsp, current->ctx.rflags);
        NUtil::printf("RAX: 0x%016lx RBX: 0x%016lx RCX: 0x%016lx RDX: 0x%016lx\n", current->ctx.rax, current->ctx.rbx, current->ctx.rcx, current->ctx.rdx);
        NUtil::printf("RSI: 0x%016lx RDI: 0x%016lx RBP: 0x%016lx\n", current->ctx.rsi, current->ctx.rdi, current->ctx.rbp);
        NUtil::printf("R8:  0x%016lx R9:  0x%016lx R10: 0x%016lx R11: 0x%016lx\n", current->ctx.r8, current->ctx.r9, current->ctx.r10, current->ctx.r11);
        NUtil::printf("R12: 0x%016lx R13: 0x%016lx R14: 0x%016lx R15: 0x%016lx\n", current->ctx.r12, current->ctx.r13, current->ctx.r14, current->ctx.r15);

        NUtil::printf("Current register state:\n");
        uint64_t rax, rbx, rcx, rdx, rsi, rdi, rbp, rip, rflags;
        __asm__ volatile(
            "mov %%rax, %0\n"
            "mov %%rbx, %1\n"
            "mov %%rcx, %2\n"
            "mov %%rdx, %3\n"
            "mov %%rsi, %4\n"
            "mov %%rdi, %5\n"
            "mov %%rbp, %6\n"
            "leaq (%%rip), %%rax\n"
            "mov %%rax, %7\n"
            "pushfq\n"
            "pop %8\n"
            : "=r"(rax), "=r"(rbx), "=r"(rcx), "=r"(rdx), "=r"(rsi), "=r"(rdi), "=r"(rbp), "=r"(rip), "=r"(rflags)
            :
            : "memory"
        );
        NUtil::printf("RIP: 0x%016lx RSP: 0x%016lx RFLAGS: 0x%016lx\n", rip, rsp, rflags);
        NUtil::printf("RAX: 0x%016lx RBX: 0x%016lx RCX: 0x%016lx RDX: 0x%016lx\n", rax, rbx, rcx, rdx);
        NUtil::printf("RSI: 0x%016lx RDI: 0x%016lx RBP: 0x%016lx\n", rsi, rdi, rbp);
        NUtil::printf("R8:  0x%016lx R9:  0x%016lx R10: 0x%016lx R11: 0x%016lx\n", current->ctx.r8, current->ctx.r9, current->ctx.r10, current->ctx.r11);
        NUtil::printf("R12: 0x%016lx R13: 0x%016lx R14: 0x%016lx R15: 0x%016lx\n", current->ctx.r12, current->ctx.r13, current->ctx.r14, current->ctx.r15);

        __builtin_unreachable();
    }

    // Check and fire ITIMER_REAL for a process if it has expired.
    static void checkitimer(Process *proc, uint64_t now) {
        if (proc->itimerdeadline == 0) {
            return; // Timer not armed.
        }

        if (now >= proc->itimerdeadline) {
            signalproc(proc, SIGALRM); // Send SIGALRM to the process.

            // Reload or disarm timer.
            if (proc->itimerintv > 0) {
                uint64_t ticks = (proc->itimerintv * TSC::hz) / 1000000;
                proc->itimerdeadline = now + ticks;
            } else {
                proc->itimerdeadline = 0;
            }
        }
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

        // Calculate time delta since last schedule.
        uint64_t now = TSC::query();
        uint64_t delta = ((now - cpu->lastschedts) * 1000) / TSC::hz;
        cpu->lastschedts = now;

        Thread *prev = cpu->currthread;

        // Update vruntime for the current thread (unless it's the idle thread).
        if (prev != cpu->idlethread) {
            prev->setvruntime(delta);
        }

        updateload(cpu);

        // Periodic zombie cleanup and load balancing.
        cpu->setint(true); // Enable interrupts for TLB shootdown handling.
        reapzombies();
        cpu->setint(false);

        if ((curintr % 4) == 0) {
            loadbalance(cpu);
        }

        // Check interval timers for the current process.
        if (prev && prev->process && !prev->process->kernel) {
            checkitimer(prev->process, now);
        }

        // Handle migration re-enable on reschedule request.
        if (prev->rescheduling) {
            __atomic_store_n(&prev->rescheduling, false, memory_order_release);
            prev->enablemigrate();
        }

        Thread *next = NULL;

        bool shouldsave = prev && prev != cpu->idlethread;

        if (shouldsave) {
#ifdef __x86_64__
            if (prev->fctx.mathused) {
                CPU::savefctx(&prev->fctx);
            }
#endif
            prev->savexctx();
            prev->savectx(ctx);
        }

        // Memory barrier to ensure context writes are visible before state transition.
        NArch::CPU::writemb();

        cpu->runqueue.lock.acquire();

        // Re-enqueue previous thread if it was running (not idle, not dead, not waiting).
        if (prev != cpu->idlethread) {
            enum Thread::pendingwait pendwait = (enum Thread::pendingwait)__atomic_load_n(&prev->pendingwaitstate, memory_order_acquire);

            // Handle pending wait state transitions using CAS to avoid race with markdeadandremove().
            if (pendwait != Thread::pendingwait::PENDING_NONE) {
                // Determine target state based on pending wait type.
                enum Thread::state targetstate = (pendwait == Thread::pendingwait::PENDING_WAIT)
                    ? Thread::state::WAITING : Thread::state::WAITINGINT;

                // Use CAS to transition RUNNING -> WAITING/WAITINGINT.
                enum Thread::state expected = Thread::state::RUNNING;
                if (__atomic_compare_exchange_n(&prev->tstate, &expected, targetstate, false, memory_order_acq_rel, memory_order_acquire)) {
                    // Successfully transitioned to waiting state.
                    __atomic_store_n(&prev->pendingwaitstate, Thread::pendingwait::PENDING_NONE, memory_order_release);
                } else if (expected == Thread::state::DEAD) {
                    // Thread was marked dead by another CPU, queue for cleanup.
                    __atomic_store_n(&prev->pendingwaitstate, Thread::pendingwait::PENDING_NONE, memory_order_release);
                    queuezombie(prev);
                    prev = NULL;
                }
            } else {
                enum Thread::state expected = Thread::state::RUNNING;
                if (__atomic_compare_exchange_n(&prev->tstate, &expected, Thread::state::SUSPENDED, false, memory_order_acq_rel, memory_order_acquire)) {
                    // Successfully transitioned to SUSPENDED, enqueue.
                    NArch::CPU::writemb();
                    cpu->runqueue._insert(&prev->node, vruntimecmp);
                } else if (expected == Thread::state::DEAD) {
                    // Thread was marked dead, queue for cleanup.
                    queuezombie(prev);
                    prev = NULL;
                }
            }
        }

        // Get next thread from runqueue.
        next = _nextthread(cpu);
        cpu->runqueue.lock.release();

        // If no thread available locally, try to steal.
        if (!next) {
            next = steal();
        }

        // Use idle thread if still no work.
        if (!next) {
            next = cpu->idlethread;
        }

        assert(next != NULL, "Next thread is NULL.\n");

        // Update CPU tracking.
        if (prev) {
            prev->lastcid = cpu->id;
        }
        __atomic_store_n(&next->cid, cpu->id, memory_order_release);

        // Perform context switch if needed.
        if (prev != next) {
            bool needswap = !prev || (prev->process->addrspace != next->process->addrspace);

            cpu->quantumdeadline = TSC::query() + (TSC::hz / 1000) * QUANTUMMS;
            Timer::rearm();

            switchthread(next, needswap); // Swap to context.
        }

        __atomic_store_n(&next->tstate, Thread::state::RUNNING, memory_order_release); // Set state.

        cpu->quantumdeadline = TSC::query() + (TSC::hz / 1000) * QUANTUMMS;
        Timer::rearm();
        cpu->setint(true);
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

        // Initialize signal state to defaults (no pending, all handlers SIG_DFL).
        this->signalstate.pending = 0;
        for (size_t i = 0; i < NSIG; i++) {
            this->signalstate.actions[i].handler = SIG_DFL;
            this->signalstate.actions[i].mask = 0;
            this->signalstate.actions[i].flags = 0;
            this->signalstate.actions[i].restorer = NULL;
        }

        if (space == &VMM::kspace) {
            this->kernel = true; // Mark process as a kernel process if it uses the kernel address space.
        } else { // Only userspace threads should bother creating file descriptor tables.
            if (!fdtable) {
                this->fdtable = new NFS::VFS::FileDescriptorTable();
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
        this->addrspace->lock.release();

        if (ref == 0) {
            delete this->addrspace;
        }

        this->pstate = Process::state::ZOMBIE;

        Process *parent = this->parent;

        // Release our lock before waking parent and sending SIGCHLD to avoid deadlock.
        this->lock.release();

        if (parent) {
            // Wake parent's exit wait queue so it can reap us.
            // WARNING: After wake(), parent may delete us on another CPU.
            // Do not access 'this' after wake()!
            parent->exitwq.wake();

            // Send SIGCHLD to parent per POSIX: signal sent when child terminates.
            signalproc(parent, SIGCHLD);
        }
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

            if (this->pgrp->procs.empty()) {
                if (this->session) {
                    this->session->lock.acquire();
                    this->session->pgrps.remove([](ProcessGroup *pg, void *arg) {
                        return pg == ((ProcessGroup *)arg);
                    }, (void *)this->pgrp);
                    this->session->lock.release();

                    if (this->session->pgrps.empty()) {
                        delete this->session;
                    }
                }
                this->pgrp->lock.release();
                delete this->pgrp;
                this->pgrp = NULL;
                this->session = NULL;
            } else {
                this->pgrp->lock.release();
            }


        }

        if (this->parent) {
            this->parent->lock.acquire();
            this->parent->children.remove([](Process *p, void *arg) {
                return p == ((Process *)arg);
            }, (void *)this);
            this->parent->lock.release();
            // Note: SIGCHLD was already sent in zombify() when child terminated.
        }

        pidtablelock.acquire();
        NSched::Process **pinitproc = pidtable->find(1); // Get init process.
        assert(pinitproc, "Failed to find init process during process destruction.\n");
        Process *initproc = *pinitproc;
        pidtablelock.release();

        if (children.size() && this != initproc) {
            NLib::DoubleList<Process *>::Iterator it = this->children.begin();
            for (; it.valid(); it.next()) {
                Process *child = *(it.get());
                child->lock.acquire();

                initproc->lock.acquire();
                child->parent = initproc; // Reparent to init.
                initproc->children.push(child);
                initproc->lock.release();

                // Notify init of reparenting, so it can reap if needed.
                signalproc(initproc, SIGCHLD);

                child->lock.release();
            }
        }

        this->lock.release();
    }

    // Request that a specific thread be rescheduled.
    void reschedule(Thread *thread) {
        // Prevent migration during the reschedule operation.
        thread->disablemigrate();
        __atomic_store_n(&thread->rescheduling, true, memory_order_release);

        // Read the CID after setting rescheduling flag to ensure consistency.
        NArch::CPU::readmb();
        size_t targetcid = __atomic_load_n(&thread->cid, memory_order_acquire);

        // Bounds check the CPU ID.
        if (targetcid >= NArch::SMP::awakecpus) {
            thread->enablemigrate();
            return;
        }

        struct CPU::cpulocal *targetcpu = NArch::SMP::cpulist[targetcid];
        if (targetcpu) {
            // Send IPI to trigger reschedule on the target CPU.
            APIC::sendipi(targetcpu->lapicid, 0xfe, APIC::IPIFIXED, APIC::IPIPHYS, 0);
        }
    }

    // Voluntarily yield the CPU to another thread.
    // The current thread will be placed back in the runqueue.
    void yield(void) {
        struct CPU::cpulocal *cpu = CPU::get();
        Thread *self = cpu->currthread;

        // Safety checks: cannot yield from idle thread or if scheduler not initialized.
        if (!initialised || self == cpu->idlethread) {
            return;
        }

        // Disable interrupts to prevent races during yield setup.
        // This ensures atomic setup of yield state.
        bool oldint = cpu->setint(false);

        // Mark that this thread is requesting a reschedule.
        __atomic_store_n(&self->rescheduling, true, memory_order_release);

        // Memory barrier to ensure rescheduling flag is visible.
        CPU::writemb();

        // Stop timer to prevent racing timer interrupt during yield.
        APIC::lapicstop();

        enum Thread::state currentstate = (enum Thread::state)__atomic_load_n(&self->tstate, memory_order_acquire);

        if (currentstate == Thread::state::DEAD) {
            for (;;) {
                asm volatile(
                    "sti\n\t"          // Enable interrupts (required for int to work properly)
                    "int $0xfe\n\t"    // Synchronously invoke scheduler
                    "cli\n\t"          // Should never reach here, but disable if we do
                    : : : "memory"
                );
            }
            __builtin_unreachable();
        }

        APIC::sendipi(cpu->lapicid, 0xfe, APIC::IPIFIXED, APIC::IPIPHYS, APIC::IPISELF);
        //asm volatile("int $0xfe\n\t" : : : "memory");

        // Enable interrupts so the IPI can be delivered.
        cpu->setint(true);

        // Wait for the scheduler to process our yield request.
        while (__atomic_load_n(&self->rescheduling, memory_order_acquire)) {
            asm volatile(
                "sti\n\t"
                "hlt\n\t"
                : : : "memory"
            );
        }

        // Restore original interrupt state.
        cpu->setint(oldint);

        enum Thread::state exitstate = (enum Thread::state)__atomic_load_n(&self->tstate, memory_order_acquire);
        if (exitstate == Thread::state::DEAD) {
            panic("yield() returned for dead thread");
        }
    }

    struct sleepstate { // Simple helper struct that avoids UAF.
        WaitQueue wq;
        bool completed; // Set to true when thread wakes (either by timer or signal).
        NArch::Spinlock lock;
    };

    // Timer callback for sleep().
    static void sleepwork(void *arg) {
        struct sleepstate *state = (struct sleepstate *)arg;

        state->lock.acquire();
        if (!state->completed) { // Only bother waking if not already completed (interrupted by signal).
            state->completed = true;
            state->lock.release();
            state->wq.wakeone(); // Wake the sleeping thread.
        } else {
            // Thread was interrupted and marked completed. We can't assume it's still around, so just cleanup.
            state->lock.release();
            delete state;
        }
    }

    int sleep(uint64_t ms) {
        if (ms == 0) {
            return 0;
        }

        // Allocate sleep state on heap so it survives even if we wake early.
        struct sleepstate *state = new sleepstate();
        state->completed = false;

        NSys::Timer::timerlock();
        NSys::Timer::create(sleepwork, state, ms);
        NSys::Timer::timerunlock();

        // Wait interruptibly. If a signal arrives, this will return -EINTR.
        int ret = state->wq.waitinterruptible();

        // Mark that we've completed (either by signal or timer).
        state->lock.acquire();
        if (!state->completed) {
            // Mark completed so timer callback knows to cleanup.
            state->completed = true;
            state->lock.release();
        } else {
            // Timer woke us up normally. We cleanup.
            state->lock.release();
            delete state;
        }

        return ret;
    }

    // XXX: Only guaranteed millisecond precision, as we convert from timespec to milliseconds.
    extern "C" ssize_t sys_sleep(struct NSys::Clock::timespec *req, struct NSys::Clock::timespec *rem) {
        SYSCALL_LOG("sys_sleep(%p, %p)\n", req, rem);

        if (!req) {
            SYSCALL_RET(-EFAULT);
        }

        // Copy timespec from userspace.
        struct NSys::Clock::timespec kreq;
        if (NMem::UserCopy::copyfrom(&kreq, req, sizeof(struct NSys::Clock::timespec)) < 0) {
            SYSCALL_RET(-EFAULT);
        }

        // Validate timespec.
        if (kreq.tv_sec < 0 || kreq.tv_nsec < 0 || kreq.tv_nsec >= NSys::Clock::NSEC_PER_SEC) {
            SYSCALL_RET(-EINVAL);
        }

        // Convert to milliseconds, rounding up.
        uint64_t ms = (uint64_t)kreq.tv_sec * NSys::Clock::MSEC_PER_SEC;
        uint64_t ns_to_ms = (kreq.tv_nsec + 999999) / 1000000; // Round up nanoseconds to milliseconds.
        ms += ns_to_ms;

        // Record start time if we need to compute remaining time.
        struct NSys::Clock::timespec start_time;
        if (rem) {
            NSys::Clock::Clock *clock = NSys::Clock::getclock(NSys::Clock::CLOCK_MONOTONIC);
            if (clock && clock->gettime(&start_time) < 0) {
                SYSCALL_RET(-EFAULT);
            }
        }

        // Perform sleep.
        int ret = sleep(ms);

        // If interrupted and rem is provided, calculate remaining time.
        if (ret == -EINTR && rem) {
            struct NSys::Clock::timespec end_time;
            NSys::Clock::Clock *clock = NSys::Clock::getclock(NSys::Clock::CLOCK_MONOTONIC);
            if (clock && clock->gettime(&end_time) == 0) {
                // Calculate elapsed time in nanoseconds.
                uint64_t elapsed_ns = ((uint64_t)end_time.tv_sec * NSys::Clock::NSEC_PER_SEC + (uint64_t)end_time.tv_nsec) -
                                      ((uint64_t)start_time.tv_sec * NSys::Clock::NSEC_PER_SEC + (uint64_t)start_time.tv_nsec);

                // Calculate requested time in nanoseconds.
                uint64_t requested_ns = (uint64_t)kreq.tv_sec * NSys::Clock::NSEC_PER_SEC + (uint64_t)kreq.tv_nsec;

                // Calculate remaining time.
                uint64_t remaining_ns = (elapsed_ns < requested_ns) ? (requested_ns - elapsed_ns) : 0;

                struct NSys::Clock::timespec krem;
                krem.tv_sec = remaining_ns / NSys::Clock::NSEC_PER_SEC;
                krem.tv_nsec = remaining_ns % NSys::Clock::NSEC_PER_SEC;

                if (NMem::UserCopy::copyto(rem, &krem, sizeof(struct NSys::Clock::timespec)) < 0) {
                    // If we can't copy the remaining time, we still return -EINTR.
                    // POSIX allows this behavior.
                }
            }
        }

        SYSCALL_RET(ret);
    }

    void Mutex::acquire(void) {
        Thread *current = NArch::CPU::get()->currthread;
        assert(current != NArch::CPU::get()->idlethread, "Mutex acquire on idle thread.\n");

        while (true) {
#ifdef __x86_64__
            // Try to acquire the lock with a simple atomic exchange.
            if (__atomic_exchange_n(&this->locked, 1, memory_order_acquire) == 0) {
                break; // Got the lock (it was previously unlocked).
            }
#endif

            // Lock is contended, wait on the waitqueue.
            this->waitqueue.waitinglock.acquire();

            // Double-check the lock is still held after acquiring waitqueue lock.
#ifdef __x86_64__
            if (__atomic_exchange_n(&this->locked, 1, memory_order_acquire) == 0) {
                this->waitqueue.waitinglock.release();
                break; // Got the lock.
            }
#endif

            // Use the WaitQueue's wait mechanism with lock already held.
            this->waitqueue.wait(true);
        }

        __atomic_add_fetch(&current->locksheld, 1, memory_order_seq_cst);
    }

    void Mutex::release(void) {
        Thread *current = NArch::CPU::get()->currthread;
        __atomic_sub_fetch(&current->locksheld, 1, memory_order_seq_cst);
#ifdef __x86_64__
        __atomic_store_n(&this->locked, 0, memory_order_release);
#endif

        // Wake one waiting thread, if any (next in line).
        this->waitqueue.wakeone();
    }

    void exit(int status, int sig) {
        // Thread exit.

        Process *proc = NArch::CPU::get()->currthread->process;

        if (!proc->kernel) { // Only perform process exit logic on user threads.

            if (proc->id == 1) {
                panic("Init got obliterated (either by itself or someone else).\n");
            }

            termothers(proc); // Terminate other threads in this process.

            {
                NLib::ScopeIRQSpinlock guard(&proc->lock);
                if (sig != 0) {
                    // If we're exiting due to a signal, encode that in exit status.
                    proc->exitstatus = (sig & 0x7f);
                } else { // Normal exit.
                    proc->exitstatus = (status & 0xff) << 8;
                }

            }
        }

        __atomic_store_n(&CPU::get()->currthread->tstate, Thread::state::DEAD, memory_order_release); // Kill ourselves. We will NOT be rescheduled.
        CPU::writemb();

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

        // Initialize per-thread signal mask to 0 (no signals blocked).
        this->blocked = 0;

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

        this->ctx.rflags = 0x202; // Enable interrupts.

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
        // Free FPU storage if allocated.
#ifdef __x86_64__
        if (!this->process->kernel && this->fctx.fpustorage) {
            PMM::free(hhdmsub(this->fctx.fpustorage), CPU::get()->fpusize);
            this->fctx.fpustorage = NULL;
        }
#endif

        PMM::free(hhdmsub(this->stack), this->stacksize); // Free stack.

        this->process->lock.acquire();
        this->process->threads.remove([](Thread *t, void *arg) {
            return t == ((Thread *)arg);
        }, (void *)this);
        this->process->lock.release();

        size_t remaining = __atomic_sub_fetch(&this->process->threadcount, 1, memory_order_seq_cst);
        if (remaining == 0) {
            // Zombify the process if this was the last thread.
            this->process->zombify();
        }
    }

    // Schedule a thread for execution on the most idle CPU.
    void schedulethread(Thread *thread) {

        // Attempt to transition thread from current state to SUSPENDED state with CAS atomic operation, aborting if thread is marked DEAD.
        enum Thread::state expected = (enum Thread::state)__atomic_load_n(&thread->tstate, memory_order_acquire);
        while (true) {
            if (expected == Thread::state::DEAD) {
                return; // Thread is dead, do not schedule.
            }

            if (expected == Thread::state::SUSPENDED) {
                return; // Thread is already in a runqueue, do not double-enqueue.
            }

            if (expected == Thread::state::RUNNING) {
                return; // Thread is currently running, do not re-enqueue.
            }

            if (__atomic_compare_exchange_n(&thread->tstate, &expected, Thread::state::SUSPENDED, false, memory_order_acq_rel, memory_order_acquire)) {
                break; // Successfully transitioned to SUSPENDED.
            }
        }

        NArch::CPU::writemb();

        // Find the most idle CPU for this thread.
        struct CPU::cpulocal *cpu = getidlest();
        if (!cpu) {
            cpu = CPU::get(); // Fallback to current CPU.
        }

        __atomic_store_n(&thread->cid, cpu->id, memory_order_release);
        NArch::CPU::writemb();

        enqueuethread(cpu, thread);
        updateload(cpu);

        // If the target CPU is idle, send an IPI to wake it up.
        // This ensures the thread gets scheduled promptly.
        if (cpu != CPU::get() && cpu->runqueue.count() == 1) {
            APIC::sendipi(cpu->lapicid, 0xfe, APIC::IPIFIXED, APIC::IPIPHYS, 0);
        }
    }

    static void idlework(void) {
        for (;;) {
            asm volatile("hlt");
        }
    }

    void entry(void) {
        Thread *idlethread = new Thread(kprocess, DEFAULTSTACKSIZE, (void *)idlework); // Create new idle thread, of the kernel process.
        CPU::get()->idlethread = idlethread; // Assign to this CPU.

        // Mark idle thread specially - it should never be in a runqueue.
        idlethread->tstate = Thread::state::RUNNING;

        CPU::get()->schedstack = (uint8_t *)PMM::alloc(16 * PAGESIZE);
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

        Thread *idlethread = new Thread(kprocess, DEFAULTSTACKSIZE, (void *)idlework);
        idlethread->tstate = Thread::state::RUNNING; // Idle thread is always "running".

        CPU::get()->schedstack = (uint8_t *)PMM::alloc(16 * PAGESIZE); // Allocate scheduler stack within HHDM, point to the top of the stack for normal stack operation.

        assertarg(CPU::get()->schedstack, "Failed to allocate scheduler stack for CPU%lu.\n", CPU::get()->id);

        CPU::get()->schedstacktop = (uintptr_t)CPU::get()->schedstack + DEFAULTSTACKSIZE;
        CPU::get()->schedstack = (uint8_t *)hhdmoff((void *)((uintptr_t)CPU::get()->schedstack));

        CPU::get()->idlethread = idlethread;
        CPU::get()->currthread = idlethread;
        CPU::get()->lastschedts = TSC::query();

        Interrupts::regisr(0xfe, schedule, true); // Register the scheduling interrupt. Mark as needing EOI, because it's through the LAPIC.

        initialised = true; // Mark the scheduler as ready.
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
        NArch::CPU::get()->currthread->sysctx = state;
        NArch::CPU::get()->intstatus = true;
    }

    extern "C" uint64_t sys_fork(void) {
        SYSCALL_LOG("sys_fork().\n");

        NLib::ScopeIRQSpinlock pidguard(&pidtablelock);

        Process *current = NArch::CPU::get()->currthread->process;

        NLib::ScopeIRQSpinlock guard(&current->lock);

        Process *child = new Process(VMM::forkcontext(current->addrspace), current->fdtable->fork());
        if (!child) {
            SYSCALL_RET(-ENOMEM);
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
        child->umask = current->umask;

        // Establish child<->parent relationship between processes.
        child->parent = current;
        current->children.push(child);

        child->session = current->session;
        child->pgrp = current->pgrp;

        // Add to process group with proper locking.
        {
            NLib::ScopeIRQSpinlock pgrpguard(&child->pgrp->lock);
            child->pgrp->procs.push(child);
        }

        Thread *cthread = new Thread(child, NSched::DEFAULTSTACKSIZE);
        if (!cthread) {
            // Clean up child process on thread allocation failure.
            child->pgrp->lock.acquire();
            child->pgrp->procs.remove([](Process *p, void *arg) {
                return p == ((Process *)arg);
            }, (void *)child);
            child->pgrp->lock.release();
            current->children.remove([](Process *p, void *arg) {
                return p == ((Process *)arg);
            }, (void *)child);
            if (child->cwd) {
                child->cwd->unref();
            }
            pidtable->remove(child->id);
            delete child;
            SYSCALL_RET(-ENOMEM);
        }

#ifdef __x86_64__
        cthread->ctx = *NArch::CPU::get()->currthread->sysctx; // Initialise using system call context.

        cthread->ctx.rax = 0; // Override return to indicate this is the child.


        // Save extra contexts.
        NArch::CPU::savexctx(&cthread->xctx);
        if (NArch::CPU::get()->currthread->fctx.mathused) {
            NArch::CPU::savefctx(&cthread->fctx);
        }


#endif

        for (size_t i = 0; i < NSIG; i++) {
            // Inherit handlers.
            child->signalstate.actions[i] = current->signalstate.actions[i];
        }
        child->signalstate.pending = 0; // Pending signals are NOT inherited.
        cthread->blocked = __atomic_load_n(&NArch::CPU::get()->currthread->blocked, memory_order_acquire); // Copy calling thread's signal mask to child thread.

        NSched::schedulethread(cthread);

        SYSCALL_RET(child->id);
    }

    extern "C" uint64_t sys_setsid(void) {
        SYSCALL_LOG("sys_setsid().\n");

        Process *current = NArch::CPU::get()->currthread->process;
        NLib::ScopeIRQSpinlock guard(&current->lock);

        ProcessGroup *oldpgrp = current->pgrp;
        oldpgrp->lock.acquire();
        if (oldpgrp->id == current->id) {
            oldpgrp->lock.release();
            SYSCALL_RET(-EPERM); // Can't create a new session as group leader.
        }
        oldpgrp->lock.release();

        // We must create a new session.
        Session *session = new Session();
        if (!session) {
            SYSCALL_RET(-ENOMEM);
        }
        session->id = current->id;
        session->ctty = 0;

        // And a new session needs a new process group to be connected to it.
        NSched::ProcessGroup *pgrp = new ProcessGroup();
        if (!pgrp) {
            delete session;
            SYSCALL_RET(-ENOMEM);
        }
        pgrp->id = current->id;
        pgrp->procs.push(current);
        pgrp->session = session;

        session->pgrps.push(pgrp);

        // Remove from old process group and clean up if empty.
        bool shoulddeleteoldpgrp = false;
        Session *oldsession = NULL;
        {
            NLib::ScopeIRQSpinlock oldpgrpguard(&oldpgrp->lock);
            oldpgrp->procs.remove([](Process *p, void *arg) {
                return p == ((Process *)arg);
            }, (void *)current);

            if (oldpgrp->procs.empty()) {
                shoulddeleteoldpgrp = true;
                oldsession = oldpgrp->session;
                if (oldsession) {
                    NLib::ScopeIRQSpinlock sessionguard(&oldsession->lock);
                    oldsession->pgrps.remove([](ProcessGroup *pg, void *arg) {
                        return pg == ((ProcessGroup *)arg);
                    }, (void *)oldpgrp);
                }
            }
        }
        if (shoulddeleteoldpgrp) {
            delete oldpgrp;
        }

        current->pgrp = pgrp;
        current->session = session;

        SYSCALL_RET(session->id);
    }

    extern "C" uint64_t sys_setpgid(int pid, int pgid) {
        SYSCALL_LOG("sys_setpgid(%d, %d).\n", pid, pgid);

        Process *current = NArch::CPU::get()->currthread->process;

        NLib::ScopeIRQSpinlock pidguard(&pidtablelock);

        if (pid == 0) { // PID 0 means us.
            pid = current->id;
        }

        if (pid < 0) {
            SYSCALL_RET(-EINVAL);
        }

        if (pgid == 0) { // PGID 0 means use pid as pgid.
            pgid = pid;
        }

        // Negative pgid is invalid.
        if (pgid < 0) {
            SYSCALL_RET(-EINVAL);
        }

        // Find the target process.
        Process **ptarget = pidtable->find(pid);
        if (!ptarget) {
            SYSCALL_RET(-ESRCH); // No such process.
        }
        Process *target = *ptarget;

        NLib::ScopeIRQSpinlock targetguard(&target->lock);

        // The target process must be either the calling process or a child of the calling process.
        if (target != current) {
            bool ischild = false;
            NLib::DoubleList<Process *>::Iterator it = current->children.begin();
            for (; it.valid(); it.next()) {
                if (*(it.get()) == target) {
                    ischild = true;
                    break;
                }
            }

            if (!ischild) {
                SYSCALL_RET(-ESRCH); // Not our child.
            }

            if (target->hasexeced) {
                SYSCALL_RET(-EACCES); // Child has already called execve.
            }
        }

        if (target->session && target->id == target->session->id) {
            SYSCALL_RET(-EPERM); // Can't change pgid of a session leader.
        }

        ProcessGroup *newpgrp = NULL;
        if (pgid != target->id) { // We join an existing process group if pgid != target's pid.
            Process **pgleader = pidtable->find(pgid);
            if (!pgleader) { // No leader found.
                SYSCALL_RET(-EPERM); // Process group doesn't exist.
            }
            Process *gleader = *pgleader;

            NLib::ScopeIRQSpinlock gleaderguard(&gleader->lock);

            if (!gleader->pgrp || gleader->pgrp->id != (size_t)pgid) {
                SYSCALL_RET(-EPERM); // Process is not a process group leader.
            }

            // Target and new process group must be in the same session.
            if (!target->session || !gleader->session || target->session != gleader->session) {
                SYSCALL_RET(-EPERM);
            }

            newpgrp = gleader->pgrp;
        } else {
            if (!target->session) { // Must have a session to create a new process group.
                SYSCALL_RET(-EPERM);
            }

            // Create new process group.
            newpgrp = new ProcessGroup();
            if (!newpgrp) {
                SYSCALL_RET(-ENOMEM);
            }
            newpgrp->id = pgid;
            newpgrp->session = target->session;

            // Add to session's process group list.
            NLib::ScopeIRQSpinlock sessionguard(&target->session->lock);
            target->session->pgrps.push(newpgrp);
        }

        // Remove from old process group.
        ProcessGroup *oldpgrp = NULL;
        bool shoulddeleteoldpgrp = false;
        if (target->pgrp) {
            oldpgrp = target->pgrp;
            {
                NLib::ScopeIRQSpinlock oldpgrpguard(&oldpgrp->lock);
                oldpgrp->procs.remove([](Process *p, void *arg) {
                    return p == ((Process *)arg);
                }, (void *)target);

                // If old process group is now empty and it's not the new one, clean it up.
                if (oldpgrp->procs.empty() && oldpgrp != newpgrp) {
                    shoulddeleteoldpgrp = true;
                    Session *oldsession = oldpgrp->session;
                    if (oldsession) {
                        NLib::ScopeIRQSpinlock sessionguard(&oldsession->lock);
                        oldsession->pgrps.remove([](ProcessGroup *pg, void *arg) {
                            return pg == ((ProcessGroup *)arg);
                        }, (void *)oldpgrp);
                    }
                }
            }
            // Delete after releasing lock.
            if (shoulddeleteoldpgrp) {
                delete oldpgrp;
            }
        }

        // Add to new process group.
        {
            NLib::ScopeIRQSpinlock newpgrpguard(&newpgrp->lock);
            target->pgrp = newpgrp;
            newpgrp->procs.push(target);
        }

        SYSCALL_RET(0); // Success.
    }

    extern "C" uint64_t sys_getpgid(int pid) {
        SYSCALL_LOG("sys_getpgid(%d).\n", pid);

        NLib::ScopeIRQSpinlock guard(&pidtablelock);

        if (!pid) {
            // Return current process' process group ID.
            SYSCALL_RET(NArch::CPU::get()->currthread->process->pgrp->id);
        }

        Process **pproc = pidtable->find(pid);
        if (!pproc) {
            SYSCALL_RET(-ESRCH);
        }

        Process *proc = *pproc;
        // Return the process group of whatever we found.
        SYSCALL_RET(proc->pgrp->id);
    }

    extern "C" uint64_t sys_gettid(void) {
        SYSCALL_LOG("sys_gettid().\n");
        SYSCALL_RET(CPU::get()->currthread->id);
    }

    extern "C" uint64_t sys_getpid(void) {
        SYSCALL_LOG("sys_getpid().\n");
        SYSCALL_RET(CPU::get()->currthread->process->id);
    }

    extern "C" uint64_t sys_getppid(void) {
        SYSCALL_LOG("sys_getppid().\n");
        if (CPU::get()->currthread->process->parent) {
            SYSCALL_RET(CPU::get()->currthread->process->parent->id);
        }
        SYSCALL_RET(0); // Default to no parent PID.
    }

    void handlelazyfpu(void) {
#ifdef __x86_64__
        // Lazily restore FPU context on-demand. This will also get the scheduler to store changes to our context when we swap tasks.

        uint64_t cr0 = CPU::rdcr0();
        if (cr0 & (1 << 3)) {
            asm volatile("clts"); // Clear TS.

            Thread *curr = CPU::get()->currthread;
            if (curr && curr->fctx.fpustorage) {
                CPU::restorefctx(&curr->fctx);
                curr->fctx.mathused = true;
            }
            return;
        }
#endif
        assert(false, "Invalid FPU lazy load trigger!\n");
    }

    // Mark a thread as dead and remove it from any wait structures.
    static void markdeadandremove(Thread *thread) {
        // Atomically mark the thread as dead.
        enum Thread::state oldstate = (enum Thread::state)__atomic_exchange_n(
            &thread->tstate, Thread::state::DEAD, memory_order_acq_rel);

        // If thread was already dead, nothing more to do.
        if (oldstate == Thread::state::DEAD) {
            return;
        }

        // If thread was waiting on a waitqueue, dequeue it.
        thread->waitingonlock.acquire();
        WaitQueue *wq = thread->waitingon;
        if (wq && (oldstate == Thread::state::WAITING || oldstate == Thread::state::WAITINGINT)) {
            wq->dequeue(thread);
            thread->waitingon = NULL;
        }
        thread->waitingonlock.release();

        // The dead thread needs to be cleaned up. How we handle this depends on its previous state.
        if (oldstate == Thread::state::SUSPENDED) {
            // Thread is in a runqueue, and it will be cleaned up when the scheduler sees it.
            size_t cid = __atomic_load_n(&thread->cid, memory_order_acquire);
            if (cid < NArch::SMP::awakecpus) {
                struct CPU::cpulocal *cpu = NArch::SMP::cpulist[cid];
                if (cpu) {
                    APIC::sendipi(cpu->lapicid, 0xfe, APIC::IPIFIXED, APIC::IPIPHYS, 0);
                }
            }
        } else if (oldstate == Thread::state::WAITING || oldstate == Thread::state::WAITINGINT) {
            queuezombie(thread);
        } else if (oldstate == Thread::state::RUNNING) {
            // Currently running threads should be signaled to reschedule immediately.
            size_t cid = __atomic_load_n(&thread->cid, memory_order_acquire);
            if (cid < NArch::SMP::awakecpus) {
                struct CPU::cpulocal *cpu = NArch::SMP::cpulist[cid];
                if (cpu) {
                    APIC::sendipi(cpu->lapicid, 0xfe, APIC::IPIFIXED, APIC::IPIPHYS, 0);
                }
            }
        } else {
            queuezombie(thread);
        }
    }

    // Terminate all threads in a process except the calling thread.
    void termothers(Process *proc) {
        Thread *me = NArch::CPU::get()->currthread;

        // First pass: mark all other threads as dead.
        proc->lock.acquire();
        NLib::DoubleList<Thread *>::Iterator it = proc->threads.begin();
        for (; it.valid(); it.next()) {
            Thread *thread = *(it.get());
            if (thread != me) {
                markdeadandremove(thread);
            }
        }
        proc->lock.release();

        // Wait for all other threads to be cleaned up.
        size_t spins = 0;
        while (__atomic_load_n(&proc->threadcount, memory_order_acquire) > 1) {
            if (++spins > 100) { // If we spent too long waiting, yield.
                yield();
                spins = 0;
            } else {
                asm volatile("pause"); // Start by just pausing, so we can immediately start working after
            }
        }
    }

    extern "C" uint64_t sys_exit(int status) {
        SYSCALL_LOG("sys_exit(%d).\n", status);

        exit(status); // Exit.
        __builtin_unreachable();
    }

    static void freeargsenvs(char **arr, size_t arrc) {
        for (size_t i = 0; i < arrc; i++) {
            delete[] arr[i];
        }
        delete[] arr;
    }

    extern "C" uint64_t sys_execve(const char *path, char *const argv[], char *const envp[]) {
        SYSCALL_LOG("sys_execve(%s, %p, %p).\n", path, argv, envp);

        ssize_t pathlen = NMem::UserCopy::strnlen(path, 4096);
        if (pathlen <= 0) {
            SYSCALL_RET(-EFAULT);
        }

        char *pathbuf = new char[pathlen + 1];
        if (!pathbuf) {
            SYSCALL_RET(-ENOMEM);
        }

        ssize_t ret = NMem::UserCopy::copyfrom(pathbuf, path, pathlen + 1);
        if (ret < 0) {
            delete[] pathbuf;
            SYSCALL_RET(-EFAULT);
        }
        pathbuf[pathlen] = 0; // Null terminate.


        if (!NMem::UserCopy::valid(argv, sizeof(char *))) {
            delete[] pathbuf;
            SYSCALL_RET(-EFAULT);
        }

        size_t argc = 0;
        while (true) {
            if (!NMem::UserCopy::valid(&argv[argc], sizeof(char *))) {
                delete[] pathbuf;
                SYSCALL_RET(-EFAULT);
            }
            if (!argv[argc]) {
                break;
            }
            argc++;
            if (argc > 4096) { // XXX: ARGMAX limit.
                delete[] pathbuf;
                SYSCALL_RET(-E2BIG);
            }
        }

        char **aargv = new char *[argc + 1];
        if (!aargv) {
            delete[] pathbuf;
            SYSCALL_RET(-ENOMEM);
        }
        for (size_t i = 0; i < argc; i++) {
            ssize_t arglen = NMem::UserCopy::strnlen(argv[i], 4096);
            if (arglen <= 0) {
                delete[] pathbuf;
                delete[] aargv;
                SYSCALL_RET(-EFAULT);
            }

            aargv[i] = new char[arglen + 1];
            if (!aargv[i]) {
                for (size_t j = 0; j < i; j++) {
                    delete[] aargv[j];
                }
                delete[] pathbuf;
                delete[] aargv;
                SYSCALL_RET(-ENOMEM);
            }

            ssize_t r = NMem::UserCopy::copyfrom(aargv[i], argv[i], arglen + 1);
            if (r < 0) {
                for (size_t j = 0; j <= i; j++) {
                    delete[] aargv[j];
                }
                delete[] pathbuf;
                delete[] aargv;
                SYSCALL_RET(-EFAULT);
            }
            aargv[i][arglen] = 0; // Null terminate.
        }
        aargv[argc] = NULL; // Null terminate.

        if (!NMem::UserCopy::valid(envp, sizeof(char *))) {
            freeargsenvs(aargv, argc);
            delete[] pathbuf;
            SYSCALL_RET(-EFAULT);
        }

        // Copy envp array:
        size_t envc = 0;
        while (true) {
            if (!NMem::UserCopy::valid(&envp[envc], sizeof(char *))) {
                freeargsenvs(aargv, argc);
                delete[] pathbuf;
                SYSCALL_RET(-EFAULT);
            }
            if (!envp[envc]) {
                break;
            }
            envc++;
            if (envc > 4096) { // XXX: ARGMAX limit.
                freeargsenvs(aargv, argc);
                delete[] pathbuf;
                SYSCALL_RET(-E2BIG);
            }
        }

        char **aenvp = new char *[envc + 1];
        if (!aenvp) {
            freeargsenvs(aargv, argc);
            delete[] pathbuf;
            SYSCALL_RET(-ENOMEM);
        }
        for (size_t i = 0; i < envc; i++) {
            ssize_t envlen = NMem::UserCopy::strnlen(envp[i], 4096);
            if (envlen <= 0) {
                freeargsenvs(aargv, argc);
                delete[] pathbuf;
                delete[] aenvp;
                SYSCALL_RET(-EFAULT);
            }
            aenvp[i] = new char[envlen + 1];
            if (!aenvp[i]) {
                for (size_t j = 0; j < i; j++) {
                    delete[] aenvp[j];
                }
                freeargsenvs(aargv, argc);
                delete[] pathbuf;
                delete[] aenvp;
                SYSCALL_RET(-ENOMEM);
            }
            ssize_t r = NMem::UserCopy::copyfrom(aenvp[i], envp[i], envlen + 1);
            if (r < 0) {
                for (size_t j = 0; j <= i; j++) {
                    delete[] aenvp[j];
                }
                freeargsenvs(aargv, argc);
                delete[] pathbuf;
                delete[] aenvp;
                SYSCALL_RET(-EFAULT);
            }
            aenvp[i][envlen] = 0; // Null terminate.
        }
        aenvp[envc] = NULL; // Null terminate.


        Process *current = NArch::CPU::get()->currthread->process;
        current->lock.acquire();
        NFS::VFS::INode *cwd = current->cwd;
        int euid = current->euid;
        int egid = current->egid;
        current->lock.release();

        NFS::VFS::INode *inode;
        ret = NFS::VFS::vfs->resolve(pathbuf, &inode, cwd, true);
        if (ret < 0) {
            freeargsenvs(aargv, argc);
            freeargsenvs(aenvp, envc);
            delete[] pathbuf;
            SYSCALL_RET(ret);
        }
        delete[] pathbuf;

        // Check permission against EUID/EGID.
        if (!NFS::VFS::vfs->checkaccess(inode, NFS::VFS::O_EXEC, euid, egid)) {
            inode->unref();
            freeargsenvs(aargv, argc);
            freeargsenvs(aenvp, envc);
            SYSCALL_RET(-EACCES);
        }

        // Check if interpreter script.
        char shebang[128] = {0};

        ssize_t res = inode->read(shebang, sizeof(shebang) - 1, 0, 0);
        if (res < 2) { // Failed to read shebang.
            inode->unref();
            freeargsenvs(aargv, argc);
            freeargsenvs(aenvp, envc);
            SYSCALL_RET(-ENOEXEC);
        }

        if (shebang[0] == '#' && shebang[1] == '!') {
            // TODO: Handle interpreter scripts.
        }

        struct NSys::ELF::header elfhdr;
        res = inode->read(&elfhdr, sizeof(elfhdr), 0, 0);
        if (res < (ssize_t)sizeof(elfhdr)) {
            inode->unref();
            freeargsenvs(aargv, argc);
            freeargsenvs(aenvp, envc);
            SYSCALL_RET(-ENOEXEC);
        }

        if (elfhdr.type != NSys::ELF::ET_EXECUTABLE && elfhdr.type != NSys::ELF::ET_DYNAMIC) {
            inode->unref();
            freeargsenvs(aargv, argc);
            freeargsenvs(aenvp, envc);
            SYSCALL_RET(-ENOEXEC);
        }

        if (!NSys::ELF::verifyheader(&elfhdr)) {
            inode->unref();
            freeargsenvs(aargv, argc);
            freeargsenvs(aenvp, envc);
            SYSCALL_RET(-ENOEXEC);
        }

        struct VMM::addrspace *newspace;
        NArch::VMM::uclonecontext(&NArch::VMM::kspace, &newspace); // Start with a clone of the kernel address space.

        bool isinterp = false;

        void *ent = NULL;
        void *interpent = NULL;
        uintptr_t execbase = 0;
        uintptr_t interpbase = 0;
        uintptr_t phdraddr = 0;

        if (elfhdr.type == NSys::ELF::ET_DYNAMIC) {
            execbase = 0x400000; // Standard base for PIE.
        } else {
            execbase = 0; // Non-PIE executables load at fixed address.
        }

        if (!NSys::ELF::loadfile(&elfhdr, inode, newspace, &ent, execbase, &phdraddr)) {
            inode->unref();
            freeargsenvs(aargv, argc);
            freeargsenvs(aenvp, envc);
            delete newspace;
            SYSCALL_RET(-ENOEXEC);
        }

        char *interp = NSys::ELF::getinterpreter(&elfhdr, inode);

        if (interp != NULL) { // Dynamically linked executable.
            isinterp = true;

            // Load interpreter ELF.
            NFS::VFS::INode *interpnode;
            ssize_t r = NFS::VFS::vfs->resolve(interp, &interpnode, cwd, true);
            delete[] interp;
            if (r < 0) {
                inode->unref();
                freeargsenvs(aargv, argc);
                freeargsenvs(aenvp, envc);
                delete newspace;
                SYSCALL_RET(r);
            }

            struct NSys::ELF::header interpelfhdr;
            ssize_t rd = interpnode->read(&interpelfhdr, sizeof(interpelfhdr), 0, 0);
            if (rd < (ssize_t)sizeof(interpelfhdr)) {
                inode->unref();
                interpnode->unref();
                freeargsenvs(aargv, argc);
                freeargsenvs(aenvp, envc);
                delete newspace;
                SYSCALL_RET(-ENOEXEC);
            }

            if (!NSys::ELF::verifyheader(&interpelfhdr)) {
                inode->unref();
                interpnode->unref();
                freeargsenvs(aargv, argc);
                freeargsenvs(aenvp, envc);
                delete newspace;
                SYSCALL_RET(-ENOEXEC);
            }

            // Load interpreter at different base address
            interpbase = 0x00000beef0000000;  // Place interpreter at a different address range
            if (!NSys::ELF::loadfile(&interpelfhdr, interpnode, newspace, &interpent, interpbase, NULL)) {
                inode->unref();
                interpnode->unref();
                freeargsenvs(aargv, argc);
                freeargsenvs(aenvp, envc);
                delete newspace;
                SYSCALL_RET(-ENOEXEC);
            }

            interpnode->unref();

            if (!interpent || (uintptr_t)interpent >= 0x0000800000000000) {
                inode->unref();
                freeargsenvs(aargv, argc);
                freeargsenvs(aenvp, envc);
                delete newspace;
                SYSCALL_RET(-ENOEXEC);
            }
        }

        if (!ent || (uintptr_t)ent >= 0x0000800000000000) {
            inode->unref();
            freeargsenvs(aargv, argc);
            freeargsenvs(aenvp, envc);
            delete newspace;
            SYSCALL_RET(-ENOEXEC);
        }


        struct NFS::VFS::stat attr = inode->getattr();

        inode->unref();

        uintptr_t ustackphy = (uintptr_t)PMM::alloc(1 << 20); // This is the physical memory behind the stack.
        if (!ustackphy) {
            freeargsenvs(aargv, argc);
            freeargsenvs(aenvp, envc);
            delete newspace;
            SYSCALL_RET(-ENOMEM);
        }

        uintptr_t ustacktop = 0x0000800000000000 - NArch::PAGESIZE; // Top of user space, minus a page for safety.
        uintptr_t ustackbottom = ustacktop - (1 << 20); // Virtual address of bottom of user stack (where ustackphy starts).

        void *rsp = NSys::ELF::preparestack((uintptr_t)NArch::hhdmoff((void *)(ustackphy + (1 << 20))), aargv, aenvp, &elfhdr, ustacktop, (uintptr_t)ent, interpbase, phdraddr);
        freeargsenvs(aargv, argc);
        freeargsenvs(aenvp, envc);

        if (!rsp) {
            PMM::free((void *)ustackphy, 1 << 20);
            delete newspace;
            SYSCALL_RET(-ENOMEM);
        }

        // Reserve user stack region.
        newspace->vmaspace->reserve(ustackbottom, ustacktop, NMem::Virt::VIRT_NX | NMem::Virt::VIRT_RW | NMem::Virt::VIRT_USER);
        newspace->vmaspace->reserve(ustacktop, 0x0000800000000000, 0); // Guard page.

        // Map user stack.
        NArch::VMM::maprange(newspace, ustackbottom, (uintptr_t)ustackphy, NArch::VMM::NOEXEC | NArch::VMM::WRITEABLE | NArch::VMM::USER | NArch::VMM::PRESENT, 1<< 20);

        // Kill other threads and await their death.
        termothers(current);

        current->lock.acquire();

        // Mark that this process has called execve.
        current->hasexeced = true;

        if (NFS::VFS::S_ISSUID(attr.st_mode)) {
            current->euid = attr.st_uid; // Run as owner of file.
        }

        if (NFS::VFS::S_ISSGID(attr.st_mode)) {
            current->egid = attr.st_gid; // Run as owner of file.
        }

        // "The effective UID of the process is copied to the saved set-user-ID"
        current->suid = current->euid;
        current->sgid = current->egid;

        // RUID and RGID remain unchanged.

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

        // Reset signal handlers to SIG_DFL on exec (except those set to SIG_IGN remain SIG_IGN).
        for (size_t i = 0; i < NSIG; i++) {
            if (current->signalstate.actions[i].handler != SIG_IGN) {
                current->signalstate.actions[i].handler = SIG_DFL;
                current->signalstate.actions[i].mask = 0;
                current->signalstate.actions[i].flags = 0;
                current->signalstate.actions[i].restorer = NULL;
            }
        }
        // Pending signals are cleared on exec.
        current->signalstate.pending = 0;
        // Signal mask is preserved across exec.

        struct NArch::CPU::context *sysctx = NArch::CPU::get()->currthread->sysctx;
#ifdef __x86_64__
        NLib::memset(&NArch::CPU::get()->currthread->xctx, 0, sizeof(NArch::CPU::get()->currthread->xctx));

        sysctx->rip = isinterp ? (uint64_t)interpent : (uint64_t)ent; // Entry point.
        sysctx->rsp = (uint64_t)rsp;
        sysctx->rflags = 0x202; // Enable interrupts.

        NUtil::printf("Execve: Entry point at 0x%lx, stack at 0x%lx\n", sysctx->rip, sysctx->rsp);

        NLib::memset(NArch::CPU::get()->currthread->fctx.fpustorage, 0, CPU::get()->fpusize);
        NArch::CPU::get()->currthread->fctx.mathused = false; // Mark as unused.

        if (CPU::get()->hasxsave) {
            uint64_t cr0 = CPU::rdcr0();
            asm volatile("clts");
            // Initialise region.
            asm volatile("xsave (%0)" : : "r"(NArch::CPU::get()->currthread->fctx.fpustorage), "a"(0xffffffff), "d"(0xffffffff));
            CPU::wrcr0(cr0); // Restore original CR0 (restores TS).
        }

        NArch::VMM::swapcontext(newspace);
        current->lock.release();

        SYSCALL_RET(sysctx->rax); // Success. This should usually be the system call number of sys_execve.
#else
        // Other architectures not implemented yet.
        current->lock.release();
        delete newspace;
        SYSCALL_RET(-ENOSYS);
#endif
    }

    #define WNOHANG     1 // Don't block.
    #define WUNTRACED   2 // Report stopped children.

    static Process *findchild(Process *parent, int pid, bool zombie) {
        NLib::DoubleList<Process *>::Iterator it = parent->children.begin();
        int childcount = 0;
        for (; it.valid(); it.next()) {
            Process *child = *(it.get());
            childcount++;

            bool match = false;

            child->lock.acquire();
            // Skip processes being reaped by another waitpid call.
            if (zombie && child->pstate != Process::state::ZOMBIE) {
                child->lock.release();
                continue; // Wanted zombies, but this is not one (or already being reaped).
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

            if (match && zombie) {
                // Atomically claim the zombie by transitioning to REAPING state.
                // This prevents other concurrent waitpid calls from reaping the same child.
                child->pstate = Process::state::REAPING;
                child->lock.release();
                return child;
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
            SYSCALL_RET(-EFAULT);
        }

        Process *current = NArch::CPU::get()->currthread->process;
        current->lock.acquire();

        // Check if we have any children that match.
        bool haschildren = findchild(current, pid, false) != NULL;

        if (!haschildren) {
            current->lock.release();
            SYSCALL_RET(-ECHILD); // No matching children.
        }

        Process *zombie = NULL;

        if (options & WNOHANG) {
            // Non-blocking wait.
            zombie = findchild(current, pid, true);
            if (!zombie) {
                current->lock.release();
                SYSCALL_RET(0); // No matching zombies.
            }
        } else {
            // Blocking wait.
            int ret;

            // Manually expand the macro to add debugging.
            ret = 0;
            while (true) {
                zombie = findchild(current, pid, true);
                if (zombie != NULL) {
                    break;
                }
                int __ret = current->exitwq.waitinterruptiblelocked(&current->lock);
                if (__ret < 0) {
                    ret = __ret;
                    break;
                }
            }

            if (ret < 0) {
                // Even if interrupted, check if a zombie appeared.
                zombie = findchild(current, pid, true);
                if (!zombie) {
                    current->lock.release();
                    SYSCALL_RET(ret); // Interrupted and no zombie.
                }
                // Fall through to reap the zombie.
            }
        }

        // The zombie is now in REAPING state (claimed by us in findchild),
        // so no other waitpid can race with us to reap it.
        current->lock.release();

        zombie->lock.acquire();
        // Verify we still own the zombie (should always be true since we claimed it).
        assert(zombie->pstate == Process::state::REAPING, "Zombie not in REAPING state after claim");
        int zstatus = zombie->exitstatus;
        size_t zid = zombie->id;

        if (status) {
            // Copy status out.
            if (NMem::UserCopy::copyto(status, &zstatus, sizeof(int)) < 0) {
                // Revert to ZOMBIE state so another waiter can try.
                zombie->pstate = Process::state::ZOMBIE;
                zombie->lock.release();
                SYSCALL_RET(-EFAULT);
            }
        }

        zombie->pstate = Process::state::DEAD;
        zombie->lock.release();

        // Destructor will acquire parent lock to remove from children list.
        // Don't hold it here to avoid double acquisition.
        delete zombie; // Reap process.

        SYSCALL_RET(zid);
    }

    extern "C" uint64_t sys_yield(void) {
        SYSCALL_LOG("sys_yield().\n");
        yield();
        SYSCALL_RET(0);
    }

    extern "C" uint64_t sys_getresuid(int *ruid, int *euid, int *suid) {
        SYSCALL_LOG("sys_getresuid(%p, %p, %p).\n", ruid, euid, suid);

        Process *current = NArch::CPU::get()->currthread->process;
        NLib::ScopeIRQSpinlock guard(&current->lock);

        if (ruid) {
            if (!NMem::UserCopy::valid(ruid, sizeof(int))) {
                SYSCALL_RET(-EFAULT);
            }
            int r = current->uid;
            if (NMem::UserCopy::copyto(ruid, &r, sizeof(int)) < 0) {
                SYSCALL_RET(-EFAULT);
            }
        }

        if (euid) {
            if (!NMem::UserCopy::valid(euid, sizeof(int))) {
                SYSCALL_RET(-EFAULT);
            }
            int e = current->euid;
            if (NMem::UserCopy::copyto(euid, &e, sizeof(int)) < 0) {
                SYSCALL_RET(-EFAULT);
            }
        }

        if (suid) {
            if (!NMem::UserCopy::valid(suid, sizeof(int))) {
                SYSCALL_RET(-EFAULT);
            }
            int s = current->suid;
            if (NMem::UserCopy::copyto(suid, &s, sizeof(int)) < 0) {
                SYSCALL_RET(-EFAULT);
            }
        }

        SYSCALL_RET(0);
    }

    extern "C" uint64_t sys_getresgid(int *rgid, int *egid, int *sgid) {
        SYSCALL_LOG("sys_getresgid(%p, %p, %p).\n", rgid, egid, sgid);

        Process *current = NArch::CPU::get()->currthread->process;
        NLib::ScopeIRQSpinlock guard(&current->lock);

        if (rgid) {
            if (!NMem::UserCopy::valid(rgid, sizeof(int))) {
                SYSCALL_RET(-EFAULT);
            }
            int r = current->gid;
            if (NMem::UserCopy::copyto(rgid, &r, sizeof(int)) < 0) {
                SYSCALL_RET(-EFAULT);
            }
        }

        if (egid) {
            if (!NMem::UserCopy::valid(egid, sizeof(int))) {
                SYSCALL_RET(-EFAULT);
            }
            int e = current->egid;
            if (NMem::UserCopy::copyto(egid, &e, sizeof(int)) < 0) {
                SYSCALL_RET(-EFAULT);
            }
        }

        if (sgid) {
            if (!NMem::UserCopy::valid(sgid, sizeof(int))) {
                SYSCALL_RET(-EFAULT);
            }
            int s = current->sgid;
            if (NMem::UserCopy::copyto(sgid, &s, sizeof(int)) < 0) {
                SYSCALL_RET(-EFAULT);
            }
        }

        SYSCALL_RET(0);
    }

    extern "C" uint64_t sys_setresuid(int ruid, int euid, int suid) {
        SYSCALL_LOG("sys_setresuid(%d, %d, %d).\n", ruid, euid, suid);

        Process *current = NArch::CPU::get()->currthread->process;
        NLib::ScopeIRQSpinlock guard(&current->lock);

        bool privileged = (NArch::CPU::get()->currthread->process->euid == 0);
        // setresuid(2):
        // An unprivileged process may change its real UID, effective UID,
        // and saved set-user-ID, each to one of: the current real UID, the
        // current effective UID, or the current saved set-user-ID.

        if (ruid != -1) {
            if (privileged || ruid == current->uid || ruid == current->euid || ruid == current->suid) {
                current->uid = ruid;
            } else {
                SYSCALL_RET(-EPERM);
            }
        }
        if (euid != -1) {
            if (privileged || euid == current->uid || euid == current->euid || euid == current->suid) {
                current->euid = euid;
            } else {
                SYSCALL_RET(-EPERM);
            }
        }
        if (suid != -1) {
            if (privileged || suid == current->uid || suid == current->euid || suid == current->suid) {
                current->suid = suid;
            } else {
                SYSCALL_RET(-EPERM);
            }
        }

        SYSCALL_RET(0);
    }

    extern "C" uint64_t sys_setresgid(int rgid, int egid, int sgid) {
        SYSCALL_LOG("sys_setresgid(%d, %d, %d).\n", rgid, egid, sgid);

        Process *current = NArch::CPU::get()->currthread->process;
        NLib::ScopeIRQSpinlock guard(&current->lock);

        bool privileged = (NArch::CPU::get()->currthread->process->euid == 0);
        // setresgid(2):
        // An unprivileged process may change its real GID, effective GID,
        // and saved set-group-ID, each to one of: the current real GID, the
        // current effective GID, or the current saved set-group-ID.

        if (rgid != -1) {
            if (privileged || rgid == current->gid || rgid == current->egid || rgid == current->sgid) {
                current->gid = rgid;
            } else {
                SYSCALL_RET(-EPERM);
            }
        }
        if (egid != -1) {
            if (privileged || egid == current->gid || egid == current->egid || egid == current->sgid) {
                current->egid = egid;
            } else {
                SYSCALL_RET(-EPERM);
            }
        }
        if (sgid != -1) {
            if (privileged || sgid == current->gid || sgid == current->egid || sgid == current->sgid) {
                current->sgid = sgid;
            } else {
                SYSCALL_RET(-EPERM);
            }
        }

        SYSCALL_RET(0);
    }

    struct timespec {
        long tv_sec;
        long tv_nsec;
    };

    #define FUTEX_WAIT      0
    #define FUTEX_WAKE      1

    extern "C" ssize_t sys_futex(int *ptr, int op, int expected, struct timespec *timeout) {
        SYSCALL_LOG("sys_futex(%p, %d, %u, %p).\n", ptr, op, expected, timeout);

        SYSCALL_RET(0); // TODO: Implement futexes.
    }

    extern "C" ssize_t sys_newthread(void *entry, void *stack) {
        SYSCALL_LOG("sys_newthread(%p, %p).\n", entry, stack);

        Process *proc = NArch::CPU::get()->currthread->process;

        Thread *newthread = new Thread(proc, NSched::DEFAULTSTACKSIZE);
        if (!newthread) {
            SYSCALL_RET(-ENOMEM);
        }

        newthread->ctx.rip = (uint64_t)entry;
        newthread->ctx.rsp = (uint64_t)stack;

        NSched::schedulethread(newthread);
        SYSCALL_RET(newthread->id);
    }

    extern "C" ssize_t sys_exitthread(void) {
        SYSCALL_LOG("sys_exitthread().\n");

        // Mark ourselves as dead and yield.
        NArch::CPU::get()->setint(false);
        __atomic_store_n(&NArch::CPU::get()->currthread->tstate, Thread::state::DEAD, memory_order_release);
        NArch::CPU::get()->setint(true);
        yield();

        __builtin_unreachable();
    }
}
