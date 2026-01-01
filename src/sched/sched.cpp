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
    // Two-phase zombie collection for safe deferred deletion.
    static Thread *oldzombies = NULL;

    static void reapzombies(void) {
        Thread *todelete = __atomic_exchange_n(&oldzombies, NULL, memory_order_acq_rel);
        while (todelete) {
            Thread *next = todelete->nextzombie;
            todelete->nextzombie = NULL;
            delete todelete;
            todelete = next;
        }

        // Then, move current zombies to oldzombies for next cycle.
        if (!__atomic_load_n(&zombiehead, memory_order_acquire)) {
            return; // What? No head?
        }

        zombielock.acquire();
        Thread *zombie = zombiehead;
        zombiehead = NULL;
        zombielock.release();

        if (zombie) {
            // Find end of zombie chain.
            Thread *tail = zombie;
            while (tail->nextzombie) {
                tail = tail->nextzombie;
            }

            // Atomically prepend to oldzombies.
            Thread *expected = __atomic_load_n(&oldzombies, memory_order_acquire);
            do {
                tail->nextzombie = expected;
            } while (!__atomic_compare_exchange_n(&oldzombies, &expected, zombie,
                                                   false, memory_order_acq_rel, memory_order_acquire));
        }
    }

    // Queue a thread for deferred deletion.
    static bool queuezombie(Thread *thread) {
        // Use CAS to ensure only one caller can queue this thread.
        bool expected = false;
        if (!__atomic_compare_exchange_n(&thread->zombiequeued, &expected, true, false, memory_order_acq_rel, memory_order_acquire)) {
            return false; // Already queued by another path.
        }

        zombielock.acquire();
        thread->nextzombie = zombiehead;
        zombiehead = thread;
        zombielock.release();
        return true;
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
        // Always acquire locks in ascending CPU ID order.
        struct CPU::cpulocal *first = (cpu->id < target->id) ? cpu : target;
        struct CPU::cpulocal *second = (cpu->id < target->id) ? target : cpu;

        first->runqueue.lock.acquire();
        second->runqueue.lock.acquire();

        struct RBTree::node *node = cpu->runqueue._last();
        size_t migrated = 0;
        while (node && migrated < quota) {
            Thread *candidate = RBTree::getentry<Thread>(node);
            struct RBTree::node *prev = cpu->runqueue._prev(node);

            // Check if thread is eligible for migration.
            enum Thread::state tstate = (enum Thread::state)__atomic_load_n(&candidate->tstate, memory_order_acquire);
            if (tstate != Thread::state::SUSPENDED ||
                __atomic_load_n(&candidate->locksheld, memory_order_acquire) > 0 ||
                __atomic_load_n(&candidate->migratedisabled, memory_order_acquire) ||
                candidate->fctx.mathused) {
                node = prev;
                continue;
            }

            cpu->runqueue._erase(node);
            __atomic_store_n(&candidate->lastcid, __atomic_load_n(&candidate->cid, memory_order_acquire), memory_order_release);
            __atomic_store_n(&candidate->cid, target->id, memory_order_release);
            NArch::CPU::writemb();
            target->runqueue._insert(node, vruntimecmp);
            migrated++;

            node = prev;
        }

        // Release locks in reverse order of acquisition.
        second->runqueue.lock.release();
        first->runqueue.lock.release();

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
            struct RBTree::node *prev = busiest->runqueue._prev(node);

            enum Thread::state tstate = (enum Thread::state)__atomic_load_n(&candidate->tstate, memory_order_acquire);

            // Only steal threads that are actually waiting to run and can be migrated.
            // Also check mathused to avoid stealing threads with potentially unsaved FPU state.
            if (tstate == Thread::state::SUSPENDED &&
                __atomic_load_n(&candidate->locksheld, memory_order_acquire) == 0 &&
                !__atomic_load_n(&candidate->migratedisabled, memory_order_acquire) &&
                !candidate->fctx.mathused) {
                busiest->runqueue._erase(node);
                stolen = candidate;
                break;
            }
            node = prev;
        }

        busiest->runqueue.lock.release();

        if (stolen) {
            updateload(busiest);
            // Atomically update lastcid and cid to prevent data races.
            __atomic_store_n(&stolen->lastcid, __atomic_load_n(&stolen->cid, memory_order_acquire), memory_order_release);
            __atomic_store_n(&stolen->cid, CPU::get()->id, memory_order_release);
            // Memory barrier to ensure cid update is visible.
            NArch::CPU::writemb();
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

            cpu->runqueue._erase(node);
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

        NArch::CPU::mb();

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

        if (__atomic_exchange_n(&cpu->inschedule, true, memory_order_acq_rel)) {
            // Already in scheduler, bail out. The outer invocation will handle scheduling.
            return;
        }

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
                bool success = __atomic_compare_exchange_n(&prev->tstate, &expected, targetstate, false, memory_order_acq_rel, memory_order_acquire);

                if (success) {
                    // Successfully transitioned to waiting state.
                    NArch::CPU::mb();
                    enum Thread::pendingwait recheckpend = (enum Thread::pendingwait)__atomic_load_n(&prev->pendingwaitstate, memory_order_acquire);
                    if (recheckpend == Thread::pendingwait::PENDING_NONE) {
                        expected = targetstate;
                        if (__atomic_compare_exchange_n(&prev->tstate, &expected, Thread::state::SUSPENDED, false, memory_order_acq_rel, memory_order_acquire)) {
                            // Successfully reverted to SUSPENDED, enqueue the thread.
                            NArch::CPU::writemb();
                            cpu->runqueue._insert(&prev->node, vruntimecmp);
                        }
                    }
                    // If pendingwaitstate is still set, thread is properly waiting.
                } else if (expected == Thread::state::DEAD) {
                    // Thread was marked dead by another CPU, queue for cleanup.
                    __atomic_store_n(&prev->pendingwaitstate, Thread::pendingwait::PENDING_NONE, memory_order_release);
                    queuezombie(prev);
                    prev = NULL;
                } else {
                    __atomic_store_n(&prev->pendingwaitstate, Thread::pendingwait::PENDING_NONE, memory_order_release);
                }
            } else {
                // No pending wait: try to transition RUNNING -> SUSPENDED.
                enum Thread::state expected = Thread::state::RUNNING;
                bool success = __atomic_compare_exchange_n(&prev->tstate, &expected, Thread::state::SUSPENDED, false, memory_order_acq_rel, memory_order_acquire);

                if (success) {
                    // Successfully transitioned to SUSPENDED, enqueue.
                    NArch::CPU::writemb();
                    cpu->runqueue._insert(&prev->node, vruntimecmp);
                } else if (expected == Thread::state::DEAD) {
                    // Thread was marked dead, queue for cleanup.
                    queuezombie(prev);
                    prev = NULL;
                }
                // If expected is something else, thread was already dequeued/waiting.
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

        if (next != cpu->idlethread) {
            enum Thread::state nstate = (enum Thread::state)__atomic_load_n(&next->tstate, memory_order_acquire);
            if (nstate == Thread::state::DEAD) {
                // Thread was killed after we selected it. Queue for cleanup and use idle thread.
                queuezombie(next);
                next = cpu->idlethread;
            } else if (nstate == Thread::state::RUNNING) {
                next = cpu->idlethread;
            } else if (nstate != Thread::state::SUSPENDED && nstate != Thread::state::READY) {
                next = cpu->idlethread;
            }
        }

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

            __atomic_store_n(&cpu->inschedule, false, memory_order_release);

            switchthread(next, needswap); // Swap to context. THIS SHOULD NEVER RETURN!

            // If we reach here, ctx_swap returned unexpectedly - this indicates severe corruption.
            panic("FATAL: switchthread() returned! Context corruption detected.\n");
        }

        __atomic_store_n(&next->tstate, Thread::state::RUNNING, memory_order_release); // Set state.

        cpu->quantumdeadline = TSC::query() + (TSC::hz / 1000) * QUANTUMMS;
        Timer::rearm();

        __atomic_store_n(&cpu->inschedule, false, memory_order_release);

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
            if (this->cwd->fs) {
                this->cwd->fs->fsunref();  // Release filesystem reference from cwd
            }
            this->cwd->unref(); // Unreference current working directory (so it isn't marked busy).
        }

        if (this->root) {
            if (this->root->fs) {
                this->root->fs->fsunref();  // Release filesystem reference from root
            }
            this->root->unref(); // Unreference root directory.
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

        // Check if thread is dead before attempting to yield.
        enum Thread::state currentstate = (enum Thread::state)__atomic_load_n(&self->tstate, memory_order_acquire);
        if (currentstate == Thread::state::DEAD) {
            for (;;) {
                asm volatile(
                    "sti\n\t"
                    "int $0xfe\n\t"
                    "cli\n\t"
                    : : : "memory"
                );
            }
            __builtin_unreachable();
        }

        // Disable interrupts to prevent races during yield setup.
        bool oldint = cpu->setint(false);

        // Mark that this thread is requesting a reschedule.
        __atomic_store_n(&self->rescheduling, true, memory_order_release);

        // Full memory barrier to ensure rescheduling flag is visible before IPI.
        NArch::CPU::writemb();
        NArch::CPU::readmb();

        // Trigger scheduler via synchronous interrupt (means we can interrupt while interrupts are disabled!).
        asm volatile(
            "sti\n\t"
            "int $0xfe\n\t"
            : : : "memory"
        );

        while (__atomic_load_n(&self->rescheduling, memory_order_acquire)) {
            asm volatile("pause" : : : "memory");
        }

        // Restore original interrupt state.
        cpu->setint(oldint);
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

            if (proc->fdtable) {
                proc->fdtable->closeall(); // Close so we can be done with files asap.
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
        // Attempt to transition thread from current state to SUSPENDED state.
        enum Thread::state expected = (enum Thread::state)__atomic_load_n(&thread->tstate, memory_order_acquire);
        while (true) {
            // Check for states that prevent scheduling.
            if (expected == Thread::state::DEAD) {
                return; // Thread is dead, do not schedule.
            }

            if (expected == Thread::state::SUSPENDED) {
                return; // Thread is already in a runqueue, do not double-enqueue.
            }

            if (expected == Thread::state::RUNNING) {
                return; // Thread is currently running, do not re-enqueue.
            }

            if (expected != Thread::state::WAITING &&
                expected != Thread::state::WAITINGINT &&
                expected != Thread::state::PAUSED &&
                expected != Thread::state::READY) {
                return; // Unknown state, refuse to schedule.
            }

            if (__atomic_compare_exchange_n(&thread->tstate, &expected, Thread::state::SUSPENDED, false, memory_order_acq_rel, memory_order_acquire)) {
                break; // Successfully transitioned to SUSPENDED.
            }
        }

        // Full memory barrier to ensure state transition is visible.
        NArch::CPU::writemb();

        // Find the most idle CPU for this thread.
        struct CPU::cpulocal *cpu = getidlest();
        if (!cpu) {
            cpu = CPU::get(); // Fallback to current CPU.
        }

        // Set CPU ID before enqueueing to ensure consistency.
        __atomic_store_n(&thread->cid, cpu->id, memory_order_release);

        // Memory barrier before insertion.
        NArch::CPU::writemb();

        // Enqueue the thread.
        enqueuethread(cpu, thread);
        updateload(cpu);

        if (cpu != CPU::get()) { // Only cause IPI if it's not us.
            NArch::CPU::readmb();
            if (cpu->runqueue.count() <= 1) { // Only force CPU to wake up if it wasn't already loaded with work (it'd be silly to wake up busy CPUs just for them to likely *not* reschedule our work).
                APIC::sendipi(cpu->lapicid, 0xfe, APIC::IPIFIXED, APIC::IPIPHYS, 0);
            }
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
        // Atomically mark the thread as dead using exchange.
        enum Thread::state oldstate = (enum Thread::state)__atomic_exchange_n(
            &thread->tstate, Thread::state::DEAD, memory_order_acq_rel);

        // Clear any pending wait state.
        __atomic_store_n(&thread->pendingwaitstate, Thread::pendingwait::PENDING_NONE, memory_order_release);

        // If thread was already dead, nothing more to do.
        if (oldstate == Thread::state::DEAD) {
            return;
        }

        // Memory barrier to ensure state change is visible.
        NArch::CPU::writemb();

        // If thread was waiting on a waitqueue, dequeue it.
        if (oldstate == Thread::state::WAITING || oldstate == Thread::state::WAITINGINT) {
            thread->waitingonlock.acquire();
            WaitQueue *wq = thread->waitingon;
            thread->waitingon = NULL;  // Clear it to prevent double-dequeue attempts
            thread->waitingonlock.release();

            if (wq) {
                // dequeue() acquires waitinglock internally.
                wq->dequeue(thread);
            }

            // The dequeue already handled cleanup; queue for deletion.
            queuezombie(thread);
        } else if (oldstate == Thread::state::SUSPENDED) {
            // Thread is in a runqueue. The scheduler will find it marked DEAD and clean it up. Send IPI to ensure timely cleanup.
            size_t cid = __atomic_load_n(&thread->cid, memory_order_acquire);
            if (cid < NArch::SMP::awakecpus) {
                struct CPU::cpulocal *cpu = NArch::SMP::cpulist[cid];
                if (cpu) {
                    APIC::sendipi(cpu->lapicid, 0xfe, APIC::IPIFIXED, APIC::IPIPHYS, 0);
                }
            }
        } else if (oldstate == Thread::state::RUNNING) {
            // Thread is currently running on a CPU.
            thread->waitingonlock.acquire();
            WaitQueue *wq = thread->waitingon;
            thread->waitingon = NULL;  // Clear to prevent double-dequeue
            thread->waitingonlock.release();

            if (wq) {
                wq->dequeue(thread);
            }

            // Send IPI to force reschedule.
            size_t cid = __atomic_load_n(&thread->cid, memory_order_acquire);
            if (cid < NArch::SMP::awakecpus) {
                struct CPU::cpulocal *cpu = NArch::SMP::cpulist[cid];
                if (cpu) {
                    APIC::sendipi(cpu->lapicid, 0xfe, APIC::IPIFIXED, APIC::IPIPHYS, 0);
                }
            }
        } else if (oldstate == Thread::state::READY || oldstate == Thread::state::PAUSED) {
            // Thread was not in any queue, safe to queue for deletion.
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

}
