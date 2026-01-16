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
#include <std/stdatomic.h>
#include <sys/clock.hpp>
#include <sys/elf.hpp>
#include <sys/syscall.hpp>
#include <sys/timer.hpp>
#include <util/kprint.hpp>

// This is SUPER easy to get wrong, be VERY careful when acquiring multiple locks.
// Lock ordering hierarchy:
// Level 1:
// - pidtablelock
// - futexlock
// Level 2:
// - Process::lock
// Level 3:
// - ProcessGroup::lock
// - Session::lock
// Level 4:
// - VMM::addrspace::lock
// Level 5:
// - waitinglock (WaitQueue)
// Level 6:
// - Thread::waitingonlock
// Level 7:
// - runqueue.lock (per-cpu)

namespace NSched {
    using namespace NArch;

    // Scheduler initialisation state, set by BSP setup.
    bool initialised = false;

    // Zombie queue for deferred thread deletion.
    static Thread *zombiehead = NULL; // Fresh zombies.
    static Thread *oldzombies = NULL; // Zombies from previous cycle (will be deleted next cycle).
    static Spinlock zombielock;

    // Queue a dead thread for deferred deletion.
    static void queuezombie(Thread *thread) {
        zombielock.acquire();
        thread->nextzombie = zombiehead;
        zombiehead = thread;
        zombielock.release();
    }

    // Called periodically from the scheduler to clean up dead threads.
    static void reapzombies(void) {
        // First, delete threads from the previous cycle (oldzombies).
        Thread *todelete = __atomic_exchange_n(&oldzombies, NULL, memory_order_acq_rel);
        while (todelete) {
            Thread *next = todelete->nextzombie;
            todelete->nextzombie = NULL;
            delete todelete;
            todelete = next;
        }

        // Then, move current zombies to oldzombies for next cycle.
        zombielock.acquire();
        Thread *zombie = zombiehead;
        zombiehead = NULL;
        zombielock.release();

        if (zombie) {
            // Append to oldzombies (will be deleted next cycle).
            __atomic_store_n(&oldzombies, zombie, memory_order_release);
        }
    }

    void setthreadstate(Thread *thread, Thread::state newstate, const char *loc) {
#ifdef TSTATE_DEBUG
        Thread::state oldstate = (Thread::state)__atomic_load_n(&thread->tstate, memory_order_acquire);
        __atomic_store_n(&thread->laststate, oldstate, memory_order_release);
        __atomic_store_n(&thread->laststateloc, loc, memory_order_release);
#ifdef __x86_64__
        __atomic_store_n(&thread->laststatetransition, TSC::query(), memory_order_release);
#endif

#endif
        __atomic_store_n(&thread->tstate, newstate, memory_order_release);
    }

#ifdef TSTATE_DEBUG
    void dumpthread(Thread *thread) {
        Thread::state curstate = (Thread::state)__atomic_load_n(&thread->tstate, memory_order_acquire);
        Thread::state laststate = (Thread::state)__atomic_load_n(&thread->laststate, memory_order_acquire);
        Thread::pendingwait pendwait = (Thread::pendingwait)__atomic_load_n(&thread->pendingwaitstate, memory_order_acquire);
        bool inrq = __atomic_load_n(&thread->inrunqueue, memory_order_acquire);
        bool wokenbefore = __atomic_load_n(&thread->wokenbeforewait, memory_order_acquire);
        size_t cid = __atomic_load_n(&thread->cid, memory_order_acquire);
        size_t lastcid = __atomic_load_n(&thread->lastcid, memory_order_acquire);
        uint64_t lastts = __atomic_load_n(&thread->laststatetransition, memory_order_acquire);
        const char *lastloc = (const char *)__atomic_load_n((uintptr_t *)&thread->laststateloc, memory_order_acquire);

        uint64_t now = 0;
#ifdef __x86_64__
        now = TSC::query();
#endif
        uint64_t agems = (lastts > 0 && now > lastts) ? ((now - lastts) * 1000 / TSC::hz) : 0;

        NUtil::printf("  Thread %p [pid=%lu tid=%lu]: state=%s (was %s), pending=%s\n",
            thread,
            thread->process ? thread->process->id : 0,
            thread->id,
            Thread::statename(curstate),
            Thread::statename(laststate),
            Thread::pendingwaitname(pendwait));
        NUtil::printf("    inrunqueue=%d, wokenbeforewait=%d, cid=%lu, lastcid=%lu\n",
            inrq, wokenbefore, cid, lastcid);
        NUtil::printf("    laststatetrans=%lums ago @ %s\n", agems, lastloc ? lastloc : "(unknown)");

        // Check for potential issues.
        if (curstate == Thread::state::READY && !inrq) {
            NUtil::printf("    !!! WARNING: Thread in READY state but not in runqueue!\n");
        }
        if (curstate == Thread::state::SUSPENDED && !inrq) {
            NUtil::printf("    !!! WARNING: Thread in SUSPENDED state but not in runqueue!\n");
        }
        if ((curstate == Thread::state::WAITING || curstate == Thread::state::WAITINGINT) && inrq) {
            NUtil::printf("    !!! WARNING: Thread in WAITING state but still in runqueue!\n");
        }
        if (curstate == Thread::state::RUNNING && thread != CPU::get()->currthread) {
            NUtil::printf("    !!! WARNING: Thread marked RUNNING but not current on this CPU!\n");
        }

        // Check for thread stuck in WAITING without a waitqueue.
        thread->waitingonlock.acquire();
        WaitQueue *wq = thread->waitingon;
        thread->waitingonlock.release();
        if ((curstate == Thread::state::WAITING || curstate == Thread::state::WAITINGINT) && !wq) {
            NUtil::printf("    !!! WARNING: Thread in WAITING state but waitingon is NULL!\n");
        }
    }

    // Debug: Dump state of all threads in the system.
    void dumpthreads(void) {
        NUtil::printf("=== THREAD STATE DUMP ===\n");

        // Dump CPU runqueues.
        for (size_t i = 0; i < SMP::awakecpus; i++) {
            struct CPU::cpulocal *cpu = SMP::cpulist[i];
            NUtil::printf("CPU %lu: currthread=%p (idle=%p), runqueue count=%lu\n",
                i,
                cpu->currthread,
                cpu->idlethread,
                cpu->runqueue.count());

            // Dump threads in this CPU's runqueue.
            cpu->runqueue.lock.acquire();
            RBTree::node *n = cpu->runqueue._first();
            size_t count = 0;
            while (n && count < 10) { // Limit to 10 for safety.
                Thread *t = RBTree::getentry<Thread>(n);
                dumpthread(t);
                n = cpu->runqueue._next(n);
                count++;
            }
            cpu->runqueue.lock.release();
        }

        // Dump all processes and their threads.
        NUtil::printf("\n--- All Processes ---\n");
        pidtablelock.acquire();
        for (auto it = pidtable->begin(); it.valid(); it.next()) {
            Process *proc = *it.value();
            NUtil::printf("Process %lu (state=%d, threads=%lu):\n",
                proc->id, proc->pstate, proc->threadcount);

            proc->lock.acquire();
            auto tit = proc->threads.begin();
            while (tit.valid()) {
                Thread *t = *tit.get();
                dumpthread(t);
                tit.next();
            }
            proc->lock.release();
        }
        pidtablelock.release();

        NUtil::printf("=== END DUMP ===\n");
    }
#endif

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

    // Save pointer system call context before a system call, so we can use it for sys_fork and sys_execve.
    extern "C" __attribute__((no_caller_saved_registers)) void sched_savesysstate(struct CPU::context *ctx) {
        struct CPU::cpulocal *cpu = CPU::get();
        Thread *thread = cpu->currthread;

        // Update pointer to context. Since it's a pointer, we can just overwrite it to return somewhere else after the system call (great for sys_execve or sys_sigreturn).
        thread->sysctx = ctx;
        // Inform kernel of current interrupt status.
        cpu->intstatus = true;
    }

    // Handle lazily restoring FPU context on-demand.
    void handlelazyfpu(void) {
#ifdef __x86_64__
        uint64_t cr0 = CPU::rdcr0();
        if (cr0 & (1 << 3)) {
            asm volatile("clts");
            Thread *thread = CPU::get()->currthread;
            if (thread && thread->fctx.fpustorage) {
                CPU::restorefctx(&thread->fctx);
                thread->fctx.mathused = true;
            }
            return;
        }
#endif
        assert(false, "Invalid FPU lazy restore!\n");
    }

    // Update minvruntime after removing the leftmost thread. Must hold cpu->runqueue.lock.
    static void updateminvruntime(struct CPU::cpulocal *cpu) {
        RBTree::node *first = cpu->runqueue._first();
        if (first) {
            Thread *t = RBTree::getentry<Thread>(first);
            uint64_t newmin = t->getvruntime();
            uint64_t oldmin = __atomic_load_n(&cpu->minvruntime, memory_order_acquire);
            // Only update if new minimum is greater (monotonic increase).
            if (newmin > oldmin) {
                __atomic_store_n(&cpu->minvruntime, newmin, memory_order_release);
            }
        }
        // If queue is empty, leave minvruntime unchanged.
    }

    // Update minvruntime after inserting a thread (might lower the minimum). Must hold cpu->runqueue.lock.
    static void updateminvruntimeoninsert(struct CPU::cpulocal *cpu, Thread *thread) {
        uint64_t newvrt = thread->getvruntime();
        uint64_t oldmin = __atomic_load_n(&cpu->minvruntime, memory_order_acquire);
        if (newvrt < oldmin || oldmin == 0) {
            __atomic_store_n(&cpu->minvruntime, newvrt, memory_order_release);
        }
    }

    static struct CPU::cpulocal *getbusiest(void) {
        struct CPU::cpulocal *busiest = NULL;
        uint64_t maxload = STEALTHRESHOLD * 1024; // Minimum threshold.

        for (size_t i = 0; i < SMP::awakecpus; i++) {
            struct CPU::cpulocal *cpu = SMP::cpulist[i];
            uint64_t load = __atomic_load_n(&cpu->loadweight, memory_order_acquire);
            if (load > maxload) {
                maxload = load;
                busiest = cpu;
            }
        }
        return busiest;
    }

    static struct CPU::cpulocal *getidlest(void) {
        struct CPU::cpulocal *idlest = NULL;
        uint64_t minload = __UINT64_MAX__;

        for (size_t i = 0; i < SMP::awakecpus; i++) {
            struct CPU::cpulocal *cpu = SMP::cpulist[i];
            uint64_t load = __atomic_load_n(&cpu->loadweight, memory_order_acquire);
            if (load < minload) {
                minload = load;
                idlest = cpu;
            }
        }
        return idlest;
    }

    // Update load weight for a CPU based on its runqueue size.
    void updateload(struct CPU::cpulocal *cpu) {
        size_t num = cpu->runqueue.count();

        uint64_t oldload = __atomic_load_n(&cpu->loadweight, memory_order_acquire);
        uint64_t newload = (oldload * 3 + num * 1024) / 4;
        __atomic_store_n(&cpu->loadweight, newload, memory_order_release);

    }

    void loadbalance(struct CPU::cpulocal *cpu) {
        // Skip if we're not overloaded.
        if (cpu->runqueue.count() <= LOADTHRESHOLD) {
            return;
        }

        struct CPU::cpulocal *target = getidlest();
        if (!target || target == cpu) {
            return;
        }

        // Migrate up to 1/4 of our excess work.
        size_t quota = (cpu->runqueue.count() - LOADTHRESHOLD) / 4;
        if (quota == 0) quota = 1;

        cpu->runqueue.lock.acquire();

        size_t migrated = 0;
        size_t checked = 0;
        size_t maxcheck = cpu->runqueue.count();

        RBTree::node *candidate = cpu->runqueue._last();

        while (migrated < quota && candidate && checked < maxcheck) {
            Thread *thread = RBTree::getentry<Thread>(candidate);
            RBTree::node *prev = cpu->runqueue._prev(candidate);

            // Check if this thread can be migrated.
            if (!__atomic_load_n(&thread->migratedisabled, memory_order_acquire) &&
                __atomic_load_n(&thread->locksheld, memory_order_acquire) == 0 &&
                thread->gettargetmode() != Thread::target::STRICT) {

                cpu->runqueue._erase(candidate);
                __atomic_store_n(&thread->inrunqueue, false, memory_order_release);

                cpu->runqueue.lock.release();

                // Normalize vruntime to target's minvruntime before inserting.
                uint64_t targetmin = __atomic_load_n(&target->minvruntime, memory_order_acquire);
                uint64_t curvrt = thread->getvruntime();
                if (curvrt < targetmin) {
                    thread->setvruntimeabs(targetmin);
                }

                // Insert into target's queue.
                __atomic_store_n(&thread->cid, target->id, memory_order_release);

                target->runqueue.lock.acquire();
                __atomic_store_n(&thread->inrunqueue, true, memory_order_release);
                target->runqueue._insert(&thread->node, vruntimecmp);
                updateminvruntimeoninsert(target, thread);
                target->runqueue.lock.release();

                migrated++;
                cpu->runqueue.lock.acquire();

                // Restart from end after tree modification.
                candidate = cpu->runqueue._last();
                checked = 0;
            } else {
                // Can't migrate this one, try the previous.
                candidate = prev;
                checked++;
            }
        }

        cpu->runqueue.lock.release();
    }


    static Thread *steal(void) {
        struct CPU::cpulocal *victim = getbusiest();
        if (!victim || victim == CPU::get()) {
            return NULL;
        }

        victim->runqueue.lock.acquire();

        // Scan from the back (highest vruntime = least urgent).
        RBTree::node *candidate = victim->runqueue._last();
        while (candidate) {
            Thread *thread = RBTree::getentry<Thread>(candidate);

            // Safety checks for migration eligibility.
            if (!__atomic_load_n(&thread->migratedisabled, memory_order_acquire) &&
                __atomic_load_n(&thread->locksheld, memory_order_acquire) == 0 &&
                thread->gettargetmode() != Thread::target::STRICT) {

                victim->runqueue._erase(candidate);

                // Clear inrunqueue flag.
                __atomic_store_n(&thread->inrunqueue, false, memory_order_release);

                // Update cid to reflect new owner (the stealing CPU).
                __atomic_store_n(&thread->cid, CPU::get()->id, memory_order_release);

                // Update victim's minvruntime.
                updateminvruntime(victim);

                victim->runqueue.lock.release();
                return thread;
            }
            candidate = victim->runqueue._prev(candidate);
        }

        victim->runqueue.lock.release();
        return NULL;
    }

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

    Thread *nextthread(void) {
        struct CPU::cpulocal *cpu = CPU::get();

        // Fast path: pop from our own runqueue.
        cpu->runqueue.lock.acquire();
        RBTree::node *first = cpu->runqueue._first();
        if (first) {
            Thread *thread = RBTree::getentry<Thread>(first);
            cpu->runqueue._erase(first);

            // Clear inrunqueue flag while holding lock.
            __atomic_store_n(&thread->inrunqueue, false, memory_order_release);

            // Update minvruntime to next thread.
            updateminvruntime(cpu);

            cpu->runqueue.lock.release();
            return thread;
        }
        cpu->runqueue.lock.release();

        // Slow path: try to steal work.
        return steal();
    }

    static void switchthread(Thread *thread, bool needswap) {
        struct CPU::cpulocal *cpu = CPU::get();

        // Swap address space if switching to a different process.
        if (needswap && thread->process && thread->process->addrspace) {
#ifdef __x86_64__
            swaptopml4(thread->process->addrspace->pml4phy);
#endif
        }

#ifdef __x86_64__
        // Reset FPU state for lazy loading.
        thread->fctx.mathused = false;
        // Set TS bit so FPU context is lazily loaded.
        uint64_t cr0 = CPU::rdcr0();
        CPU::wrcr0(cr0 | (1 << 3)); // CR0.TS = 1
#endif

        // Restore extra context (FSBASE, etc).
        CPU::restorexctx(&thread->xctx);

        // Update kernel stack pointer in TSS for syscalls.
        cpu->ist.rsp0 = (uint64_t)thread->stacktop;

        // Set thread state to running.
        setthreadstate(thread, Thread::state::RUNNING, "sched:switchthread");

        // Update current thread pointer.
        cpu->currthread = thread;

        // Perform the actual context switch.
        CPU::ctx_swap(&thread->ctx);
    }

    // Scheduler interrupt handler.
    void schedule(struct Interrupts::isr *isr, struct CPU::context *ctx) {
        struct CPU::cpulocal *cpu = CPU::get();

        // Prevent nested scheduler invocation.
        if (__atomic_exchange_n(&cpu->inschedule, true, memory_order_acquire)) {
            return;
        }

        uint64_t now = TSC::query();
        Thread *prev = cpu->currthread;

        // Protect prev from being stolen while we're using it.
        if (prev && prev != cpu->idlethread) {
            prev->disablemigrate();
        }

        // 1. Calculate time delta and update vruntime.
        uint64_t delta = now - cpu->lastschedts;
        cpu->lastschedts = now;

        if (prev && prev != cpu->idlethread) {
            prev->setvruntime(delta);
        }

        // 2. Update load weight periodically.
        updateload(cpu);

        // 3. Load balance every N quantums (e.g., every 4 = 40ms).
        if ((cpu->schedintr % 4) == 0) {
            loadbalance(cpu);
        }
        cpu->schedintr++;

        // 4. Check process itimer.
        if (prev && prev->process && !prev->process->kernel) {
            checkitimer(prev->process, now);
        }

        // 5. Save context of previous thread.
        if (prev) {
            prev->savectx(ctx);
            prev->savexctx();

            // Handle pending state transitions.
            enum Thread::pendingwait pendwait =
                (enum Thread::pendingwait)__atomic_exchange_n(
                    &prev->pendingwaitstate,
                    Thread::pendingwait::PENDING_NONE,
                    memory_order_acq_rel);

            // Check if wake() raced ahead and already woke this thread.
            // If wokenbeforewait is set, the thread should stay runnable, not transition to WAITING.
            bool woken = __atomic_exchange_n(&prev->wokenbeforewait, false, memory_order_acq_rel);

            if (!woken && pendwait == Thread::pendingwait::PENDING_WAIT) {
                setthreadstate(prev, Thread::state::WAITING, "sched:PENDING_WAIT");
            } else if (!woken && pendwait == Thread::pendingwait::PENDING_WAITINT) {
                setthreadstate(prev, Thread::state::WAITINGINT, "sched:PENDING_WAITINT");
            }
        }

        // 6. Re-insert previous thread if still runnable (skip idle thread).
        enum Thread::state prevstate = prev ?
            (enum Thread::state)__atomic_load_n(&prev->tstate, memory_order_acquire) :
            Thread::state::DEAD;

        if (prev && prev != cpu->idlethread && prevstate == Thread::state::RUNNING) {
            setthreadstate(prev, Thread::state::SUSPENDED, "sched:reinsert");

            // Insert back into runqueue with inrunqueue guard.
            cpu->runqueue.lock.acquire();
            if (!__atomic_load_n(&prev->inrunqueue, memory_order_acquire)) {
                __atomic_store_n(&prev->inrunqueue, true, memory_order_release);
                cpu->runqueue._insert(&prev->node, vruntimecmp);
                updateminvruntimeoninsert(cpu, prev);
            }
            cpu->runqueue.lock.release();
        }

        bool shouldqueuezombie = false;
        Thread *zombiethread = NULL;

        // Handle dead thread cleanup.
        if (prev && prev != cpu->idlethread && prevstate == Thread::state::DEAD) {
            if (!__atomic_exchange_n(&prev->zombiequeued, true, memory_order_acq_rel)) {
                shouldqueuezombie = true;
                zombiethread = prev; // Save reference for zombie queueing.
            }
        }

        // Save prev reference for migration re-enable AFTER thread selection.
        // We must not enable migration before nextthread() because that would allow the thread to be stolen.
        Thread *prevformigration = (prev && prev != cpu->idlethread) ? prev : NULL;

        cpu->setint(true);
        // Reap zombies.
        reapzombies();
        cpu->setint(false);

        // 7. Select next thread.
        Thread *next = nextthread();
        if (!next) {
            next = cpu->idlethread;
#ifdef TSTATE_DEBUG
            cpu->idlecount++;
            // After 1000 consecutive idle selections (~10 seconds), dump state for debugging.
            if (cpu->idlecount == 1000) {
                NUtil::printf("[sched] CPU%lu: 1000 consecutive idle selections elapsed, dumping thread state:\n", cpu->id);
                dumpthreads();
            }
        } else {
            cpu->idlecount = 0; // Reset on non-idle selection.
        }
#else
        }
#endif

        if (prevformigration && prevformigration != next) {
            prevformigration->enablemigrate(); // Safe to re-enable now.
        }

        // 8. Handle migration re-enable.
        if (next->rescheduling) {
            __atomic_store_n(&next->rescheduling, false, memory_order_release);
            next->enablemigrate();
        }

        // 9. Update CPU tracking.
        __atomic_store_n(&next->lastcid, next->cid, memory_order_release);
        __atomic_store_n(&next->cid, cpu->id, memory_order_release);

        // 10. Context switch if needed.
        if (next != cpu->currthread) {
            bool needswap = !cpu->currthread || (cpu->currthread->process != next->process);

            if (shouldqueuezombie && zombiethread) {
                queuezombie(zombiethread);
            }


            // Reset quantum deadline and re-arm timer before switch.
            cpu->quantumdeadline = now + (TSC::hz / 1000) * QUANTUMMS;
            Timer::rearm();

            __atomic_store_n(&cpu->inschedule, false, memory_order_release);
            switchthread(next, needswap);

            // XXX: There are STILL niche cases where we can end up back here for no good reason. Typically while in the middle of a system call that blocks on a waitqueue.

            // Print current register state.
            uint64_t rax = 0, rbx = 0, rcx = 0, rdx = 0;
            uint64_t rsi = 0, rdi = 0, rsp = 0, rbp = 0;
            uint64_t r8 = 0, r9 = 0, r10 = 0, r11 = 0;
            uint64_t r12 = 0, r13 = 0, r14 = 0, r15 = 0;
            asm volatile("mov %%rax, %0" : "=r"(rax));
            asm volatile("mov %%rbx, %0" : "=r"(rbx));
            asm volatile("mov %%rcx, %0" : "=r"(rcx));
            asm volatile("mov %%rdx, %0" : "=r"(rdx));
            asm volatile("mov %%rsi, %0" : "=r"(rsi));
            asm volatile("mov %%rdi, %0" : "=r"(rdi));
            asm volatile("mov %%rsp, %0" : "=r"(rsp));
            asm volatile("mov %%rbp, %0" : "=r"(rbp));
            asm volatile("mov %%r8, %0" : "=r"(r8));
            asm volatile("mov %%r9, %0" : "=r"(r9));
            asm volatile("mov %%r10, %0" : "=r"(r10));
            asm volatile("mov %%r11, %0" : "=r"(r11));
            asm volatile("mov %%r12, %0" : "=r"(r12));
            asm volatile("mov %%r13, %0" : "=r"(r13));
            asm volatile("mov %%r14, %0" : "=r"(r14));
            asm volatile("mov %%r15, %0" : "=r"(r15));

            NUtil::printf("[sched] BUG: Returned to scheduler interrupt handler unexpectedly!\n");
            NUtil::printf(" Registers after switch: RAX=%#018lx RBX=%#018lx RCX=%#018lx RDX=%#018lx\n",
                rax, rbx, rcx, rdx);
            NUtil::printf(" RSI=%#018lx RDI=%#018lx RSP=%#018lx RBP=%#018lx\n",
                rsi, rdi, rsp, rbp);
            NUtil::printf(" R8=%#018lx R9=%#018lx R10=%#018lx R11=%#018lx\n",
                r8, r9, r10, r11);
            NUtil::printf(" R12=%#018lx R13=%#018lx R14=%#018lx R15=%#018lx\n",
                r12, r13, r14, r15);

            // Print "current thread" context.
            Thread *curr = CPU::get()->currthread;
            NUtil::printf(" Current thread after switch: %p (pid=%lu tid=%lu)\n",
                curr,
                curr->process ? curr->process->id : 0,
                curr->id);
            // Print its registers.
            rax = curr->ctx.rax;
            rbx = curr->ctx.rbx;
            rcx = curr->ctx.rcx;
            rdx = curr->ctx.rdx;
            rsi = curr->ctx.rsi;
            rdi = curr->ctx.rdi;
            rsp = curr->ctx.rsp;
            rbp = curr->ctx.rbp;
            r8 = curr->ctx.r8;
            r9 = curr->ctx.r9;
            r10 = curr->ctx.r10;
            r11 = curr->ctx.r11;
            r12 = curr->ctx.r12;
            r13 = curr->ctx.r13;
            r14 = curr->ctx.r14;
            r15 = curr->ctx.r15;
            NUtil::printf(" Saved context: RAX=%#018lx RBX=%#018lx RCX=%#018lx RDX=%#018lx\n",
                rax, rbx, rcx, rdx);
            NUtil::printf(" RSI=%#018lx RDI=%#018lx RSP=%#018lx RBP=%#018lx\n",
                rsi, rdi, rsp, rbp);
            NUtil::printf(" R8=%#018lx R9=%#018lx R10=%#018lx R11=%#018lx\n",
                r8, r9, r10, r11);
            NUtil::printf(" R12=%#018lx R13=%#018lx R14=%#018lx R15=%#018lx\n",
                r12, r13, r14, r15);

            __builtin_unreachable(); // Don't even THINK about it.
        } else {
            if (prevformigration) {
                prevformigration->enablemigrate(); // Safe to re-enable now.
            }

            // Queue zombie if needed (edge case: thread dying but still selected).
            if (shouldqueuezombie && zombiethread) {
                assertarg(false, "Thread %p (pid=%lu tid=%lu) was marked DEAD but is trying to continue!\n", zombiethread, zombiethread->process ? zombiethread->process->id : 0, zombiethread->id);
            }

            // 11. Continue execution of the same thread.
            Thread *curr = cpu->currthread;
            if (curr && curr->tstate == Thread::state::SUSPENDED) {
                setthreadstate(curr, Thread::state::RUNNING, "sched:continue");
            }

            // 12. Reset quantum deadline and re-arm timer (same thread continues).
            cpu->quantumdeadline = now + (TSC::hz / 1000) * QUANTUMMS;
            Timer::rearm();

            __atomic_store_n(&cpu->inschedule, false, memory_order_release);
        }
    }

    // Idle thread function.
    static void idlework(void) {
        for (;;) {
            asm volatile("hlt");
        }
    }

    void entry(void) {
        Thread *idlethread = new Thread(kprocess, DEFAULTSTACKSIZE, (void *)idlework);
        CPU::get()->idlethread = idlethread;

        idlethread->tstate = Thread::state::RUNNING;

        CPU::get()->schedstack = (uint8_t *)PMM::alloc(DEFAULTSTACKSIZE, PMM::FLAGS_NOTRACK);
        assertarg(CPU::get()->schedstack, "Failed to allocate scheduler stack for CPU%lu.\n", CPU::get()->id);

        CPU::get()->schedstacktop = (uintptr_t)CPU::get()->schedstack + DEFAULTSTACKSIZE;
        CPU::get()->schedstack = (uint8_t *)hhdmoff((void *)((uintptr_t)CPU::get()->schedstack));

        CPU::get()->currthread = idlethread;

        CPU::get()->lastschedts = TSC::query();

        // Register the scheduling interrupt on this CPU.
        Interrupts::regisr(0xfe, schedule, true);
        await();
    }

    // BSP scheduler setup.
    void setup(void) {
        pidtable = new NLib::KVHashMap<size_t, Process *>();

        kprocess = new Process(&VMM::kspace);
        pidtable->insert(kprocess->id, kprocess);

        Thread *idlethread = new Thread(kprocess, DEFAULTSTACKSIZE, (void *)idlework);
        idlethread->tstate = Thread::state::RUNNING;

        CPU::get()->schedstack = (uint8_t *)PMM::alloc(DEFAULTSTACKSIZE, PMM::FLAGS_NOTRACK);
        assertarg(CPU::get()->schedstack, "Failed to allocate scheduler stack for CPU%lu.\n", CPU::get()->id);
        CPU::get()->schedstacktop = (uintptr_t)CPU::get()->schedstack + DEFAULTSTACKSIZE;
        CPU::get()->schedstack = (uint8_t *)hhdmoff((void *)((uintptr_t)CPU::get()->schedstack));

        CPU::get()->idlethread = idlethread;
        CPU::get()->currthread = idlethread;
        CPU::get()->lastschedts = TSC::query();

        // Register the scheduling interrupt on this CPU.
        Interrupts::regisr(0xfe, schedule, true);

        initialised = true;
    }

    // Schedule a thread onto a CPU's runqueue.
    void schedulethread(Thread *thread) {
        // Guard: Don't insert if already in a runqueue.
        if (__atomic_load_n(&thread->inrunqueue, memory_order_acquire)) {
            return; // Already queued, nothing to do.
        }

        // Determine target CPU.
        struct CPU::cpulocal *target;

        if (thread->gettargetmode() == Thread::target::STRICT) {
            // Strict targeting REFUSES to let the scheduler choose another CPU.
            target = SMP::cpulist[thread->gettarget()];
        } else {
            // Prefer last CPU (cache affinity), otherwise use idlest.
            size_t lastcid = __atomic_load_n(&thread->lastcid, memory_order_acquire);
            if (lastcid < SMP::awakecpus) {
                target = SMP::cpulist[lastcid];
            } else {
                target = getidlest();
            }
            if (!target) target = CPU::get();
        }

        // Normalize vruntime to target's minvruntime (lock-free read).
        uint64_t targetmin = __atomic_load_n(&target->minvruntime, memory_order_acquire);
        uint64_t curvrt = thread->getvruntime();
        if (curvrt < targetmin) {
            // Prevent newly woken threads from starving existing ones.
            thread->setvruntimeabs(targetmin);
        }

        // Set thread state.
        setthreadstate(thread, Thread::state::SUSPENDED, "schedulethread");
        __atomic_store_n(&thread->cid, target->id, memory_order_release);

        // Insert into runqueue with inrunqueue guard.
        target->runqueue.lock.acquire();

        // Double-check inrunqueue under lock (another CPU might have beaten us).
        if (!__atomic_load_n(&thread->inrunqueue, memory_order_acquire)) {
            __atomic_store_n(&thread->inrunqueue, true, memory_order_release);
            target->runqueue._insert(&thread->node, vruntimecmp);
            updateminvruntimeoninsert(target, thread);
        }

        target->runqueue.lock.release();

        // Wake idle CPU if needed.
        if (target != CPU::get() && target->currthread == target->idlethread) {
            APIC::sendipi(target->lapicid, 0xfe, APIC::IPIFIXED, APIC::IPIPHYS, 0);
        }
    }

    // Voluntarily relinquish the CPU.
    void yield(void) {
        struct CPU::cpulocal *cpu = CPU::get();
        Thread *thread = cpu->currthread;

        // Thanks, twin. For this, you get a little bit of a bonus! Encourages I/O work to yield.
        uint64_t bonus = (TSC::hz / 1000) * QUANTUMMS / 2; // Half a quantum.
        uint64_t curvrt = thread->getvruntime();
        if (curvrt > bonus) {
            // Subtract bonus from current vruntime (slightly more appealing to the scheduler).
            thread->setvruntimeabs(curvrt - bonus);
        }

        // Trigger scheduler interrupt via software interrupt.
        asm volatile("int $0xfe");
    }

    // Sleep for a given number of milliseconds.
    int sleep(uint64_t ms) {
        if (ms == 0) {
            yield();
            return 0;
        }

        WaitQueue wq;
        volatile bool expired = false;

        // Timer state passed to callback.
        struct sleepstate {
            volatile bool *exp;
            WaitQueue *wq;
        };

        struct sleepstate state = { &expired, &wq };

        // Timer callback to wake the waitqueue.
        auto callback = [](void *arg) {
            struct sleepstate *st = (struct sleepstate *)arg;
            *st->exp = true;
            st->wq->wake();
        };

        NSys::Timer::create(callback, (void *)&state, ms);

        int ret;
        waiteventinterruptible(&wq, expired, ret);

        return ret;
    }

    // Force reschedule of a specific thread.
    void reschedule(Thread *thread) {
        thread->disablemigrate();
        __atomic_store_n(&thread->rescheduling, true, memory_order_release);

        size_t targetcid = __atomic_load_n(&thread->cid, memory_order_acquire);

        if (targetcid == CPU::get()->id) {
            // Self-reschedule. The scheduler will clear rescheduling and re-enable migration.
            asm volatile("int $0xfe");
        } else if (targetcid < SMP::awakecpus) {
            // Send IPI to target CPU. The scheduler on that CPU will handle cleanup.
            APIC::sendipi(SMP::cpulist[targetcid]->lapicid, 0xfe, APIC::IPIFIXED, APIC::IPIPHYS, 0);
        } else {
            // Cleanup weird CID state.
            __atomic_store_n(&thread->rescheduling, false, memory_order_release);
            thread->enablemigrate();
        }
    }

    // Terminate all other threads in a process except the calling thread.
    void termothers(Process *proc) {
        Thread *current = CPU::get()->currthread;

        // Collect threads to terminate while holding lock.
        NLib::SingleList<Thread *> toexit;

        proc->lock.acquire();

        auto it = proc->threads.begin();
        while (it.valid()) {
            Thread *thread = *it.get();
            it.next();

            if (thread == current) continue;
            toexit.push(thread);
        }

        proc->lock.release();

        // Now process each thread without holding proc->lock.
        while (!toexit.empty()) {
            Thread *thread = toexit.pop();

            // Disable migration to stabilize cid for this thread.
            thread->disablemigrate();

            enum Thread::state state = (enum Thread::state)__atomic_load_n(&thread->tstate, memory_order_acquire);

            // Remove from waitqueue if present (do this regardless of state).
            thread->waitingonlock.acquire();
            WaitQueue *wq = thread->waitingon;
            thread->waitingonlock.release();

            if (wq) {
                wq->dequeue(thread);
            }

            // Mark dead.
            setthreadstate(thread, Thread::state::DEAD, "termothers");

            // Handle based on original state.
            if (state == Thread::state::RUNNING) {
                // Thread is/was running. Get cid while migration is disabled.
                size_t cid = __atomic_load_n(&thread->cid, memory_order_acquire);

                thread->enablemigrate();

                // Send IPI to force that CPU to reschedule and handle the dead thread.
                if (cid < SMP::awakecpus && cid != CPU::get()->id) {
                    APIC::sendipi(SMP::cpulist[cid]->lapicid, 0xfe, APIC::IPIFIXED, APIC::IPIPHYS, 0);
                }
            } else { // Simply remove from runqueue if needed.
                size_t cid = __atomic_load_n(&thread->cid, memory_order_acquire);
                if (cid < SMP::awakecpus && __atomic_load_n(&thread->inrunqueue, memory_order_acquire)) {
                    struct CPU::cpulocal *cpu = SMP::cpulist[cid];
                    cpu->runqueue.lock.acquire();
                    if (__atomic_load_n(&thread->inrunqueue, memory_order_acquire)) {
                        cpu->runqueue._erase(&thread->node);
                        __atomic_store_n(&thread->inrunqueue, false, memory_order_release);
                        updateminvruntime(cpu);
                    }
                    cpu->runqueue.lock.release();
                }

                thread->enablemigrate();

                // Force reschedule to ensure cleanup happens.
                reschedule(thread);
            }
        }
    }

    void await(void) {
        CPU::get()->setint(false);

        // Set initial quantum deadline.
        CPU::get()->quantumdeadline = TSC::query() + (TSC::hz / 1000) * QUANTUMMS;
        CPU::get()->preemptdisabled = false; // Enable preemption.
        Timer::rearm(); // Arm timer so we get scheduled.

        // Enable interrupts outside of critical section.
        CPU::get()->setint(true);

        for (;;) {
            asm volatile("hlt");
        }
    }
}