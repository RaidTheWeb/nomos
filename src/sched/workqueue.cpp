#ifdef __x86_64__
#include <arch/x86_64/cpu.hpp>
#include <arch/x86_64/smp.hpp>
#include <arch/x86_64/tsc.hpp>
#endif
#include <sched/workqueue.hpp>
#include <sys/timer.hpp>
#include <util/kprint.hpp>

namespace NSched {
    WorkerPool *unboundworkpool = NULL;
    WorkerPool *priounboundworkpool = NULL;

    WorkQueue *systemwq = NULL;
    WorkQueue *systempriowq = NULL;
    WorkQueue *systemunboundwq = NULL;

    static void workerentry(void *arg);

    WorkQueue::WorkQueue(const char *name, uint32_t flags, WorkerPool *pool) {
        this->name = name;
        this->flags = flags & ~WQ_DRAINING;
        this->custompool = pool;
    }

    WorkerPool::WorkerPool(int cpu, uint32_t pflags, size_t minw, size_t maxw) {
        this->worklisthead = NULL;
        this->worklisttail = NULL;
        this->pendingcount = 0;
        this->idlecount = 0;
        this->activecount = 0;
        this->intensivecount = 0;
        this->cid = cpu;
        this->flags = pflags;
        this->minworkers = minw;
        this->maxworkers = maxw;
        this->lastidle = 0;
        this->exiting = false;
    }

    WorkerPool::~WorkerPool(void) {
        // Signal all workers to exit.
        this->lock.acquire();
        this->exiting = true;
        this->lock.release();

        // Wake all workers so they can see the exit flag.
        this->workwq.wake();

        // XXX: Await worker thread exits and cleanup.
    }

    void WorkerPool::addwork(struct work *w) {
        bool shouldwake = false;
        bool shouldspawn = false;

        this->lock.acquire();

        // Link to tail of list.
        w->next = NULL;
        w->prev = this->worklisttail;
        w->pool = this;
        __atomic_or_fetch(&w->flags, WORK_PENDING, memory_order_release);

        if (this->worklisttail) {
            this->worklisttail->next = w;
        } else {
            this->worklisthead = w;
        }
        this->worklisttail = w;
        this->pendingcount++;

        // Wake a worker if any are idle.
        if (this->idlecount > 0) {
            shouldwake = true;
        } else {
            // Effective concurrency excludes intensive workers.
            size_t effectiveactive = this->activecount - this->intensivecount;
            if ((effectiveactive > 0 || this->pendingcount > 0) && this->workers.getsize() < this->maxworkers) {
                shouldspawn = true;
            }
        }

        this->lock.release();

        if (shouldwake) {
            this->workwq.wakeone();
        }

        if (shouldspawn) {
            this->maybespawnworker();
        }
    }

    struct work *WorkerPool::getwork(void) {
        // Caller must hold pool lock.
        if (this->worklisthead == NULL) {
            return NULL; // No work!
        }

        struct work *w = this->worklisthead;
        this->worklisthead = w->next;

        if (this->worklisthead) {
            this->worklisthead->prev = NULL;
        } else {
            this->worklisttail = NULL;
        }

        w->next = NULL;
        w->prev = NULL;
        __atomic_and_fetch(&w->flags, ~WORK_PENDING, memory_order_release); // Mark work as no longer pending.
        this->pendingcount--;

        return w;
    }

    void WorkerPool::wakeworker(void) {
        // Caller must hold pool lock.
        if (this->idlecount > 0) {
            this->workwq.wakeone();
        }
    }

    void WorkerPool::spawnworker(void) {
        // Create a new worker thread.
        Thread *worker = new Thread(
            kprocess,
            DEFAULTSTACKSIZE,
            (void *)workerentry,
            (void *)this
        );

        // Set CPU affinity for bound pools.
        if (this->cid >= 0) {
            worker->setaffinity((uint32_t)this->cid);
            worker->settmode(Thread::target::STRICT); // Mark strict so the scheduler knows it's for this CPU only.
        } else {
            worker->settmode(Thread::target::RELAXED);
        }

        if (this->flags & WQ_HIGHPRI) {
            worker->setnice(-10); // High priority workqueue workers get boosted priority. XXX: Tune this later.
        }

        this->lock.acquire();
        this->workers.push(worker);
        this->lock.release();

        schedulethread(worker);
    }

    bool WorkerPool::maybespawnworker(void) {
        this->lock.acquire();

        // Check if we should spawn under the lock.
        size_t effectiveactive = this->activecount - this->intensivecount;
        bool shouldspawn = (this->idlecount == 0) &&
                           (effectiveactive > 0 || this->pendingcount > 0) &&
                           (this->workers.getsize() < this->maxworkers);

        this->lock.release();

        if (shouldspawn) {
            this->spawnworker();
            return true;
        }
        return false;
    }

    // Thread entry for worker threads.
    static void workerentry(void *arg) {
        WorkerPool *pool = (WorkerPool *)arg;

        for (;;) {
            struct work *w = NULL;

            pool->lock.acquire();

            // Wait for work if queue is empty.
            while (pool->worklisthead == NULL && !pool->exiting) {
                pool->idlecount++; // Increase our idle count so addwork can wake us.

                // Add ourselves to wait list BEFORE releasing pool->lock.
                pool->workwq.waitinglock.acquire();
                pool->lock.release();

                pool->workwq.preparewait();
                pool->workwq.waitinglock.release();

                yield(); // Wait for work. We'll be woken up when work is added.

                pool->workwq.waitinglock.acquire();
                pool->workwq.finishwait(true);
                pool->workwq.waitinglock.release();

                pool->lock.acquire();
                pool->idlecount--;
            }

            if (pool->exiting) { // Automatically exit worker threads if pool is being destroyed.
                pool->lock.release();
                break;
            }

            // Dequeue work.
            w = pool->getwork();
            if (w) {
                pool->activecount++;

                // Check if this is CPU-intensive work.
                bool intensive = w->wq && (w->wq->flags & WQ_INTENSIVE);
                if (intensive) {
                    pool->intensivecount++;
                }

                pool->lock.release();

                // Execute work outside of lock.
                if (w->func) {
                    w->func(w);
                }

                pool->lock.acquire();

                if (intensive) {
                    pool->intensivecount--;
                }
                pool->activecount--;

                pool->lock.release();
            } else {
                pool->lock.release();
            }
        }

        exit(0);
    }

    WorkerPool *WorkQueue::getpoolforwork(void) {
        // Use custom pool if set.
        if (this->custompool) {
            return this->custompool;
        }

        bool highpri = (this->flags & WQ_HIGHPRI) != 0;
        bool unbound = (this->flags & WQ_UNBOUND) != 0;

        if (unbound) {
            return highpri ? priounboundworkpool : unboundworkpool;
        } else {
            // Use per-CPU pool.
            struct NArch::CPU::cpulocal *cpu = NArch::CPU::get();
            return highpri ? cpu->prioworkpool : cpu->workpool;
        }
    }

    bool WorkQueue::queue(struct work *w) {
        // Check if already pending.
        if (__atomic_load_n(&w->flags, memory_order_acquire) & WORK_PENDING) {
            return false;
        }

        WorkerPool *pool = this->getpoolforwork();
        if (!pool) {
            return false;
        }

        w->wq = this;
        pool->addwork(w);

        return true;
    }

    bool WorkQueue::queueon(int cpu, struct work *w) {
        // Check if already pending.
        if (__atomic_load_n(&w->flags, memory_order_acquire) & WORK_PENDING) {
            return false;
        }

        bool highpri = (this->flags & WQ_HIGHPRI) != 0;

        // Get the target CPU's pool.
        WorkerPool *pool = NULL;
        if (cpu < 0 || (size_t)cpu >= NArch::SMP::awakecpus) {
            // Invalid CPU, use unbound.
            pool = highpri ? priounboundworkpool : unboundworkpool;
        } else {
            struct NArch::CPU::cpulocal *cpudata = NArch::SMP::cpulist[cpu];
            pool = highpri ? cpudata->prioworkpool : cpudata->workpool;
        }

        if (!pool) {
            return false;
        }

        w->wq = this;
        pool->addwork(w);

        return true;
    }

    // Timer callback for delayed work.
    static void delayedworkcallback(void *arg) {
        struct work *w = (struct work *)arg;

        // Check if work was canceled before timer fired.
        uint32_t flags = __atomic_load_n(&w->flags, memory_order_acquire);
        if (flags & WORK_CANCELING) {
            // Work was canceled, clear flags and bail out.
            __atomic_and_fetch(&w->flags, ~(WORK_DELAYED | WORK_CANCELING), memory_order_release);
            return;
        }

        // Clear delayed flag.
        __atomic_and_fetch(&w->flags, ~WORK_DELAYED, memory_order_release);

        // Queue for immediate execution. Use atomic load for wq since cancel() may clear it.
        WorkQueue *wq = __atomic_load_n(&w->wq, memory_order_acquire);
        if (wq) {
            wq->queue(w);
        }
    }

    bool WorkQueue::queuedelayed(struct work *w, uint64_t delayms) {
        // Use CAS to atomically set WORK_DELAYED, preventing double-queue races.
        uint32_t expected = 0;
        uint32_t desired = WORK_DELAYED;
        while (!__atomic_compare_exchange_n(&w->flags, &expected, desired,
                false, memory_order_acq_rel, memory_order_acquire)) {
            // If any conflicting flags are set, fail.
            if (expected & (WORK_PENDING | WORK_DELAYED | WORK_CANCELING)) {
                return false;
            }
            // Otherwise retry CAS with updated expected value.
        }

        __atomic_store_n(&w->wq, this, memory_order_release);

        NSys::Timer::timerlock();
        NSys::Timer::create(delayedworkcallback, w, delayms);
        NSys::Timer::timerunlock();

        return true;
    }

    bool WorkQueue::cancel(struct work *w) {
        uint32_t curflags = __atomic_load_n(&w->flags, memory_order_acquire);

        // Handle delayed work (timer cancellation not fully supported yet).
        if (curflags & WORK_DELAYED) {
            // Set WORK_CANCELING so timer callback knows to abort.
            __atomic_or_fetch(&w->flags, WORK_CANCELING, memory_order_release);
            // Clear delayed flag.
            __atomic_and_fetch(&w->flags, ~WORK_DELAYED, memory_order_release);
            // Clear wq atomically so timer callback won't queue.
            __atomic_store_n(&w->wq, (WorkQueue *)NULL, memory_order_release);
            return true;
        }

        // Handle pending work.
        if (curflags & WORK_PENDING) {
            WorkerPool *pool = w->pool;
            if (pool) {
                pool->lock.acquire();

                // Double-check still pending in this pool.
                if ((w->flags & WORK_PENDING) && w->pool == pool) {
                    // Unlink from list.
                    if (w->prev) {
                        w->prev->next = w->next;
                    } else {
                        pool->worklisthead = w->next;
                    }
                    if (w->next) {
                        w->next->prev = w->prev;
                    } else {
                        pool->worklisttail = w->prev;
                    }

                    __atomic_and_fetch(&w->flags, ~WORK_PENDING, memory_order_release);
                    w->next = NULL;
                    w->prev = NULL;
                    w->pool = NULL;
                    pool->pendingcount--;

                    pool->lock.release();
                    return true;
                }

                pool->lock.release();
            }
        }

        return false; // Not pending or already running.
    }

    static void flushbarrierwork(struct work *w) {
        // This is a fairly simple trick: Since work in a queue is, well, queued, we can guarantee that the final bit of work only completes after all other work is done.
        WaitQueue *completionwq = (WaitQueue *)w->udata;
        completionwq->wake(); // Wake the flusher to indicate completion.
    }

    void WorkQueue::flush(void) {
        // Queue a barrier work item and wait for it to complete.
        struct work barrier;
        WaitQueue completionwq;

        initwork(&barrier, flushbarrierwork, &completionwq);

        // Queue the barrier.
        if (!this->queue(&barrier)) {
            return; // Failed to queue, nothing to flush.
        }

        // Wait for barrier to complete. Use atomic load for flags.
        waitevent(&completionwq, !(__atomic_load_n(&barrier.flags, memory_order_acquire) & WORK_PENDING));
    }

    void WorkQueue::drain(void) {
        this->flags |= WQ_DRAINING;
        this->flush();
    }

    bool flushwork(struct work *w) {
        uint32_t flags = __atomic_load_n(&w->flags, memory_order_acquire);
        if (!(flags & WORK_PENDING)) {
            return true; // Not pending, either running or already completed.
        }

        WorkerPool *pool = w->pool;
        if (!pool) {
            return false; // No pool, can't flush.
        }

        struct work barrier;
        WaitQueue completionwq;
        initwork(&barrier, flushbarrierwork, &completionwq);
        pool->lock.acquire();
        flags = __atomic_load_n(&w->flags, memory_order_acquire);
        if (!(flags & WORK_PENDING) || w->pool != pool) {
            pool->lock.release();
            return false; // Not pending, either running or already completed.
        }

        // Insert barrier after the work item. When the barrier completes, we know the work item has also completed.
        barrier.next = w->next;
        barrier.prev = w;
        barrier.pool = pool;
        barrier.wq = w->wq;
        __atomic_or_fetch(&barrier.flags, WORK_PENDING, memory_order_release);

        if (w->next) {
            w->next->prev = &barrier;
        } else {
            pool->worklisttail = &barrier;
        }
        w->next = &barrier;
        pool->pendingcount++;
        pool->lock.release();

        waitevent(&completionwq, !(__atomic_load_n(&barrier.flags, memory_order_acquire) & WORK_PENDING));
        return true;
    }

    void initcpuworkpool(void) {
        struct NArch::CPU::cpulocal *cpu = NArch::CPU::get();

        // Create normal priority pool for this CPU.
        cpu->workpool = new WorkerPool(
            (int)cpu->id,   // CPU ID.
            0,              // No special flags.
            1,              // Min 1 worker.
            4               // Max 4 workers.
        );

        // Create high priority pool for this CPU.
        cpu->prioworkpool = new WorkerPool(
            (int)cpu->id,
            WQ_HIGHPRI,
            1,
            2
        );

        // Spawn initial workers.
        cpu->workpool->spawnworker();
        cpu->prioworkpool->spawnworker();
    }

    void WorkerPool::init(void) {
        // Get CPU count for sizing unbound pools.
        size_t ncpus = NArch::SMP::awakecpus;

        // Create global unbound pools.
        unboundworkpool = new WorkerPool(
            -1,                 // Unbound (no CPU affinity).
            WQ_UNBOUND,
            ncpus,              // Min workers = CPU count.
            ncpus * 4           // Max workers = 4x CPU count.
        );

        priounboundworkpool = new WorkerPool(
            -1,
            WQ_UNBOUND | WQ_HIGHPRI,
            ncpus,
            ncpus * 2
        );

        for (size_t i = 0; i < ncpus; i++) {
            unboundworkpool->spawnworker();
            priounboundworkpool->spawnworker();

            NArch::SMP::cpulist[i]->workpool = new WorkerPool(
                NArch::SMP::cpulist[i]->id,
                0,
                1,
                4
            );

            NArch::SMP::cpulist[i]->prioworkpool = new WorkerPool(
                NArch::SMP::cpulist[i]->id,
                WQ_HIGHPRI,
                1,
                2
            );

            NArch::SMP::cpulist[i]->workpool->spawnworker();
            NArch::SMP::cpulist[i]->prioworkpool->spawnworker();
        }
    }

    void WorkQueue::init(void) {
        // Create global system workqueues.
        systemwq = new WorkQueue("system", 0);
        systempriowq = new WorkQueue("system_highpri", WQ_HIGHPRI);
        systemunboundwq = new WorkQueue("system_unbound", WQ_UNBOUND);
    }

}