#ifndef _SCHED__WORKQUEUE_HPP
#define _SCHED__WORKQUEUE_HPP

#include <sched/event.hpp>
#include <sched/sched.hpp>

namespace NSched {
    enum workflags {
        WORK_PENDING      = (1 << 0), // Work item is pending execution.
        WORK_DELAYED      = (1 << 1), // Work item is delayed.
        WORK_CANCELING    = (1 << 2)  // Work item is being cancelled.
    };


    struct work;
    typedef void (*workfunc_t)(struct work *);

    // Work item.
    struct work {
        workfunc_t func; // Function to call.
        uint32_t flags; // Work item flags.

        void *udata; // User data pointer.

        struct work *next;
        struct work *prev;

        class WorkQueue *wq; // Owning workqueue.
        class WorkerPool *pool; // Owning worker pool.

        uint64_t timer;
    };

    // Flags passed to WorkQueue constructor, controls its behaviour.
    enum wqflags {
        WQ_UNBOUND        = (1 << 0),  // Unbound workqueue, can run on any CPU.
        WQ_HIGHPRI        = (1 << 1),  // High priority workqueue (pulls from high priority pool, high priority worker threads are favoured more by the scheduler).
        WQ_INTENSIVE      = (1 << 2),  // CPU intensive workqueue (isn't considered when it comes to concurrency).
        WQ_DRAINING       = (1 << 3)   // Workqueue is draining (clean up, we don't want to accept new work).
    };

    class WorkQueue {
        public:
            const char *name;
            uint32_t flags;
            WorkerPool *custompool; // Optional custom pool.

            WorkQueue(const char *name, uint32_t flags) {
                this->name = name;
                flags &= ~WQ_DRAINING;
                this->flags = flags;
                this->custompool = NULL;
            }

            WorkQueue(const char *name, uint32_t flags, WorkerPool *pool);

            // Queue work, get it done whenever the workqueue feels like it.
            bool queue(struct work *w);
            // Queue work, but draw from a specific CPU's worker pool.
            bool queueon(int cpu, struct work *w);

            // Queue some work, but delay its execution by delayms milliseconds.
            bool queuedelayed(struct work *w, uint64_t delayms);

            // Cancel queued work, returns false if it was already done, and we missed our window to cancel it.
            bool cancel(struct work *w);
            void flush(void);
            void drain(void);

            // Workqueue subsystem initialisation.
            static void init(void);
        private:
            WorkerPool *getpoolforwork(void);
    };

    static inline void initwork(struct work *w, workfunc_t func, void *udata = NULL) {
        w->func = func;
        w->flags = 0;
        w->udata = udata;
        w->next = NULL;
        w->prev = NULL;
        w->wq = NULL;
        w->pool = NULL;
        w->timer = 0;
    }

    class WorkerPool {
        public:
            NArch::IRQSpinlock lock;

            struct work *worklisthead;
            struct work *worklisttail;
            size_t pendingcount;

            WaitQueue workwq;
            NLib::Vector<Thread *> workers; // Worker threads will be created with STRICT target to this pool's cid (or RELAXED for unbound).
            size_t idlecount;
            size_t activecount;
            size_t intensivecount; // Workers currently running CPU-intensive work (don't count toward concurrency).

            int cid; // CPU affinity for this pool (-1 indicates unbound).
            uint32_t flags;

            size_t maxworkers;
            size_t minworkers;
            uint64_t lastidle; // Last idle timestamp.

            volatile bool exiting; // Atomic exit state.

            WorkerPool(int cpu = -1, uint32_t flags = 0, size_t minworkers = 1, size_t maxworkers = 0);
            ~WorkerPool(void);

            void addwork(struct work *w);
            struct work *getwork(void);

            void wakeworker(void);
            void spawnworker(void);
            bool maybespawnworker(void); // Spawn worker if needed and under limit.

            // Worker pool subsystem initialisation.
            static void init(void);
    };

    // Global unbound pools.
    extern WorkerPool *unboundworkpool;
    extern WorkerPool *priounboundworkpool;

    // General purpose bound workqueue (work dispatched will run workers from its CPU-bound pools).
    extern WorkQueue *systemwq;
    // General purpose high-priority bound workqueue (ditto).
    extern WorkQueue *systempriowq;
    // General purpose unbound workqueue (work dispatched will run on any CPU, generally better for generic long-running work).
    extern WorkQueue *systemunboundwq;

    // Wait for a specific work item to complete. Does nothing (and returns false) if the work is not pending or running (or is completed already).
    bool flushwork(struct work *w);

    // Convenience functions for system workqueue.
    static inline bool schedulework(struct work *w) {
        return systemwq->queue(w);
    }

    static inline bool scheduleworkdelayed(struct work *w, uint64_t delayms) {
        return systemwq->queuedelayed(w, delayms);
    }

    static inline bool scheduleworkon(int cpu, struct work *w) {
        return systemwq->queueon(cpu, w);
    }
}


#endif