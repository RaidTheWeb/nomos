#ifdef __x86_64__
#include <arch/x86_64/cpu.hpp>
#endif
#include <lib/assert.hpp>
#include <lib/errno.hpp>
#include <sched/event.hpp>
#include <sched/signal.hpp>

namespace NSched {

    static inline bool haspendingsignal(Thread *thread) {
        if (!thread || !thread->process) {
            return false;
        }

        // Get pending signals that aren't blocked.
        NLib::sigset_t pending = __atomic_load_n(&thread->process->signalstate.pending, memory_order_acquire);
        NLib::sigset_t blocked = __atomic_load_n(&thread->blocked, memory_order_acquire);
        NLib::sigset_t unblocked = pending & ~blocked;

        return unblocked != 0;
    }

    static Thread *wakeoneinternal(NLib::DoubleList<Thread *> &waiting) {
        while (!waiting.empty()) {
            Thread *thread = waiting.pop();

            __atomic_store_n(&thread->pendingwaitstate, Thread::pendingwait::PENDING_NONE, memory_order_release);

            NArch::CPU::mb();

            // Clear the waitingon pointer while holding waitingonlock.
            thread->waitingonlock.acquire();
            thread->waitingon = NULL;
            thread->waitingonlock.release();

            // Read current state to determine action.
            enum Thread::state curstate = (enum Thread::state)__atomic_load_n(&thread->tstate, memory_order_acquire);

            if (curstate == Thread::state::WAITING || curstate == Thread::state::WAITINGINT) {
                schedulethread(thread);
            }

            return thread;
        }
        return NULL;
    }

    void WaitQueue::preparewait(void) {
        Thread *thread = NArch::CPU::get()->currthread;

        // Set pending wait state FIRST, before adding to list.
        // This ensures signal handlers see the pending state even if list add races.
        __atomic_store_n(&thread->pendingwaitstate, Thread::pendingwait::PENDING_WAIT, memory_order_release);

        // Memory barrier to ensure pendingwaitstate is visible.
        NArch::CPU::writemb();

        // Set waitingon pointer. Lock order: waitinglock (held) -> waitingonlock.
        thread->waitingonlock.acquire();
        assertarg(thread->waitingon == NULL, "preparewait: Thread %p already waiting on %p, cannot add to %p\n", thread, thread->waitingon, this);
        thread->waitingon = this;
        thread->waitingonlock.release();

        // Add to wait list. This is safe because we hold waitinglock.
        this->waiting.pushback(thread);
    }

    bool WaitQueue::preparewaitinterruptible(void) {
        Thread *thread = NArch::CPU::get()->currthread;

        // Check for pending signals before committing to wait.
        if (haspendingsignal(thread)) {
            return true; // Signal pending, caller should not wait.
        }

        // Set pending wait state for interruptible wait.
        __atomic_store_n(&thread->pendingwaitstate, Thread::pendingwait::PENDING_WAITINT, memory_order_release);

        // Memory barrier to ensure pendingwaitstate is visible.
        NArch::CPU::writemb();

        // Set waitingon pointer. Lock order: waitinglock (held) -> waitingonlock.
        thread->waitingonlock.acquire();
        assertarg(thread->waitingon == NULL, "preparewaitinterruptible: Thread %p already waiting on %p, cannot add to %p\n", thread, thread->waitingon, this);
        thread->waitingon = this;
        thread->waitingonlock.release();

        // Add to wait list.
        this->waiting.pushback(thread);

        return false; // Proceed with wait.
    }

    void WaitQueue::finishwait(bool locked) {
        Thread *thread = NArch::CPU::get()->currthread;

        __atomic_store_n(&thread->pendingwaitstate, Thread::pendingwait::PENDING_NONE, memory_order_release);

        if (locked) {
            // Caller holds this->waitinglock.
            thread->waitingonlock.acquire();
            if (thread->waitingon == this) {
                // Remove from this waitqueue's list.
                this->waiting.remove([](Thread *t, void *udata) -> bool {
                    return t == (Thread *)udata;
                }, (void *)thread);
                thread->waitingon = NULL;
            }
            thread->waitingonlock.release();
            return;
        }

        thread->waitingonlock.acquire();
        WaitQueue *wq = thread->waitingon;
        thread->waitingonlock.release();

        if (!wq) {
            // Not on any waitqueue (already woken or never added).
            return;
        }

        wq->waitinglock.acquire();
        thread->waitingonlock.acquire();

        // Re-check waitingon in case it changed while we acquired locks.
        if (thread->waitingon == wq) {
            wq->waiting.remove([](Thread *t, void *udata) -> bool {
                return t == (Thread *)udata;
            }, (void *)thread);
            thread->waitingon = NULL;
        }
        // If waitingon changed (e.g., became NULL because wake() ran), nothing to do.

        thread->waitingonlock.release();
        wq->waitinglock.release();
    }

    int WaitQueue::finishwaitinterruptible(bool locked) {
        Thread *thread = NArch::CPU::get()->currthread;

        __atomic_store_n(&thread->pendingwaitstate, Thread::pendingwait::PENDING_NONE, memory_order_release);

        if (locked) {
            // Caller holds this->waitinglock.
            thread->waitingonlock.acquire();
            if (thread->waitingon == this) {
                this->waiting.remove([](Thread *t, void *udata) -> bool {
                    return t == (Thread *)udata;
                }, (void *)thread);
                thread->waitingon = NULL;
            } else if (thread->waitingon != NULL) {
                thread->waitingon = NULL;
            }
            thread->waitingonlock.release();
        } else {
            thread->waitingonlock.acquire();
            WaitQueue *wq = thread->waitingon;
            thread->waitingonlock.release();

            if (wq) {
                wq->waitinglock.acquire();
                thread->waitingonlock.acquire();

                if (thread->waitingon == wq) {
                    wq->waiting.remove([](Thread *t, void *udata) -> bool {
                        return t == (Thread *)udata;
                    }, (void *)thread);
                    thread->waitingon = NULL;
                }

                thread->waitingonlock.release();
                wq->waitinglock.release();
            }
        }

        // Check if we were woken by a signal.
        if (haspendingsignal(thread)) {
            return -EINTR;
        }

        return 0;
    }

    void WaitQueue::wait(bool locked) {
        Thread *thread = NArch::CPU::get()->currthread;

        if (!locked) {
            this->waitinglock.acquire();
        }

        // Set up the wait state atomically while holding the lock.
        __atomic_store_n(&thread->pendingwaitstate, Thread::pendingwait::PENDING_WAIT, memory_order_release);

        // Set waitingon under proper lock order.
        thread->waitingonlock.acquire();
        thread->waitingon = this;
        thread->waitingonlock.release();

        this->waiting.pushback(thread);

        // Full memory barrier to ensure all setup is visible before releasing lock.
        NArch::CPU::writemb();

        this->waitinglock.release();

        yield();

        this->finishwait();
    }

    // Implementation macro for waitlocked variants.
    #define WAITLOCKED_IMPL(funcname, locktype) \
    void WaitQueue::funcname(locktype *lock) { \
        Thread *thread = NArch::CPU::get()->currthread; \
        this->waitinglock.acquire(); \
        __atomic_store_n(&thread->pendingwaitstate, Thread::pendingwait::PENDING_WAIT, memory_order_release); \
        thread->waitingonlock.acquire(); \
        thread->waitingon = this; \
        thread->waitingonlock.release(); \
        this->waiting.pushback(thread); \
        NArch::CPU::writemb(); \
        this->waitinglock.release(); \
        lock->release(); \
        yield(); \
        this->finishwait(); \
        lock->acquire(); \
    }

    WAITLOCKED_IMPL(waitlocked, NArch::IRQSpinlock)
    WAITLOCKED_IMPL(waitlocked, NArch::Spinlock)
    WAITLOCKED_IMPL(waitlocked, NSched::Mutex)

    int WaitQueue::waitinterruptible(bool locked) {
        Thread *thread = NArch::CPU::get()->currthread;

        if (!locked) {
            this->waitinglock.acquire();
        }

        // Check for pending signals before sleeping.
        if (haspendingsignal(thread)) {
            this->waitinglock.release();
            return -EINTR;
        }

        // Set up interruptible wait.
        __atomic_store_n(&thread->pendingwaitstate, Thread::pendingwait::PENDING_WAITINT, memory_order_release);

        thread->waitingonlock.acquire();
        thread->waitingon = this;
        thread->waitingonlock.release();

        this->waiting.pushback(thread);

        // Full memory barrier to ensure all setup is visible before releasing lock.
        NArch::CPU::writemb();

        this->waitinglock.release();

        yield();

        // Clean up and check for signals.
        return this->finishwaitinterruptible();
    }

    // Implementation macro for waitinterruptiblelocked variants.
    #define WAITINTLOCKED_IMPL(funcname, locktype) \
    int WaitQueue::funcname(locktype *lock) { \
        Thread *thread = NArch::CPU::get()->currthread; \
        this->waitinglock.acquire(); \
        if (haspendingsignal(thread)) { \
            this->waitinglock.release(); \
            return -EINTR; \
        } \
        __atomic_store_n(&thread->pendingwaitstate, Thread::pendingwait::PENDING_WAITINT, memory_order_release); \
        thread->waitingonlock.acquire(); \
        thread->waitingon = this; \
        thread->waitingonlock.release(); \
        this->waiting.pushback(thread); \
        NArch::CPU::writemb(); \
        this->waitinglock.release(); \
        lock->release(); \
        yield(); \
        lock->acquire(); \
        return this->finishwaitinterruptible(); \
    }

    WAITINTLOCKED_IMPL(waitinterruptiblelocked, NArch::IRQSpinlock)
    WAITINTLOCKED_IMPL(waitinterruptiblelocked, NArch::Spinlock)
    WAITINTLOCKED_IMPL(waitinterruptiblelocked, NSched::Mutex)

    void WaitQueue::wake(void) {
        this->waitinglock.acquire();

        // Wake all waiting threads.
        while (!this->waiting.empty()) {
            Thread *thread = this->waiting.pop();

            // Clear pending wait state FIRST to prevent scheduler from re-transitioning.
            __atomic_store_n(&thread->pendingwaitstate, Thread::pendingwait::PENDING_NONE, memory_order_release);

            // Full memory barrier.
            NArch::CPU::mb();

            // Clear waitingon pointer. Lock order: waitinglock (held) -> waitingonlock.
            thread->waitingonlock.acquire();
            thread->waitingon = NULL;
            thread->waitingonlock.release();

            // Read current state to determine action.
            enum Thread::state curstate = (enum Thread::state)__atomic_load_n(&thread->tstate, memory_order_acquire);

            if (curstate == Thread::state::WAITING || curstate == Thread::state::WAITINGINT) {
                schedulethread(thread);
            }
        }

        this->waitinglock.release();
    }

    void WaitQueue::wakeone(void) {
        this->waitinglock.acquire();
        wakeoneinternal(this->waiting);
        this->waitinglock.release();
    }

    bool WaitQueue::dequeue(Thread *target) {
        this->waitinglock.acquire();

        bool found = this->waiting.remove([](Thread *thread, void *udata) -> bool {
            Thread *t = (Thread *)udata;
            return thread == t;
        }, (void *)target);

        if (found) {
            __atomic_store_n(&target->pendingwaitstate, Thread::pendingwait::PENDING_NONE, memory_order_release);

            // Memory barrier.
            NArch::CPU::mb();

            // Clear waitingon pointer. Lock order: waitinglock (held) -> waitingonlock.
            target->waitingonlock.acquire();
            target->waitingon = NULL;
            target->waitingonlock.release();
        }

        this->waitinglock.release();

        return found;
    }
}
