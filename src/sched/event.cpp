#ifdef __x86_64__
#include <arch/x86_64/cpu.hpp>
#endif
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

    // Internal helper to wake a single thread from the wait list. Locks must be held by caller.
    static Thread *wakeoneinternal(NLib::DoubleList<Thread *> &waiting) {
        while (!waiting.empty()) {
            Thread *thread = waiting.pop();

            enum Thread::state tstate = (enum Thread::state)__atomic_load_n(&thread->tstate, memory_order_acquire);

            // Skip dead threads.
            if (tstate == Thread::state::DEAD) {
                continue;
            }

            enum Thread::pendingwait expected = (enum Thread::pendingwait)__atomic_load_n(&thread->pendingwaitstate, memory_order_acquire);
            if (expected != Thread::pendingwait::PENDING_NONE) {
                __atomic_store_n(&thread->pendingwaitstate, Thread::pendingwait::PENDING_NONE, memory_order_release);
            }

            // Clear the waitingon pointer.
            thread->waitingonlock.acquire();
            thread->waitingon = NULL;
            thread->waitingonlock.release();

            if (tstate == Thread::state::WAITING || tstate == Thread::state::WAITINGINT) {
                schedulethread(thread);
            }

            return thread;
        }
        return NULL;
    }

    void WaitQueue::preparewait(void) {
        Thread *thread = NArch::CPU::get()->currthread;

        __atomic_store_n(&thread->pendingwaitstate, Thread::pendingwait::PENDING_WAIT, memory_order_release);

        // Link thread to this waitqueue.
        thread->waitingonlock.acquire();
        thread->waitingon = this;
        thread->waitingonlock.release();

        // Add to wait list.
        this->waiting.pushback(thread);
    }

    bool WaitQueue::preparewaitinterruptible(void) {
        Thread *thread = NArch::CPU::get()->currthread;

        // Check for pending signals before committing to wait.
        if (haspendingsignal(thread)) {
            return true; // Signal pending, we don't wait.
        }

        // Set pending wait state for interruptible wait.
        __atomic_store_n(&thread->pendingwaitstate, Thread::pendingwait::PENDING_WAITINT, memory_order_release);

        // Link thread to this waitqueue.
        thread->waitingonlock.acquire();
        thread->waitingon = this;
        thread->waitingonlock.release();

        // Add to wait list.
        this->waiting.pushback(thread);

        return false; // Proceed with wait.
    }

    void WaitQueue::finishwait(void) {
        Thread *thread = NArch::CPU::get()->currthread;

        thread->waitingonlock.acquire();
        thread->waitingon = NULL;
        thread->waitingonlock.release();
    }

    int WaitQueue::finishwaitinterruptible(void) {
        Thread *thread = NArch::CPU::get()->currthread;

        // Clear the waitingon pointer.
        thread->waitingonlock.acquire();
        thread->waitingon = NULL;
        thread->waitingonlock.release();

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

        // Set up the wait.
        __atomic_store_n(&thread->pendingwaitstate, Thread::pendingwait::PENDING_WAIT, memory_order_release);
        thread->waitingonlock.acquire();
        thread->waitingon = this;
        this->waiting.pushback(thread);
        thread->waitingonlock.release();

        this->waitinglock.release();

        // Memory barrier before yielding.
        NArch::CPU::writemb();

        yield();

        // Clean up after waking.
        thread->waitingonlock.acquire();
        thread->waitingon = NULL;
        thread->waitingonlock.release();
    }

    void WaitQueue::waitlocked(NArch::IRQSpinlock *lock) {
        Thread *thread = NArch::CPU::get()->currthread;

        // Acquire waitqueue lock while still holding external lock.
        this->waitinglock.acquire();

        // Set up the wait.
        __atomic_store_n(&thread->pendingwaitstate, Thread::pendingwait::PENDING_WAIT, memory_order_release);
        thread->waitingonlock.acquire();
        thread->waitingon = this;
        this->waiting.pushback(thread);
        thread->waitingonlock.release();

        // Release locks, waitqueue first to minimize hold time.
        this->waitinglock.release();
        lock->release();

        NArch::CPU::writemb();
        yield();

        // Clean up and re-acquire external lock.
        thread->waitingonlock.acquire();
        thread->waitingon = NULL;
        thread->waitingonlock.release();

        lock->acquire();
    }

    void WaitQueue::waitlocked(NArch::Spinlock *lock) {
        Thread *thread = NArch::CPU::get()->currthread;

        this->waitinglock.acquire();

        __atomic_store_n(&thread->pendingwaitstate, Thread::pendingwait::PENDING_WAIT, memory_order_release);
        thread->waitingonlock.acquire();
        thread->waitingon = this;
        this->waiting.pushback(thread);
        thread->waitingonlock.release();

        this->waitinglock.release();
        lock->release();

        NArch::CPU::writemb();
        yield();

        thread->waitingonlock.acquire();
        thread->waitingon = NULL;
        thread->waitingonlock.release();

        lock->acquire();
    }

    void WaitQueue::waitlocked(NSched::Mutex *lock) {
        Thread *thread = NArch::CPU::get()->currthread;

        this->waitinglock.acquire();

        __atomic_store_n(&thread->pendingwaitstate, Thread::pendingwait::PENDING_WAIT, memory_order_release);
        thread->waitingonlock.acquire();
        thread->waitingon = this;
        this->waiting.pushback(thread);
        thread->waitingonlock.release();

        this->waitinglock.release();
        lock->release();

        NArch::CPU::writemb();
        yield();

        thread->waitingonlock.acquire();
        thread->waitingon = NULL;
        thread->waitingonlock.release();

        lock->acquire();
    }

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
        this->waiting.pushback(thread);
        thread->waitingonlock.release();

        this->waitinglock.release();

        NArch::CPU::writemb();
        yield();

        thread->waitingonlock.acquire();
        thread->waitingon = NULL;
        thread->waitingonlock.release();

        // Check if we were interrupted by a signal.
        if (haspendingsignal(thread)) {
            return -EINTR;
        }

        return 0;
    }

    int WaitQueue::waitinterruptiblelocked(NArch::IRQSpinlock *lock) {
        Thread *thread = NArch::CPU::get()->currthread;

        this->waitinglock.acquire();

        // Check for pending signals before sleeping.
        if (haspendingsignal(thread)) {
            this->waitinglock.release();
            return -EINTR;
        }

        // Set up interruptible wait.
        __atomic_store_n(&thread->pendingwaitstate, Thread::pendingwait::PENDING_WAITINT, memory_order_release);
        thread->waitingonlock.acquire();
        thread->waitingon = this;
        this->waiting.pushback(thread);
        thread->waitingonlock.release();

        // Release locks.
        this->waitinglock.release();
        lock->release();

        NArch::CPU::writemb();
        yield();

        thread->waitingonlock.acquire();
        thread->waitingon = NULL;
        thread->waitingonlock.release();

        // Re-acquire external lock before returning.
        lock->acquire();

        // Check if we were interrupted by a signal.
        if (haspendingsignal(thread)) {
            return -EINTR;
        }

        return 0;
    }

    int WaitQueue::waitinterruptiblelocked(NArch::Spinlock *lock) {
        Thread *thread = NArch::CPU::get()->currthread;

        this->waitinglock.acquire();

        if (haspendingsignal(thread)) {
            this->waitinglock.release();
            return -EINTR;
        }

        __atomic_store_n(&thread->pendingwaitstate, Thread::pendingwait::PENDING_WAITINT, memory_order_release);
        thread->waitingonlock.acquire();
        thread->waitingon = this;
        this->waiting.pushback(thread);
        thread->waitingonlock.release();

        this->waitinglock.release();
        lock->release();

        NArch::CPU::writemb();
        yield();

        thread->waitingonlock.acquire();
        thread->waitingon = NULL;
        thread->waitingonlock.release();

        lock->acquire();

        if (haspendingsignal(thread)) {
            return -EINTR;
        }

        return 0;
    }

    int WaitQueue::waitinterruptiblelocked(NSched::Mutex *lock) {
        Thread *thread = NArch::CPU::get()->currthread;

        this->waitinglock.acquire();

        if (haspendingsignal(thread)) {
            this->waitinglock.release();
            return -EINTR;
        }

        __atomic_store_n(&thread->pendingwaitstate, Thread::pendingwait::PENDING_WAITINT, memory_order_release);
        thread->waitingonlock.acquire();
        thread->waitingon = this;
        this->waiting.pushback(thread);
        thread->waitingonlock.release();

        this->waitinglock.release();
        lock->release();

        NArch::CPU::writemb();
        yield();

        thread->waitingonlock.acquire();
        thread->waitingon = NULL;
        thread->waitingonlock.release();

        lock->acquire();

        if (haspendingsignal(thread)) {
            return -EINTR;
        }

        return 0;
    }


    void WaitQueue::wake(void) {
        this->waitinglock.acquire();

        // Wake all waiting threads.
        while (!this->waiting.empty()) {
            Thread *thread = this->waiting.pop();

            enum Thread::state tstate = (enum Thread::state)__atomic_load_n(&thread->tstate, memory_order_acquire);

            // Skip dead threads.
            if (tstate == Thread::state::DEAD) {
                continue;
            }

            // Clear pending wait state to prevent scheduler from transitioning.
            __atomic_store_n(&thread->pendingwaitstate, Thread::pendingwait::PENDING_NONE, memory_order_release);

            // Clear waitingon pointer.
            thread->waitingonlock.acquire();
            thread->waitingon = NULL;
            thread->waitingonlock.release();

            // Schedule if already in waiting state.
            if (tstate == Thread::state::WAITING || tstate == Thread::state::WAITINGINT) {
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

        this->waitinglock.release();

        if (found) {
            // Clear the pending wait state.
            __atomic_store_n(&target->pendingwaitstate, Thread::pendingwait::PENDING_NONE, memory_order_release);

            // Clear the waitingon pointer.
            target->waitingonlock.acquire();
            target->waitingon = NULL;
            target->waitingonlock.release();
        }

        return found;
    }
}
