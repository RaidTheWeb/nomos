#ifdef __x86_64__
#include <arch/x86_64/cpu.hpp>
#endif
#include <lib/errno.hpp>
#include <sched/event.hpp>
#include <sched/signal.hpp>

namespace NSched {
    // Helper function to check if thread has pending unblocked signals.
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

    void WaitQueue::wait(bool locked) {
        Thread *thread = NArch::CPU::get()->currthread;

        if (!locked) {
            this->waitinglock.acquire(); // We MUST acquire the lock before setting the thread to waiting, otherwise we'll never be rescheduled when the timeslice expires.
        }

        // Set state to WAITING before adding to queue.
        __atomic_store_n(&thread->tstate, Thread::state::WAITING, memory_order_release);
        thread->waitingon = this;
        this->waiting.pushback(thread);

        this->waitinglock.release();

        // Memory barrier to ensure state is visible before yield.
        NArch::CPU::writemb();

        yield();

        // After waking, clear the waitingon pointer.
        thread->waitingon = NULL;
    }

    void WaitQueue::waitlocked(NArch::IRQSpinlock *lock) {
        Thread *thread = NArch::CPU::get()->currthread;

        // Acquire waitqueue lock while still holding external lock.
        this->waitinglock.acquire();

        // Set up wait state while holding both locks.
        __atomic_store_n(&thread->tstate, Thread::state::WAITING, memory_order_release);
        thread->waitingon = this;
        this->waiting.pushback(thread);

        // Release locks in correct order: waitqueue first, then external.
        this->waitinglock.release();
        lock->release();

        NArch::CPU::writemb();
        yield();

        thread->waitingon = NULL;

        // When we wake up, re-acquire the external lock before returning
        lock->acquire();
    }

    void WaitQueue::waitlocked(NArch::Spinlock *lock) {
        Thread *thread = NArch::CPU::get()->currthread;

        this->waitinglock.acquire();

        __atomic_store_n(&thread->tstate, Thread::state::WAITING, memory_order_release);
        thread->waitingon = this;
        this->waiting.pushback(thread);

        this->waitinglock.release();
        lock->release();

        NArch::CPU::writemb();
        yield();

        thread->waitingon = NULL;
        lock->acquire();
    }

    void WaitQueue::waitlocked(NSched::Mutex *lock) {
        Thread *thread = NArch::CPU::get()->currthread;

        this->waitinglock.acquire();

        __atomic_store_n(&thread->tstate, Thread::state::WAITING, memory_order_release);
        thread->waitingon = this;
        this->waiting.pushback(thread);

        this->waitinglock.release();
        lock->release();

        NArch::CPU::writemb();
        yield();

        thread->waitingon = NULL;
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

        __atomic_store_n(&thread->tstate, Thread::state::WAITINGINT, memory_order_release);
        thread->waitingon = this;
        this->waiting.pushback(thread);

        this->waitinglock.release();

        NArch::CPU::writemb();
        yield();

        thread->waitingon = NULL;

        // After waking, check if we were interrupted by a signal.
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

        // Set up wait state.
        __atomic_store_n(&thread->tstate, Thread::state::WAITINGINT, memory_order_release);
        thread->waitingon = this;
        this->waiting.pushback(thread);

        // Release locks: waitqueue first, then external.
        this->waitinglock.release();
        lock->release();

        NArch::CPU::writemb();
        yield();

        thread->waitingon = NULL;

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

        // Check for pending signals before sleeping.
        if (haspendingsignal(thread)) {
            this->waitinglock.release();
            return -EINTR;
        }

        __atomic_store_n(&thread->tstate, Thread::state::WAITINGINT, memory_order_release);
        thread->waitingon = this;
        this->waiting.pushback(thread);

        this->waitinglock.release();
        lock->release();

        NArch::CPU::writemb();
        yield();

        thread->waitingon = NULL;

        lock->acquire();

        if (haspendingsignal(thread)) {
            return -EINTR;
        }

        return 0;
    }

    int WaitQueue::waitinterruptiblelocked(NSched::Mutex *lock) {
        Thread *thread = NArch::CPU::get()->currthread;

        this->waitinglock.acquire();

        // Check for pending signals before sleeping.
        if (haspendingsignal(thread)) {
            this->waitinglock.release();
            return -EINTR;
        }

        __atomic_store_n(&thread->tstate, Thread::state::WAITINGINT, memory_order_release);
        thread->waitingon = this;
        this->waiting.pushback(thread);

        this->waitinglock.release();
        lock->release();

        NArch::CPU::writemb();
        yield();

        thread->waitingon = NULL;

        lock->acquire();

        if (haspendingsignal(thread)) {
            return -EINTR;
        }

        return 0;
    }

    // Wake up all threads waiting on this waitqueue.
    void WaitQueue::wake(void) {
        NLib::SingleList<Thread *> towake;

        this->waitinglock.acquire();

        // Collect all waiting threads into a temporary list.
        while (!this->waiting.empty()) {
            Thread *thread = this->waiting.pop();

            // Verify thread is still in a waiting state.
            enum Thread::state tstate = (enum Thread::state)__atomic_load_n(&thread->tstate, memory_order_acquire);
            if (tstate == Thread::state::WAITING || tstate == Thread::state::WAITINGINT) {
                towake.push(thread);
            }
            // If thread is not waiting (e.g., already marked DEAD), skip it.
        }

        this->waitinglock.release();

        // Schedule all collected threads outside of the lock.
        for (NLib::SingleList<Thread *>::Iterator it = towake.begin(); it.valid(); it.next()) {
            Thread *thread = *(it.get());
            schedulethread(thread);
        }
    }

    // Remove a specific thread from the waitqueue.
    bool WaitQueue::dequeue(Thread *target) {
        this->waitinglock.acquire();

        bool found = this->waiting.remove([](Thread *thread, void *udata) -> bool {
            Thread *t = (Thread *)udata;
            return thread == t;
        }, (void *)target);

        this->waitinglock.release();

        if (found) {
            target->waitingon = NULL;
        }

        return found;
    }
}
