#ifdef __x86_64__
#include <arch/x86_64/cpu.hpp>
#endif
#include <lib/errno.hpp>
#include <sched/event.hpp>
#include <sched/signal.hpp>

namespace NSched {
    // Helper function to check if thread has pending unblocked signals.
    static inline bool haspendingsignal(Thread *thread) {
        if (!thread->process) return false;

        // Get pending signals that aren't blocked.
        NLib::sigset_t pending = __atomic_load_n(&thread->process->signalstate.pending, memory_order_acquire);
        NLib::sigset_t blocked = __atomic_load_n(&thread->blocked, memory_order_acquire);
        NLib::sigset_t unblocked = pending & ~blocked;

        return unblocked != 0;
    }

    void WaitQueue::wait(bool locked) {
        if (!locked) {
            this->waitinglock.acquire(); // We MUST acquire the lock before setting the thread to waiting, otherwise we'll never be rescheduled when the timeslice expires.
        }

        Thread *thread = NArch::CPU::get()->currthread;
        __atomic_store_n(&thread->tstate, Thread::state::WAITING, memory_order_release);
        thread->waitingon = this;
        this->waiting.pushback(thread);

        this->waitinglock.release();
        yield();

        thread->waitingon = NULL;
    }

    void WaitQueue::waitlocked(NArch::IRQSpinlock *lock) {
        // Acquire waitqueue lock first
        this->waitinglock.acquire();

        lock->release(); // Release before sleeping.

        Thread *thread = NArch::CPU::get()->currthread;
        __atomic_store_n(&thread->tstate, Thread::state::WAITING, memory_order_release);
        thread->waitingon = this;
        this->waiting.pushback(thread);

        this->waitinglock.release();
        yield();

        thread->waitingon = NULL;

        // When we wake up, re-acquire the external lock before returning
        lock->acquire();
    }

    void WaitQueue::waitlocked(NArch::Spinlock *lock) {
        // Acquire waitqueue lock first
        this->waitinglock.acquire();

        lock->release(); // Release before sleeping.

        Thread *thread = NArch::CPU::get()->currthread;
        __atomic_store_n(&thread->tstate, Thread::state::WAITING, memory_order_release);
        thread->waitingon = this;
        this->waiting.pushback(thread);

        this->waitinglock.release();
        yield();

        thread->waitingon = NULL;

        // When we wake up, re-acquire the external lock before returning
        lock->acquire();
    }

    void WaitQueue::waitlocked(NSched::Mutex *lock) {
        // Acquire waitqueue lock first
        this->waitinglock.acquire();

        lock->release(); // Release before sleeping.

        Thread *thread = NArch::CPU::get()->currthread;
        __atomic_store_n(&thread->tstate, Thread::state::WAITING, memory_order_release);
        thread->waitingon = this;
        this->waiting.pushback(thread);

        this->waitinglock.release();
        yield();

        thread->waitingon = NULL;

        // When we wake up, re-acquire the external lock before returning
        lock->acquire();
    }

    int WaitQueue::waitinterruptible(bool locked) {
        if (!locked) {
            this->waitinglock.acquire();
        }

        Thread *thread = NArch::CPU::get()->currthread;

        // Check for pending signals before sleeping.
        if (haspendingsignal(thread)) {
            this->waitinglock.release();
            return -EINTR;
        }

        __atomic_store_n(&thread->tstate, Thread::state::WAITINGINT, memory_order_release);
        thread->waitingon = this;
        this->waiting.pushback(thread);

        this->waitinglock.release();
        yield();

        thread->waitingon = NULL;

        // After waking, check if we were interrupted by a signal.
        if (haspendingsignal(thread)) {
            return -EINTR;
        }

        return 0;
    }

    int WaitQueue::waitinterruptiblelocked(NArch::IRQSpinlock *lock) {
        // Acquire waitqueue lock first
        this->waitinglock.acquire();

        Thread *thread = NArch::CPU::get()->currthread;

        // Check for pending signals before sleeping.
        if (haspendingsignal(thread)) {
            this->waitinglock.release();
            return -EINTR;
        }

        lock->release(); // Release before sleeping.

        __atomic_store_n(&thread->tstate, Thread::state::WAITINGINT, memory_order_release);
        thread->waitingon = this;
        this->waiting.pushback(thread);

        this->waitinglock.release();
        yield();

        thread->waitingon = NULL;

        // When we wake up, re-acquire the external lock before returning
        lock->acquire();

        // After waking, check if we were interrupted by a signal.
        if (haspendingsignal(thread)) {
            return -EINTR;
        }

        return 0;
    }

    int WaitQueue::waitinterruptiblelocked(NArch::Spinlock *lock) {
        // Acquire waitqueue lock first
        this->waitinglock.acquire();

        Thread *thread = NArch::CPU::get()->currthread;

        // Check for pending signals before sleeping.
        if (haspendingsignal(thread)) {
            this->waitinglock.release();
            return -EINTR;
        }

        lock->release(); // Release before sleeping.

        __atomic_store_n(&thread->tstate, Thread::state::WAITINGINT, memory_order_release);
        thread->waitingon = this;
        this->waiting.pushback(thread);

        this->waitinglock.release();
        yield();

        thread->waitingon = NULL;

        // When we wake up, re-acquire the external lock before returning
        lock->acquire();

        // After waking, check if we were interrupted by a signal.
        if (haspendingsignal(thread)) {
            return -EINTR;
        }

        return 0;
    }

    int WaitQueue::waitinterruptiblelocked(NSched::Mutex *lock) {
        // Acquire waitqueue lock first
        this->waitinglock.acquire();

        Thread *thread = NArch::CPU::get()->currthread;

        // Check for pending signals before sleeping.
        if (haspendingsignal(thread)) {
            this->waitinglock.release();
            return -EINTR;
        }

        lock->release(); // Release before sleeping.

        __atomic_store_n(&thread->tstate, Thread::state::WAITINGINT, memory_order_release);
        thread->waitingon = this;
        this->waiting.pushback(thread);

        this->waitinglock.release();
        yield();

        thread->waitingon = NULL;

        // When we wake up, re-acquire the external lock before returning
        lock->acquire();

        // After waking, check if we were interrupted by a signal.
        if (haspendingsignal(thread)) {
            return -EINTR;
        }

        return 0;
    }

    void WaitQueue::wake(void) {
        NLib::SingleList<Thread *> towake;
        this->waitinglock.acquire();
        size_t i = 0;
        while (!this->waiting.empty()) {
            Thread *thread = this->waiting.pop();
            enum Thread::state tstate = __atomic_load_n(&thread->tstate, memory_order_acquire);
            if (tstate != Thread::state::WAITING && tstate != Thread::state::WAITINGINT) {
                continue; // Thread is no longer waiting, skip it.
            }
            i++;
            towake.push(thread);
        }
        this->waitinglock.release();

        // Schedule all threads that were waiting.
        for (NLib::SingleList<Thread *>::Iterator it = towake.begin(); it.valid(); it.next()) {
            Thread *thread = *(it.get());
            schedulethread(thread);
        }
    }

    // Dequeue a specific thread from the waitqueue.
    bool WaitQueue::dequeue(Thread *target) {
        this->waitinglock.acquire();

        bool found = this->waiting.remove([](Thread *thread, void *udata) -> bool {
            Thread *target = (Thread *)udata;
            return thread == target;
        }, (void *)target);

        this->waitinglock.release();

        if (found) {
            target->waitingon = NULL;
        }

        return found;
    }
}
