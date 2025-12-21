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

        // Set pending wait state - actual state transition happens in scheduler after context is saved.
        // This prevents the race where a signal wakes us before our context is saved.
        __atomic_store_n(&thread->pendingwaitstate, Thread::pendingwait::PENDING_WAIT, memory_order_release);
        thread->waitingonlock.acquire();
        thread->waitingon = this;
        this->waiting.pushback(thread);
        thread->waitingonlock.release();

        this->waitinglock.release();

        // Memory barrier to ensure state is visible before yield.
        NArch::CPU::writemb();

        yield();

        // After waking, clear the waitingon pointer.
        thread->waitingonlock.acquire();
        thread->waitingon = NULL;
        thread->waitingonlock.release();
    }

    void WaitQueue::waitlocked(NArch::IRQSpinlock *lock) {
        Thread *thread = NArch::CPU::get()->currthread;

        // Acquire waitqueue lock while still holding external lock.
        this->waitinglock.acquire();

        // Set pending wait state - actual state transition happens in scheduler after context is saved.
        __atomic_store_n(&thread->pendingwaitstate, Thread::pendingwait::PENDING_WAIT, memory_order_release);
        thread->waitingonlock.acquire();
        thread->waitingon = this;
        this->waiting.pushback(thread);
        thread->waitingonlock.release();

        // Release locks in correct order: waitqueue first, then external.
        this->waitinglock.release();
        lock->release();

        NArch::CPU::writemb();
        yield();

        thread->waitingonlock.acquire();
        thread->waitingon = NULL;
        thread->waitingonlock.release();

        // When we wake up, re-acquire the external lock before returning
        lock->acquire();
    }

    void WaitQueue::waitlocked(NArch::Spinlock *lock) {
        Thread *thread = NArch::CPU::get()->currthread;

        this->waitinglock.acquire();

        // Set pending wait state - actual state transition happens in scheduler after context is saved.
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

        // Set pending wait state - actual state transition happens in scheduler after context is saved.
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

        // Set pending wait state - actual state transition happens in scheduler after context is saved.
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

        // Set pending wait state - actual state transition happens in scheduler after context is saved.
        __atomic_store_n(&thread->pendingwaitstate, Thread::pendingwait::PENDING_WAITINT, memory_order_release);
        thread->waitingonlock.acquire();
        thread->waitingon = this;
        this->waiting.pushback(thread);
        thread->waitingonlock.release();

        // Release locks: waitqueue first, then external.
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

        // Check for pending signals before sleeping.
        if (haspendingsignal(thread)) {
            this->waitinglock.release();
            return -EINTR;
        }

        // Set pending wait state - actual state transition happens in scheduler after context is saved.
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

        // Check for pending signals before sleeping.
        if (haspendingsignal(thread)) {
            this->waitinglock.release();
            return -EINTR;
        }

        // Set pending wait state - actual state transition happens in scheduler after context is saved.
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

    // Wake up all threads waiting on this waitqueue.
    void WaitQueue::wake(void) {
        this->waitinglock.acquire();

        // Collect all waiting threads into a temporary list.
        while (!this->waiting.empty()) {
            Thread *thread = this->waiting.pop();

            // Check if thread has a pending wait or is in a waiting state.
            enum Thread::state tstate = (enum Thread::state)__atomic_load_n(&thread->tstate, memory_order_acquire);
            enum Thread::pendingwait pwait = (enum Thread::pendingwait)__atomic_load_n(&thread->pendingwaitstate, memory_order_acquire);

            if (tstate == Thread::state::DEAD) {
                continue; // Thread is dead, skip it.
            }

            // Clear pending wait state so the scheduler knows not to transition to waiting.
            __atomic_store_n(&thread->pendingwaitstate, Thread::pendingwait::PENDING_NONE, memory_order_release);

            // Only schedule if thread was in a waiting state (context already saved).
            if (tstate == Thread::state::WAITING || tstate == Thread::state::WAITINGINT) {
                schedulethread(thread);
            }
            // If tstate == RUNNING and pwait != PENDING_NONE, the thread was in the process of going to sleep. By clearing pendingwaitstate, we ensure its scheduler will re-enqueue it instead of transitioning to WAITING state.
        }

        this->waitinglock.release();
    }

    void WaitQueue::wakeone(void) {
        this->waitinglock.acquire();

        if (!this->waiting.empty()) {
            Thread *thread = this->waiting.pop();

            enum Thread::state tstate = (enum Thread::state)__atomic_load_n(&thread->tstate, memory_order_acquire);

            if (tstate != Thread::state::DEAD) {
                // Clear pending wait state so the scheduler knows not to transition to waiting.
                __atomic_store_n(&thread->pendingwaitstate, Thread::pendingwait::PENDING_NONE, memory_order_release);

                // Only schedule if thread was in a waiting state (context already saved).
                if (tstate == Thread::state::WAITING || tstate == Thread::state::WAITINGINT) {
                    schedulethread(thread);
                }
            }
        }

        this->waitinglock.release();
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
            target->waitingonlock.acquire();
            target->waitingon = NULL;
            target->waitingonlock.release();
        }

        return found;
    }
}
