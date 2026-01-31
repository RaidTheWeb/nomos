#ifndef _SCHED__EVENT_HPP
#define _SCHED__EVENT_HPP

#include <lib/list.hpp>
#include <lib/sync.hpp>

#include <sched/sched.hpp>


namespace NSched {

// Wait on this wait queue until condition becomes true. Non-interruptible.
#define waitevent(wq, condition) do { \
        (wq)->waitinglock.acquire(); \
        while (!(condition)) { \
            (wq)->preparewait(); \
            (wq)->waitinglock.release(); \
            NSched::yield(); \
            (wq)->waitinglock.acquire(); \
            (wq)->finishwait(true); \
        } \
        (wq)->waitinglock.release(); \
    } while (0)

// Wait on this wait queue, with external lock held, until condition becomes true. Non-interruptible. The external lock protects the condition.
#define waiteventlocked(wq, condition, lock) do { \
        while (!(condition)) { \
            (wq)->waitinglock.acquire(); \
            if (!(condition)) { \
                (wq)->preparewait(); \
                (wq)->waitinglock.release(); \
                (lock)->release(); \
                NSched::yield(); \
                (lock)->acquire(); \
                (wq)->waitinglock.acquire(); \
                (wq)->finishwait(true); \
                (wq)->waitinglock.release(); \
            } else { \
                (wq)->waitinglock.release(); \
                break; \
            } \
        } \
    } while (0)

// Wait on this wait queue, until condition becomes true. Interruptible by signals.
#define waiteventinterruptible(wq, condition, result) do { \
        (result) = 0; \
        (wq)->waitinglock.acquire(); \
        while (!(condition)) { \
            if ((wq)->preparewaitinterruptible()) { \
                (wq)->waitinglock.release(); \
                (result) = -EINTR; \
                break; \
            } \
            (wq)->waitinglock.release(); \
            NSched::yield(); \
            (wq)->waitinglock.acquire(); \
            int __finret = (wq)->finishwaitinterruptible(true); \
            if (__finret < 0) { \
                (wq)->waitinglock.release(); \
                (result) = __finret; \
                break; \
            } \
        } \
        if ((result) == 0) { \
            (wq)->waitinglock.release(); \
        } \
    } while (0)

// Wait on this wait queue, with external lock held, until condition becomes true. Interruptible by signals. External lock protects the condition.
#define waiteventinterruptiblelocked(wq, condition, lock, result) do { \
        (result) = 0; \
        while (!(condition)) { \
            (wq)->waitinglock.acquire(); \
            if (!(condition)) { \
                if ((wq)->preparewaitinterruptible()) { \
                    (wq)->waitinglock.release(); \
                    (result) = -EINTR; \
                    break; \
                } \
                (wq)->waitinglock.release(); \
                (lock)->release(); \
                NSched::yield(); \
                (lock)->acquire(); \
                (wq)->waitinglock.acquire(); \
                int __finret = (wq)->finishwaitinterruptible(true); \
                (wq)->waitinglock.release(); \
                if (__finret < 0) { \
                    (result) = __finret; \
                    break; \
                } \
            } else { \
                (wq)->waitinglock.release(); \
                break; \
            } \
        } \
    } while (0)

// Internal state for timeout-based waits.
struct timeoutstate {
    WaitQueue *waitqueue;
    volatile bool expired = false;
    volatile bool finished = false;
    NArch::IRQSpinlock lock;
    uint64_t timerhandle = 0; // Handle for cancellation.
    volatile int refcount = 2; // Caller + callback each hold one ref.

    timeoutstate(WaitQueue *wq) : waitqueue(wq) { }

    bool unref(void) {
        int newref = __atomic_sub_fetch(&this->refcount, 1, memory_order_acq_rel);
        if (newref == 0) {
            delete this;
            return true;
        }
        return false;
    }

    void clearwaitqueue(void) {
        this->waitqueue = NULL;
    }

    static void callback(void *arg) {
        timeoutstate *state = (timeoutstate *)arg;

        state->lock.acquire();
        __atomic_store_n(&state->expired, true, memory_order_release);
        bool finished = __atomic_load_n(&state->finished, memory_order_acquire);
        WaitQueue *wq = state->waitqueue;

        if (!finished && wq) {
            wq->wake();
        }

        state->lock.release();

        state->unref();
    }
};

}

// Include timer header after namespace declaration to avoid circular deps.
#include <sys/timer.hpp>

namespace NSched {

// Wait on wait queue until condition becomes true OR timeout expires. Non-interruptible. Returns -ETIMEDOUT if timeout expires.
#define waiteventtimeout(wq, condition, timeout_ms, result) do { \
    (result) = 0; \
    NArch::CPU::mb(); \
    if (condition) { \
        break; \
    } \
    NSched::timeoutstate *__tstate = new NSched::timeoutstate(wq); \
    NSys::Timer::timerlock(); \
    __tstate->timerhandle = NSys::Timer::create(NSched::timeoutstate::callback, __tstate, (timeout_ms)); \
    NSys::Timer::timerunlock(); \
    (wq)->waitinglock.acquire(); \
    while (!(condition) && !__atomic_load_n(&__tstate->expired, memory_order_acquire)) { \
        (wq)->preparewait(); \
        /* Re-check expired after preparewait to catch timer that fired while we set up. */ \
        if (__atomic_load_n(&__tstate->expired, __ATOMIC_ACQUIRE)) { \
            (wq)->finishwait(true); \
            break; \
        } \
        (wq)->waitinglock.release(); \
        NSched::yield(); \
        (wq)->waitinglock.acquire(); \
        (wq)->finishwait(true); \
    } \
    (wq)->waitinglock.release(); \
    /* Try to cancel the timer to prevent callback from running after we return. */ \
    NSys::Timer::timerlock(); \
    bool __cancelled = NSys::Timer::cancel(__tstate->timerhandle); \
    NSys::Timer::timerunlock(); \
    __tstate->lock.acquire(); \
    __atomic_store_n(&__tstate->finished, true, memory_order_release); \
    __tstate->clearwaitqueue(); /* Prevent callback from calling wake() on potentially freed wq. */ \
    bool __expired = __atomic_load_n(&__tstate->expired, memory_order_acquire); \
    __tstate->lock.release(); \
    if (__expired && !(condition)) { \
        (result) = -ETIMEDOUT; \
    } \
    if (__cancelled) { \
        __tstate->unref(); /* Release callback's ref since it won't run. */ \
    } \
    __tstate->unref(); /* Release caller's ref. May delete if callback already ran. */ \
} while (0)

// Wait on wait queue until condition becomes true, timeout expires, or signal received. Returns -ETIMEDOUT if timeout expires, -EINTR if interrupted by signal.
#define waiteventinterruptibletimeout(wq, condition, timeout_ms, result) do { \
    (result) = 0; \
    NArch::CPU::mb(); \
    if (condition) { \
        break; \
    } \
    NSched::timeoutstate *__tstate = new NSched::timeoutstate(wq); \
    NSys::Timer::timerlock(); \
    __tstate->timerhandle = NSys::Timer::create(NSched::timeoutstate::callback, __tstate, (timeout_ms)); \
    NSys::Timer::timerunlock(); \
    (wq)->waitinglock.acquire(); \
    while (!(condition) && !__atomic_load_n(&__tstate->expired, memory_order_acquire)) { \
        if ((wq)->preparewaitinterruptible()) { \
            (wq)->waitinglock.release(); \
            (result) = -EINTR; \
            break; \
        } \
        /* Re-check expired after preparewait to catch timer that fired while we set up. */ \
        if (__atomic_load_n(&__tstate->expired, memory_order_acquire)) { \
            (wq)->finishwait(true); \
            break; \
        } \
        (wq)->waitinglock.release(); \
        NSched::yield(); \
        (wq)->waitinglock.acquire(); \
        int __finret = (wq)->finishwaitinterruptible(true); \
        if (__finret < 0) { \
            (wq)->waitinglock.release(); \
            (result) = __finret; \
            break; \
        } \
    } \
    if ((result) == 0) { \
        (wq)->waitinglock.release(); \
    } \
    /* Try to cancel the timer to prevent callback from running after we return. */ \
    NSys::Timer::timerlock(); \
    bool __cancelled = NSys::Timer::cancel(__tstate->timerhandle); \
    NSys::Timer::timerunlock(); \
    __tstate->lock.acquire(); \
    __atomic_store_n(&__tstate->finished, true, memory_order_release); \
    __tstate->clearwaitqueue(); /* Prevent callback from calling wake() on potentially freed wq. */ \
    bool __expired = __atomic_load_n(&__tstate->expired, memory_order_acquire); \
    __tstate->lock.release(); \
    if (__expired && (result) == 0 && !(condition)) { \
        (result) = -ETIMEDOUT; \
    } \
    if (__cancelled) { \
        __tstate->unref(); /* Release callback's ref since it won't run. */ \
    } \
    __tstate->unref(); /* Release caller's ref. May delete if callback already ran. */ \
} while (0)

}

#endif
