#ifndef _SCHED__EVENT_HPP
#define _SCHED__EVENT_HPP

#include <lib/list.hpp>
#include <lib/sync.hpp>

#include <sched/sched.hpp>


namespace NSched {

// Wait on this wait queue, testing for condition().
// The condition is checked under the waitqueue lock to avoid races.
#define waitevent(wq, condition) do { \
        for (;;) { \
            (wq)->waitinglock.acquire(); \
            if ((condition)) { \
                (wq)->waitinglock.release(); \
                break; \
            } \
            (wq)->wait(true); \
        } \
    } while (0)

// Wait on this wait queue, testing for condition(). Manages waiting upon an active lock, will leave the lock acquired on return. NOTE: The condition should only depend on state protected by the provided lock. The lock is released during sleep and re-acquired before the condition is checked again.
#define waiteventlocked(wq, condition, lock) do { \
        while (!(condition)) { \
            (wq)->waitlocked(lock); \
        } \
    } while (0)

// Interruptible wait on this wait queue, testing for condition(). Returns -EINTR if interrupted by a signal, 0 on success. The condition is checked under the waitqueue lock to avoid races.
#define waiteventinterruptible(wq, condition, result) do { \
        (result) = 0; \
        for (;;) { \
            (wq)->waitinglock.acquire(); \
            if ((condition)) { \
                (wq)->waitinglock.release(); \
                break; \
            } \
            int __ret = (wq)->waitinterruptible(true); \
            if (__ret < 0) { \
                (result) = __ret; \
                break; \
            } \
        } \
    } while (0)

// Interruptible wait on this wait queue with external lock held. Returns -EINTR if interrupted by a signal, 0 on success. NOTE: The condition should only depend on state protected by the provided lock. The lock is released during sleep and re-acquired before the condition is checked again.
#define waiteventinterruptiblelocked(wq, condition, lock, result) do { \
        (result) = 0; \
        while (!(condition)) { \
            int __ret = (wq)->waitinterruptiblelocked(lock); \
            if (__ret < 0) { \
                (result) = __ret; \
                break; \
            } \
        } \
    } while (0)
}

#endif
