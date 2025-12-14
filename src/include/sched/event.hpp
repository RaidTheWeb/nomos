#ifndef _SCHED__EVENT_HPP
#define _SCHED__EVENT_HPP

#include <lib/list.hpp>
#include <lib/sync.hpp>

#include <sched/sched.hpp>


namespace NSched {

// Wait on this wait queue, testing for condition().
#define waitevent(wq, condition) { \
        if (!(condition)) { \
            for (;;) { \
                (wq)->waitinglock.acquire(); \
                if ((condition)) { \
                    (wq)->waitinglock.release(); \
                    break; \
                } \
                (wq)->wait(true); \
            } \
        } \
    }

// Wait on this wait queue, testing for condition(). Manages waiting upon an active lock, will leave the lock acquired on return. NOTE: Recommended for when the calling thread holds active locks, as wake up does not guarantee wake up on the same CPU it slept on.
#define waiteventlocked(wq, condition, lock) { \
        while (!(condition)) { \
            (wq)->waitlocked(lock); \
        } \
    }

// Interruptible wait on this wait queue, testing for condition(). Returns -EINTR if interrupted by a signal, 0 on success.
#define waiteventinterruptible(wq, condition, result) { \
        (result) = 0; \
        if (!(condition)) { \
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
        } \
    }

// Interruptible wait on this wait queue with external lock held. Returns -EINTR if interrupted by a signal, 0 on success.
#define waiteventinterruptiblelocked(wq, condition, lock, result) { \
        (result) = 0; \
        while (!(condition)) { \
            int __ret = (wq)->waitinterruptiblelocked(lock); \
            if (__ret < 0) { \
                (result) = __ret; \
                break; \
            } \
        } \
    }
}

#endif
