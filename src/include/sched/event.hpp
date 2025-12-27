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
            (wq)->finishwait(); \
        } \
        (wq)->waitinglock.release(); \
    } while (0)

// Wait on this wait queue, with external lock held, until condition becomes true. Non-interruptible.
#define waiteventlocked(wq, condition, lock) do { \
        while (!(condition)) { \
            (wq)->waitinglock.acquire(); \
            (wq)->preparewait(); \
            (wq)->waitinglock.release(); \
            (lock)->release(); \
            NSched::yield(); \
            (lock)->acquire(); \
            (wq)->waitinglock.acquire(); \
            (wq)->finishwait(); \
            (wq)->waitinglock.release(); \
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
            int __finret = (wq)->finishwaitinterruptible(); \
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

// Wait on this wait queue, with external lock held, until condition becomes true. Interruptible by signals.
#define waiteventinterruptiblelocked(wq, condition, lock, result) do { \
        (result) = 0; \
        while (!(condition)) { \
            (wq)->waitinglock.acquire(); \
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
            int __finret = (wq)->finishwaitinterruptible(); \
            (wq)->waitinglock.release(); \
            if (__finret < 0) { \
                (result) = __finret; \
                break; \
            } \
        } \
    } while (0)

}

#endif
