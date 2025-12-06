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
                if (!(condition)) { \
                    (wq)->wait(true); \
                } else { \
                    (wq)->waitinglock.release(); \
                } \
                if ((condition)) { \
                    break; \
                } \
            } \
        } \
    }

// Wait on this wait queue, testing for condition(). Manages waiting upon an active lock, will leave the lock active on return. NOTE: Recommended for when the calling thread holds active locks, as wake up does not guarantee wake up on the same CPU it slept on.
#define waiteventlocked(wq, condition, lock) { \
        if (!(condition)) { \
            for (;;) { \
                (wq)->waitinglock.acquire(); \
                (lock)->release(); \
                if (!(condition)) { \
                    (wq)->wait(true); \
                    (lock)->acquire(); \
                } else { \
                    (wq)->waitinglock.release(); \
                    (lock)->acquire(); \
                } \
                if ((condition)) { \
                    break; \
                } \
            } \
        } \
    }
}

#endif
