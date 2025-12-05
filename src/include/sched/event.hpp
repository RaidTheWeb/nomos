#ifndef _SCHED__EVENT_HPP
#define _SCHED__EVENT_HPP

#include <lib/list.hpp>
#include <lib/sync.hpp>
#include <sched/sched.hpp>

namespace NSched {

    class WaitQueue {
        private:
            NLib::DoubleList<Thread *> waiting;
        public:

            NArch::IRQSpinlock waitinglock;
            // Dump current thread into waiting queue, to be woken up upon wake(), if it's its turn. Takes an optional parameter specifying whether the wait queue lock is already held.
            void wait(bool locked = false);
            // Wake up sleeping threads in the wait queue, so they'll check if they can run again.
            void wake(void);
    };

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
