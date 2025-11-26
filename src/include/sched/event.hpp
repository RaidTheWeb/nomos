#ifndef _SCHED__EVENT_HPP
#define _SCHED__EVENT_HPP

#include <lib/list.hpp>
#include <lib/sync.hpp>
#include <sched/sched.hpp>

namespace NSched {

    class WaitQueue {
        private:
            NArch::Spinlock waitinglock;
            NLib::DoubleList<Thread *> waiting;
        public:
            // Dump current thread into waiting queue, to be woken up upon wake(), if it's its turn.
            void wait(void);
            // Wake up sleeping threads in the wait queue, so they'll check if they can run again.
            void wake(void);
    };

// Wait on this wait queue, testing for condition().
#define waitevent(wq, condition) { \
        if (!(condition)) { \
            for (;;) { \
                (wq)->wait(); \
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
                (lock)->release(); \
                (wq)->wait(); \
                (lock)->acquire(); \
                if ((condition)) { \
                    break; \
                } \
            } \
        } \
    }
}

#endif
