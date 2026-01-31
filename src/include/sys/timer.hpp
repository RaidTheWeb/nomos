#ifndef _SYS__TIMER_HPP
#define _SYS__TIMER_HPP

#include <stdint.h>

namespace NSys {

    namespace Timer {
        // Timer handle for cancellation.
        typedef uint64_t timerhandle_t;

        class OneshotEvent {
            public:
                void (*callback)(void *);
                void *arg;
                uint64_t expiry;
                timerhandle_t handle;
                bool cancelled;

                OneshotEvent(void (*callback)(void *), void *arg, uint64_t expiry, timerhandle_t handle = 0) {
                    this->callback = callback;
                    this->arg = arg;
                    this->expiry = expiry;
                    this->handle = handle;
                    this->cancelled = false;
                }

                void trigger(void) {
                    if (this->callback && !this->cancelled) {
                        this->callback(this->arg);
                    }
                }
        };

        // Exposed lock/unlock functions for use by other subsystems.
        void timerlock(void);
        void timerunlock(void);

        // Create a new one-shot timer event, duration is not guaranteed to be exact, as the timer sometimes does its best to avoid doing any work.
        // Returns a handle that can be used to cancel the timer.
        timerhandle_t create(void (*callback)(void *), void *arg, uint64_t duration);

        // Cancel a timer by handle.
        bool cancel(timerhandle_t handle);

        void update(uint64_t current);
    }
}

#endif