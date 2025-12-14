#ifndef _SYS__TIMER_HPP
#define _SYS__TIMER_HPP

#include <stdint.h>

namespace NSys {

    namespace Timer {
        class OneshotEvent {
            public:
                void (*callback)(void *);
                void *arg;
                uint64_t expiry;

                OneshotEvent(void (*callback)(void *), void *arg, uint64_t expiry) {
                    this->callback = callback;
                    this->arg = arg;
                    this->expiry = expiry;
                }

                void trigger(void) {
                    if (this->callback) {
                        this->callback(this->arg);
                    }
                }
        };

        // Exposed lock/unlock functions for use by other subsystems.
        void timerlock(void);
        void timerunlock(void);

        // Create a new one-shot timer event, duration is not guaranteed to be exact, as the timer sometimes does its best to avoid doing any work.
        void create(void (*callback)(void *), void *arg, uint64_t duration);
        void update(uint64_t current);
    }
}

#endif