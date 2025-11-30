#ifndef __SYS__TIMER_HPP
#define __SYS__TIMER_HPP

#include <stdint.h>

namespace NSys {

    namespace Timer {
        class OneshotEvent {
            public:
                void (*callback)(void *);
                void *arg;
                uint64_t expire_time;

                OneshotEvent(void (*callback)(void *), void *arg, uint64_t expire_time) {
                    this->callback = callback;
                    this->arg = arg;
                    this->expire_time = expire_time;
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

        void create(void (*callback)(void *), void *arg, uint64_t duration);
        void update(uint64_t current);
        void init(void);
    }
}

#endif