#include <sys/timer.hpp>
#include <lib/list.hpp>
#include <lib/sync.hpp>

#ifdef __x86_64__
#include <arch/x86_64/sync.hpp>
#include <arch/x86_64/cpu.hpp>
#endif

namespace NSys {
    namespace Timer {
        static NLib::Vector<OneshotEvent> events;
        static uint64_t ticks = 0;
        static NArch::IRQSpinlock lock;

        void timerlock(void) {
            lock.acquire();
        }

        void timerunlock(void) {
            lock.release();
        }

        void create(void (*callback)(void *), void *arg, uint64_t duration) {
            // This function EXPECTS the caller to have locked the timer subsystem.
            OneshotEvent event(callback, arg, ticks + duration);
            events.push(event);
        }

        void update(uint64_t current) {
            if (!lock.trylock()) {
                return; // We CANNOT afford to block waiting for a lock here. Therefore, we just leave this for the next update.
            }
            ticks = current;

            NLib::Vector<OneshotEvent> expired;
            for (size_t i = 0; i < events.getsize(); i++) {
                if (events[i].expiry <= ticks) {
                    expired.push(events[i]);
                    events[i] = events.back();
                    events.resize(events.getsize() - 1);
                    i--;
                }
            }

            lock.release();

            // Trigger callbacks without holding the lock.
            for (size_t i = 0; i < expired.getsize(); i++) {
                expired[i].trigger();
            }
        }
    }
}