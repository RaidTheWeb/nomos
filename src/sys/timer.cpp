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
        static volatile uint64_t ticks = 0;
        static NArch::IRQSpinlock lock;
        static uint64_t nexthandle = 1;

        void timerlock(void) {
            lock.acquire();
        }

        void timerunlock(void) {
            lock.release();
        }

        static void triggerwork(struct NSched::work *w) {
            OneshotEvent *udata = (OneshotEvent *)w->udata;
            if (udata) {
                udata->trigger();
            }
        }


        timerhandle_t create(void (*callback)(void *), void *arg, uint64_t duration) {
            // This function EXPECTS the caller to have locked the timer subsystem.
            uint64_t curticks = __atomic_load_n(&ticks, memory_order_acquire);
            timerhandle_t handle = nexthandle++;
            OneshotEvent event(callback, arg, curticks + duration, handle);
            events.push(event);
            return handle;
        }

        bool cancel(timerhandle_t handle) {
            // Caller must hold timer lock.
            for (size_t i = 0; i < events.getsize(); i++) {
                if (events[i].handle == handle && !events[i].cancelled) {
                    events[i].cancelled = true;
                    return true;
                }
            }
            return false;
        }

        void update(uint64_t current) {
            // Always update the tick counter, even if we can't process events.
            __atomic_store_n(&ticks, current, memory_order_release);

            if (!lock.trylock()) {
                return;
            }

            // Re-read ticks under lock to get the most recent value.
            uint64_t now = __atomic_load_n(&ticks, memory_order_acquire);

            NLib::Vector<OneshotEvent> expired;
            for (size_t i = 0; i < events.getsize(); i++) {
                // Remove cancelled events without triggering.
                if (events[i].cancelled) {
                    events[i] = events.back();
                    events.resize(events.getsize() - 1);
                    i--;
                    continue;
                }
                if (events[i].expiry <= now) {
                    expired.push(events[i]);
                    events[i] = events.back();
                    events.resize(events.getsize() - 1);
                    i--;
                }
            }

            lock.release();

            // XXX: Even outside the timer lock, interrupts are still disabled, so long callbacks could impact latency (potentially even causing shootdowns).

            // Trigger callbacks without holding the lock.
            for (size_t i = 0; i < expired.getsize(); i++) {
                expired[i].trigger();
            }
        }
    }
}