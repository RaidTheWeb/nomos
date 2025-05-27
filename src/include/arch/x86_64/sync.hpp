#ifndef _ARCH__X86_64__SYNC_HPP
#define _ARCH__X86_64__SYNC_HPP

#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>

namespace NArch {
    __attribute__((unused))
    static const size_t BACKOFFMIN = 4;

    __attribute__((unused))
    static const size_t BACKOFFMAX = 1024;

    // Bog-standard spinlock implementation, with included "backoff" to reduce load, while still consuming busy wait time.
    // Best suited for operations we can guarantee are short, but are still "critical sections".
    class Spinlock {
        private:
            volatile uint32_t locked;
        public:
            Spinlock(void) {
                this->locked = 0;
            }

            void acquire(void) {
                while (true) {
                    if (__atomic_exchange_n(&this->locked, 1, memory_order_acquire) == 0) { // Try to exchange, if it goes through with success, we now own the lock.
                        break; // Success!
                    }

                    // Otherwise, wait on it.

                    size_t backoff = BACKOFFMIN;
                    do {
                        for (size_t i = 0; i < backoff; i++) {
                            asm volatile("pause"); // Pause to avoid consuming crazy amounts of power during contention. Backoff is used to reduce contention.
                        }

                        backoff = (backoff << 1) | 1;
                        if (backoff > BACKOFFMAX) {
                            backoff = BACKOFFMAX;
                        }
                    } while (this->locked);
                }
            }

            bool trylock(void) {
                // Only *attempt* to acquire the lock.
                return __atomic_exchange_n(&this->locked, 1, memory_order_acquire) == 0;
            }

            void release(void) {
                // Release the lock.
                __atomic_store_n(&this->locked, 0, memory_order_release);
            }
    };



    // Mellor-Crummey and Scott spinlock implementation.
    // Includes handling off lock depth, and integrates with thread_local to provide individual states to each CPU.
    // In-all-other-cases primitive that can handle higher contention than the bog-standard spinlock primitive.
    class MCSSpinlock {
        private:

            struct mcsnode {
                struct mcsnode *next;
                volatile uint32_t locked;
            };

            struct mcsnode *tail = NULL;
        public:
            struct state {
                struct mcsnode *node;
                uint8_t depth = 0;
                uint8_t inited = false;
            };
            MCSSpinlock(void) { };

            static void initstate(struct state *state);

            void acquire(void);
            void release(void);
    };
}

#endif
