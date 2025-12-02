#ifndef _ARCH__X86_64__SYNC_HPP
#define _ARCH__X86_64__SYNC_HPP

#include <arch/limine/console.hpp>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>

namespace NArch {
    __attribute__((used))
    static const size_t BACKOFFMIN = 4;

    __attribute__((used))
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

            void acquire(void);
            bool trylock(void);
            void release(void);
    };

    // Special wrapper class for spinlocks that blocks and disables interrupts while holding the lock. NOTE: Do NOT use in thread-thread synchronisation cases, only for thread-interrupt synchronisation cases.
    class IRQSpinlock {
        private:
            bool state;
            NArch::Spinlock lock;
        public:
            IRQSpinlock(void) {
                this->state = false;
            }

            void acquire(void);
            void release(void);
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
