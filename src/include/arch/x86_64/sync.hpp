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
    // Can deadlock in interrupt context. Use IRQSpinlock instead if there is any chance an interrupt handler could try to acquire the same lock.
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
    // This should ONLY be used for *very* short critical sections, otherwise, we risk deadlocking on TLB shootdowns and other interrupt-context operations.
    class IRQSpinlock {

        private:
            NArch::Spinlock lock;
        public:
            IRQSpinlock(void) { }

            void acquire(void);
            bool trylock(void);
            void release(void);
    };
}

#endif
