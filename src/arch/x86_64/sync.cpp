#include <arch/x86_64/cpu.hpp>
#include <arch/x86_64/smp.hpp>
#include <arch/x86_64/sync.hpp>
#include <lib/assert.hpp>
#include <mm/slab.hpp>

namespace NArch {

    void Spinlock::acquire(void) {
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

                // Exponential backoff to reduce contention.
                backoff = (backoff << 1) | 1;
                if (backoff > BACKOFFMAX) {
                    backoff = BACKOFFMAX;
                }
            } while (this->locked);
        }

        if (SMP::initialised && CPU::get()->currthread) {
            __atomic_add_fetch(&CPU::get()->currthread->locksheld, 1, memory_order_seq_cst);
        }
    }

    bool Spinlock::trylock(void) {
        if (__atomic_exchange_n(&this->locked, 1, memory_order_acquire) == 0) {
            if (SMP::initialised && CPU::get()->currthread) {
                __atomic_add_fetch(&CPU::get()->currthread->locksheld, 1, memory_order_seq_cst);
            }
            return true;
        }
        return false;
    }

    void Spinlock::release(void) {
        if (SMP::initialised && CPU::get()->currthread) {
            __atomic_sub_fetch(&CPU::get()->currthread->locksheld, 1, memory_order_seq_cst);
        }
        __atomic_store_n(&this->locked, 0, memory_order_release);
    }

    void IRQSpinlock::acquire(void) {
        bool oldstate;
        if (CPU::get()) {
            oldstate = CPU::get()->setint(false);
            // Push saved state onto per-CPU stack for nested locks.
            size_t depth = CPU::get()->irqstackdepth;
            if (depth < CPU::cpulocal::IRQSTACKMAX) {
                CPU::get()->irqstatestack[depth] = oldstate;
                CPU::get()->irqstackdepth = depth + 1;
            }
            // If stack overflows, we just lose the state, and interrupts stay disabled.
        } else {
            asm volatile("cli");
        }
        this->lock.acquire(); // Raw acquire internal lock.
    }

    bool IRQSpinlock::trylock(void) {
        bool oldstate;
        if (CPU::get()) {
            oldstate = CPU::get()->setint(false);
            // Push saved state onto per-CPU stack for nested locks.
            size_t depth = CPU::get()->irqstackdepth;
            if (depth < CPU::cpulocal::IRQSTACKMAX) {
                CPU::get()->irqstatestack[depth] = oldstate;
                CPU::get()->irqstackdepth = depth + 1;
            }
            // If stack overflows, we just lose the state, and interrupts stay disabled.
        } else {
            asm volatile("cli");
        }
        if (this->lock.trylock()) {
            return true;
        } else {
            // Failed to acquire, restore previous interrupt state.
            if (CPU::get()) {
                size_t depth = CPU::get()->irqstackdepth;
                if (depth > 0) {
                    depth--;
                    CPU::get()->irqstackdepth = depth;
                    CPU::get()->setint(CPU::get()->irqstatestack[depth]);
                }
            } else {
                asm volatile("sti");
            }
            return false;
        }
    }

    void IRQSpinlock::release(void) {
        this->lock.release(); // Raw release internal lock.
        if (CPU::get()) {
            // Pop and restore state from per-CPU stack.
            size_t depth = CPU::get()->irqstackdepth;
            if (depth > 0) {
                depth--;
                CPU::get()->irqstackdepth = depth;
                CPU::get()->setint(CPU::get()->irqstatestack[depth]);
            }
        } else {
            asm volatile("sti");
        }
    }
}
