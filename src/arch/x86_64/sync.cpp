#include <arch/x86_64/cpu.hpp>
#include <arch/x86_64/sync.hpp>
#include <lib/assert.hpp>
#include <mm/slab.hpp>

namespace NArch {

    void IRQSpinlock::acquire(void) {
        this->state = CPU::get()->setint(false); // Disable interrupts. Stops preemption.
        this->lock->acquire(); // Raw acquire internal lock.
                               //
    }

    void IRQSpinlock::release(void) {
        this->lock->release(); // Raw release internal lock.
        CPU::get()->setint(this->state); // Restore initial interrupt state.
    }

    // XXX: This needs to be made thread local!
    void MCSSpinlock::initstate(struct state *state) {
        state->depth = 0;
        state->node = new struct mcsnode;
        state->node->next = NULL;
        state->node->locked = 0;
        state->inited = true;
    }

    void MCSSpinlock::acquire(void) {
        struct MCSSpinlock::state *mcsstate = &CPU::get()->mcsstate;

        assert(mcsstate->depth < 16, "Maximum MCS lock depth exceeded.\n");

        if (!mcsstate->inited) {
            this->initstate(mcsstate);
        }

        struct mcsnode *node = mcsstate->node;
        node->next = NULL;
        node->locked = 1;

        // Enter ourselves into the tail, this will disrupt release operations during contention, but we handle that with a handoff procedure.
        struct mcsnode *prev = __atomic_exchange_n(&this->tail, node, memory_order_seq_cst);

        // If a previous node exists, there is contention on the long, and we need to wait on it.
        if (prev) {
            __atomic_store_n(&prev->next, node, memory_order_release); // Enter ourselves next in line after the previous node.

            while (__atomic_load_n(&node->locked, memory_order_acquire)) {
                // Await on acquisition of lock.
                asm volatile("pause" : : : "memory");
            }
        }

        mcsstate->depth++;
    }

    void MCSSpinlock::release(void) {
        struct MCSSpinlock::state *mcsstate = &CPU::get()->mcsstate;

        struct mcsnode *node = mcsstate->node;

        // If there is no next node in the queue (we are the last node), we can immediately release if this is the case, but this can change later:
        if (!__atomic_load_n(&node->next, memory_order_acquire)) {
            struct mcsnode *expected = node;
            // NUtil::printf("expecting 0x%0llx.\n", expected);
            // Attempt to set the tail to nothing (proper release)
            // But, if the tail is somehow not us, this indicates that someone else just came along and entered the line, in which case, we need to hand off to them.
            if (__atomic_compare_exchange_n(&this->tail, &expected, NULL, false, memory_order_release, memory_order_relaxed)) {
                goto release; // Successfully released access.
            }

            // Await handoff to next owner.
            // Matches with the release store in acquire().
            // For as long as they haven't yet set our next node to themselves, we wait.
            while (!__atomic_load_n(&node->next, memory_order_acquire)) {
                asm volatile("pause" : : : "memory");
            }
        }

        // Release our lock state.
        __atomic_store_n(&node->next->locked, 0, memory_order_release);
release:
        mcsstate->depth--;
    }
}
