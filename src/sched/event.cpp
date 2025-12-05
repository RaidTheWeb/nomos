#ifdef __x86_64__
#include <arch/x86_64/cpu.hpp>
#endif
#include <sched/event.hpp>

namespace NSched {
    void WaitQueue::wait(bool locked) {
        if (!locked) {
            this->waitinglock.acquire(); // We MUST acquire the lock before setting the thread to waiting, otherwise we'll never be rescheduled when the timeslice expires.

        }
        __atomic_store_n(&NArch::CPU::get()->currthread->tstate, Thread::state::WAITING, memory_order_release);
        this->waiting.pushback(NArch::CPU::get()->currthread);

        this->waitinglock.release();
        yield();
    }

    void WaitQueue::wake(void) {
        NLib::SingleList<Thread *> towake;
        this->waitinglock.acquire();
        while (!this->waiting.empty()) {
            Thread *thread = this->waiting.pop();
            towake.push(thread);
        }
        this->waitinglock.release();

        // Schedule all threads that were waiting.
        for (NLib::SingleList<Thread *>::Iterator it = towake.begin(); it.valid(); it.next()) {
            Thread *thread = *(it.get());
            schedulethread(thread);
        }
    }
}
