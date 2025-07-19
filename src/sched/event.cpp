#ifdef __x86_64__
#include <arch/x86_64/cpu.hpp>
#endif
#include <sched/event.hpp>

namespace NSched {
    void WaitQueue::wait(void) {
        __atomic_store_n(&NArch::CPU::get()->currthread->tstate, Thread::state::WAITING, memory_order_release);

        this->waitinglock.acquire();
        this->waiting.pushback(NArch::CPU::get()->currthread);
        this->waitinglock.release();
        yield();
    }

    void WaitQueue::wake(void) {
        this->waitinglock.acquire();
        if (!this->waiting.empty()) {
            Thread *thread = this->waiting.pop();
            schedulethread(thread); // Reschedule waiting thread. XXX: Consider dumping it back into the CPU that it first yielded on, for cache reasons.
        }
        this->waitinglock.release();
    }
}
