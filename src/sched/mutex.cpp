#ifdef __x86_64__
#include <arch/x86_64/apic.hpp>
#include <arch/x86_64/cpu.hpp>
#include <arch/x86_64/e9.hpp>
#include <arch/x86_64/smp.hpp>
#include <arch/x86_64/stacktrace.hpp>
#include <arch/x86_64/tsc.hpp>
#include <arch/x86_64/timer.hpp>
#endif
#include <fs/devfs.hpp>
#include <lib/assert.hpp>
#include <mm/slab.hpp>
#include <mm/ucopy.hpp>
#include <sched/event.hpp>
#include <sched/sched.hpp>
#include <std/stdatomic.h>
#include <sys/clock.hpp>
#include <sys/elf.hpp>
#include <sys/syscall.hpp>
#include <sys/timer.hpp>

namespace NSched {
    using namespace NArch;


    void Mutex::acquire(void) {
        Thread *current = NArch::CPU::get()->currthread;
        assert(current != NArch::CPU::get()->idlethread, "Mutex acquire on idle thread.\n");

        while (true) {
#ifdef __x86_64__
            // Try to acquire the lock with a simple atomic exchange.
            if (__atomic_exchange_n(&this->locked, 1, memory_order_acquire) == 0) {
                break; // Got the lock (it was previously unlocked).
            }
#endif

            // Lock is contended, wait on the waitqueue.
            this->waitqueue.waitinglock.acquire();

            // Double-check the lock is still held after acquiring waitqueue lock.
#ifdef __x86_64__
            if (__atomic_exchange_n(&this->locked, 1, memory_order_acquire) == 0) {
                this->waitqueue.waitinglock.release();
                break; // Got the lock.
            }
#endif

            // Use the WaitQueue's wait mechanism with lock already held.
            this->waitqueue.wait(true);
        }

        __atomic_add_fetch(&current->locksheld, 1, memory_order_seq_cst);
    }

    void Mutex::release(void) {
        Thread *current = NArch::CPU::get()->currthread;
        __atomic_sub_fetch(&current->locksheld, 1, memory_order_seq_cst);
#ifdef __x86_64__
        __atomic_store_n(&this->locked, 0, memory_order_release);
#endif

        // Wake one waiting thread, if any (next in line).
        this->waitqueue.wakeone();
    }

    void exit(int status, int sig) {
        // Thread exit.

        Process *proc = NArch::CPU::get()->currthread->process;

        if (!proc->kernel) { // Only perform process exit logic on user threads.

            if (proc->id == 1) {
                panic("Init got obliterated (either by itself or someone else).\n");
            }

            termothers(proc); // Terminate other threads in this process.

            {
                NLib::ScopeIRQSpinlock guard(&proc->lock);
                if (sig != 0) {
                    // If we're exiting due to a signal, encode that in exit status.
                    proc->exitstatus = (sig & 0x7f);
                } else { // Normal exit.
                    proc->exitstatus = (status & 0xff) << 8;
                }
            }

            if (proc->fdtable) {
                proc->fdtable->closeall(); // Close so we can be done with files asap.
            }
        }

        setthreadstate(CPU::get()->currthread, Thread::state::DEAD, "exit"); // Kill ourselves. We will NOT be rescheduled.
        CPU::writemb();

        yield(); // Yield back to scheduler, so the thread never gets rescheduled.

        assert(false, "Exiting thread was rescheduled!");
    }
}