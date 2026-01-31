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

    #define FUTEX_WAIT          0
    #define FUTEX_WAKE          1
    #define FUTEX_PRIVATE_FLAG  128
    #define FUTEX_CMD_MASK      (~FUTEX_PRIVATE_FLAG)

    struct futexentry {
        WaitQueue wq;
        size_t waiters; // Number of threads waiting on this futex.
    };

    // Key is physical address of futex! Pretty neat, actually, since shared memory works correctly.
    static NLib::KVHashMap<uintptr_t, struct futexentry *> *futextable = NULL;
    static NArch::IRQSpinlock futexlock;

    // Get or create a futex entry for a given physical address.
    static struct futexentry *futexget(uintptr_t phys) {
        struct futexentry **entry = futextable->find(phys);
        if (entry) {
            return *entry;
        }

        // Create a new futex entry.
        struct futexentry *newentry = new struct futexentry;
        newentry->waiters = 0;
        futextable->insert(phys, newentry);
        return newentry;
    }

    // Remove futex entry if no more waiters.
    static void futexput(uintptr_t phys, struct futexentry *entry) {
        if (entry->waiters == 0) {
            futextable->remove(phys);
            delete entry;
        }
    }

    // Wait state for sleep()-like interruptible wake with timeout.
    struct futexwaitstate {
        WaitQueue *wq;
        bool timerfired;
        bool threadwoke;
        NArch::IRQSpinlock lock;
    };

    // Timer callback for futex timeout.
    static void futextimeoutwork(void *arg) {
        struct futexwaitstate *state = (struct futexwaitstate *)arg;

        state->lock.acquire();
        state->timerfired = true;
        bool threadwoke = state->threadwoke;
        state->lock.release();

        if (!threadwoke) {
            // Thread is still sleeping. Wake it.
            state->wq->wakeone();
        }

    }

    extern "C" ssize_t sys_futex(int *ptr, int op, int expected, struct NSys::Clock::timespec *timeout) {
        SYSCALL_LOG("sys_futex(%p, %d, %d, %p).\n", ptr, op, expected, timeout);

        // Lazily initialise the futex table.
        if (!futextable) {
            futexlock.acquire();
            if (!futextable) {
                futextable = new NLib::KVHashMap<uintptr_t, struct futexentry *>();
            }
            futexlock.release();
        }

        // Validate pointer.
        if (!ptr || !NMem::UserCopy::valid(ptr, sizeof(int))) {
            SYSCALL_RET(-EFAULT);
        }

        // Get physical address for futex key (shared memory works correctly).
        Process *proc = NArch::CPU::get()->currthread->process;
        uintptr_t phys = NArch::VMM::virt2phys(proc->addrspace, (uintptr_t)ptr);
        if (phys == 0) {
            SYSCALL_RET(-EFAULT);
        }

        int cmd = op & FUTEX_CMD_MASK;

        switch (cmd) {
            case FUTEX_WAIT: {
                // Copy timeout from userspace if provided.
                uint64_t timeoutms = 0;
                bool hastimeout = false;
                if (timeout) {
                    struct NSys::Clock::timespec ktimeout;
                    if (NMem::UserCopy::copyfrom(&ktimeout, timeout, sizeof(struct NSys::Clock::timespec)) < 0) {
                        SYSCALL_RET(-EFAULT);
                    }
                    if (ktimeout.tv_sec < 0 || ktimeout.tv_nsec < 0 || ktimeout.tv_nsec >= NSys::Clock::NSEC_PER_SEC) {
                        SYSCALL_RET(-EINVAL);
                    }
                    // Convert to milliseconds, rounding up.
                    timeoutms = (uint64_t)ktimeout.tv_sec * NSys::Clock::MSEC_PER_SEC;
                    timeoutms += (ktimeout.tv_nsec + 999999) / 1000000;
                    hastimeout = true;
                }

                futexlock.acquire();
                struct futexentry *entry = futexget(phys);

                // Atomically check the futex value.
                int currentval;
                if (NMem::UserCopy::copyfrom(&currentval, ptr, sizeof(int)) < 0) {
                    futexput(phys, entry);
                    futexlock.release();
                    SYSCALL_RET(-EFAULT);
                }

                if (currentval != expected) {
                    futexput(phys, entry);
                    futexlock.release();
                    SYSCALL_RET(-EAGAIN);
                }

                entry->waiters++;
                futexlock.release();

                int ret = 0;

                if (hastimeout && timeoutms > 0) {
                    // Wait with timeout.
                    struct futexwaitstate *state = new struct futexwaitstate;
                    state->wq = &entry->wq;
                    state->timerfired = false;
                    state->threadwoke = false;

                    NSys::Timer::timerlock();
                    NSys::Timer::create(futextimeoutwork, state, timeoutms);
                    NSys::Timer::timerunlock();

                    ret = entry->wq.waitinterruptible();

                    // Mark that we've woken up and check if timer fired.
                    state->lock.acquire();
                    state->threadwoke = true;
                    bool timerfired = state->timerfired;
                    state->lock.release();

                    delete state;

                    if (timerfired && ret == 0) {
                        // Timer woke us, this is a timeout.
                        ret = -ETIMEDOUT;
                    }
                } else if (hastimeout && timeoutms == 0) {
                    // Zero timeout means don't wait at all.
                    ret = -ETIMEDOUT;
                } else {
                    // Wait without timeout.
                    ret = entry->wq.waitinterruptible();
                }

                futexlock.acquire();
                entry->waiters--;
                futexput(phys, entry);
                futexlock.release();

                SYSCALL_RET(ret);
            }

            case FUTEX_WAKE: {
                futexlock.acquire();
                struct futexentry **entryptr = futextable->find(phys);
                if (!entryptr) {
                    futexlock.release();
                    SYSCALL_RET(0); // No waiters.
                }

                struct futexentry *entry = *entryptr;
                int woken = 0;
                int towake = expected; // 'expected' is actually the count for FUTEX_WAKE.

                size_t actualwaiters = entry->waiters;
                while (towake > 0 && actualwaiters > 0) {
                    entry->wq.wakeone(); // Wake up whatever we can.
                    woken++;
                    towake--;
                    actualwaiters--;
                }

                futexlock.release();
                SYSCALL_RET(woken);
            }

            default:
                SYSCALL_RET(-ENOSYS);
        }
    }
}