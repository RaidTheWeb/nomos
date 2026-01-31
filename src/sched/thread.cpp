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

    void Thread::init(Process *proc, size_t stacksize, void *entry, void *arg) {
        this->process = proc;

        proc->lock.acquire();
        proc->threads.push(this);
        proc->lock.release();

        __atomic_add_fetch(&proc->threadcount, 1, memory_order_seq_cst); // Add to thread count.

        // Initialise stack within HHDM, from page allocated memory. Stacks need to be unique for each thread.
        this->stack = (uint8_t *)hhdmoff((void *)((uintptr_t)PMM::alloc(stacksize)));
        assert(this->stack, "Failed to allocate thread stack.\n");

        this->stacktop = (uint8_t *)((uintptr_t)this->stack + stacksize); // Determine stack top.

        this->stacksize = stacksize;

        // Allocate thread ID.
        this->id = __atomic_fetch_add(&this->process->tidcounter, 1, memory_order_seq_cst);

        // Initialise per-thread signal mask to 0 (no signals blocked).
        this->blocked = 0;

        // Zero context.
        NLib::memset(&this->ctx, 0, sizeof(this->ctx));

        // Initialise context:
#ifdef __x86_64__
        uint64_t code = this->process->kernel ? 0x08 : 0x23;
        uint64_t data = this->process->kernel ? 0x10 : 0x1b;
        this->ctx.cs = code; // Kernel Code.

        this->ctx.ds = data; // Kernel Data.
        this->ctx.es = data; // Ditto.
        this->ctx.ss = data; // Ditto.

        this->ctx.rsp = (uint64_t)this->stacktop;
        this->ctx.rip = (uint64_t)entry;
        this->ctx.rdi = (uint64_t)arg; // Pass argument in through RDI (System V ABI first argument).

        this->ctx.rflags = 0x202; // Enable interrupts.

        if (!this->process->kernel) {
            this->fctx.fpustorage = PMM::alloc(CPU::get()->fpusize);
            assert(this->fctx.fpustorage, "Failed to allocate thread's FPU storage.\n");
            this->fctx.fpustorage = NArch::hhdmoff(this->fctx.fpustorage); // Refer to via HHDM offset.
            NLib::memset(this->fctx.fpustorage, 0, CPU::get()->fpusize); // Clear memory.

            if (CPU::get()->hasxsave) {
                uint64_t cr0 = CPU::rdcr0();
                asm volatile("clts");
                // Initialise region.
                asm volatile("xsave (%0)" : : "r"(this->fctx.fpustorage), "a"(0xffffffff), "d"(0xffffffff));
                CPU::wrcr0(cr0); // Restore original CR0 (restores TS).
            }
        }
#else
        assert(false, "Thread init not implemented on this architecture.");
#endif
    }

    void Thread::destroy(void) {
        // Free FPU storage if allocated.
#ifdef __x86_64__
        if (!this->process->kernel && this->fctx.fpustorage) {
            PMM::free(hhdmsub(this->fctx.fpustorage), CPU::get()->fpusize);
            this->fctx.fpustorage = NULL;
        }
#endif

        PMM::free(hhdmsub(this->stack), this->stacksize); // Free stack.

        this->process->lock.acquire();
        this->process->threads.remove([](Thread *t, void *arg) {
            return t == ((Thread *)arg);
        }, (void *)this);
        this->process->lock.release();

        size_t remaining = __atomic_sub_fetch(&this->process->threadcount, 1, memory_order_seq_cst);
        if (remaining == 0) {
            // Last thread. Zombify the process.
            this->process->zombify();
        }
    }

    void markdeadandremove(Thread *thread) {
        // Disable migration first to stabilize cid.
        thread->disablemigrate();

        // Mark thread as dead.
        setthreadstate(thread, Thread::state::DEAD, "markdeadandremove");

        // Clear pending wait state.
        __atomic_store_n(&thread->pendingwaitstate, Thread::pendingwait::PENDING_NONE, memory_order_release);

        // Remove from waitqueue if queued.
        thread->waitingonlock.acquire();
        WaitQueue *wq = thread->waitingon;
        thread->waitingonlock.release();

        if (wq) {
            wq->dequeue(thread);
        }

        // Remove from runqueue if present. cid is stable because migration is disabled.
        if (__atomic_load_n(&thread->inrunqueue, memory_order_acquire)) {
            size_t cid = __atomic_load_n(&thread->cid, memory_order_acquire);
            if (cid < SMP::awakecpus) {
                struct CPU::cpulocal *cpu = SMP::cpulist[cid];
                // Use trylock for cross-CPU access to avoid spinning with interrupts disabled.
                // If we can't get the lock, the thread will be cleaned up when that CPU schedules.
                bool acquired = (cpu == CPU::get()) ? (cpu->runqueue.lock.acquire(), true) : cpu->runqueue.lock.trylock();
                if (acquired) {
                    // Re-check under lock.
                    if (__atomic_load_n(&thread->inrunqueue, memory_order_acquire)) {
                        cpu->runqueue._erase(&thread->node);
                        __atomic_store_n(&thread->inrunqueue, false, memory_order_release);
                    }
                    cpu->runqueue.lock.release();
                }
            }
        }

        // Get cid for IPI before re-enabling migration.
        size_t cid = __atomic_load_n(&thread->cid, memory_order_acquire);

        // Re-enable migration before IPI.
        thread->enablemigrate();

        // Send IPI to ensure remote CPU sees the state change (if not self).
        if (cid < SMP::awakecpus && cid != CPU::get()->id) {
            APIC::sendipi(SMP::cpulist[cid]->lapicid, 0xfe, APIC::IPIFIXED, APIC::IPIPHYS, 0);
        }
    }

    extern "C" uint64_t sys_yield(void) {
        SYSCALL_LOG("sys_yield().\n");
        yield();
        SYSCALL_RET(0);
    }

    extern "C" ssize_t sys_newthread(void *entry, void *stack) {
        SYSCALL_LOG("sys_newthread(%p, %p).\n", entry, stack);

        Process *proc = NArch::CPU::get()->currthread->process;

        Thread *newthread = new Thread(proc, NSched::DEFAULTSTACKSIZE);
        if (!newthread) {
            SYSCALL_RET(-ENOMEM);
        }

        newthread->ctx.rip = (uint64_t)entry;
        newthread->ctx.rsp = (uint64_t)stack;

        NSched::schedulethread(newthread);
        SYSCALL_RET(newthread->id);
    }

    extern "C" ssize_t sys_exitthread(void) {
        SYSCALL_LOG("sys_exitthread().\n");

        // Mark ourselves as dead and yield.
        NSched::setthreadstate(NArch::CPU::get()->currthread, Thread::state::DEAD, "sys_exitthread");
        yield();

        __builtin_unreachable();
    }

    extern "C" uint64_t sys_exit(int status) {
        SYSCALL_LOG("sys_exit(%d).\n", status);

        exit(status); // Exit.
        __builtin_unreachable();
    }
}