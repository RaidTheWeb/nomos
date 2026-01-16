#ifndef _SCHED__JOBCTRL_HPP
#define _SCHED__JOBCTRL_HPP

#ifdef __x86_64__
#include <arch/x86_64/sync.hpp>
#endif

#include <sched/sched.hpp>
#include <std/stdatomic.h>

#include <lib/list.hpp>

namespace NSched {
    class Process;

    class Session;

    class ProcessGroup {
        private:
        public:
            NArch::IRQSpinlock lock;

            Session *session = NULL;

            size_t id = 0;
            volatile size_t refcount = 0;
            NLib::DoubleList<NSched::Process *> procs;

            void ref(void) {
                __atomic_add_fetch(&this->refcount, 1, memory_order_seq_cst);
            }

            void unref(void) {
                __atomic_sub_fetch(&this->refcount, 1, memory_order_seq_cst);
            }

            size_t getrefcount(void) {
                return __atomic_load_n(&this->refcount, memory_order_seq_cst);
            }
    };

    class Session {
        private:
        public:
            NArch::IRQSpinlock lock;

            size_t id = 0;
            uint64_t ctty = 0;
            volatile size_t refcount = 0;

            NLib::DoubleList<ProcessGroup *> pgrps;

            void ref(void) {
                __atomic_add_fetch(&this->refcount, 1, memory_order_seq_cst);
            }

            void unref(void) {
                __atomic_sub_fetch(&this->refcount, 1, memory_order_seq_cst);
            }

            size_t getrefcount(void) {
                return __atomic_load_n(&this->refcount, memory_order_seq_cst);
            }
    };
}

#endif
