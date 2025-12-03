#ifndef _SCHED__JOBCTRL_HPP
#define _SCHED__JOBCTRL_HPP

#ifdef __x86_64__
#include <arch/x86_64/sync.hpp>
#endif

#include <lib/list.hpp>

namespace NSched {
    class Process;

    class Session;

    class ProcessGroup {
        private:
        public:
            NArch::IRQSpinlock lock;

            Session *session;

            size_t id;
            NLib::DoubleList<NSched::Process *> procs;
    };

    class Session {
        private:
        public:
            NArch::IRQSpinlock lock;

            size_t id;
            uint64_t ctty;

            NLib::DoubleList<ProcessGroup *> pgrps;
    };
}

#endif
