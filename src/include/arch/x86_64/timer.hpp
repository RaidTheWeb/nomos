#ifndef _ARCH__X86_64__TIMER_HPP
#define _ARCH__X86_64__TIMER_HPP

namespace NArch {
    namespace Timer {
        void setisr(void);
        void rearm(void);

        void init(void);
    }
}

#endif