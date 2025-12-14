#ifndef _ARCH__X86_64__RTC_HPP
#define _ARCH__X86_64__RTC_HPP

#include <stdint.h>
#include <sys/clock.hpp>

namespace NArch {
    namespace RTC {
        int gettime(struct NSys::Clock::timespec *ts);

        void init(void);
    }
}

#endif