#include <arch/x86_64/rtc.hpp>
#include <lib/errno.hpp>

namespace NArch {
    namespace RTC {

        int gettime(struct NSys::Clock::timespec *ts) {
            // XXX: To implement.
            (void)ts;
            return -ENOSYS;
        }
    }
}