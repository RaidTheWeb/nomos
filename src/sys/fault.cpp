#include <sys/fault.hpp>

extern "C" struct NSys::faultentry __faulttable_start[];
extern "C" struct NSys::faultentry __faulttable_end[];

namespace NSys {
    uintptr_t checkfault(uintptr_t faultaddr) {
        struct faultentry *start = __faulttable_start;
        struct faultentry *end = __faulttable_end;


        // Attempt binary search for faultaddr in the fault table.
        // XXX: What if the linker doesn't sort these properly? May need to sort at runtime.
        while (start < end) {
            struct faultentry *mid = start + (end - start) / 2;
            if (mid->addr == faultaddr) {
                return mid->fixaddr;
            } else if (mid->addr < faultaddr) {
                start = mid + 1;
            } else {
                end = mid;
            }
        }

        return 0; // No matching fault entry found.
    }
}