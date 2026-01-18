#ifndef _SYS__FAULT_HPP
#define _SYS__FAULT_HPP

#include <stdint.h>

namespace NSys {

    // XXX: Consider more parts of the kernel that could benefit from this. This is only really used in usercopy stuff right now.


    // Sort of hacky trick to handle recovering from known faults. Pretty useful for ucopy operations.
    // When an exception occurs, we can check if the faulting address matches any known fault entries, and if so, we can jump to the specified recovery address.
    // NOTE: This REQUIRES that faulting entries exist on a specific instruction boundary, and that the recovery code is valid.

    struct faultentry {
        uintptr_t addr; // Address of faulting instruction.
        uintptr_t fixaddr; // Address to jump to in order to recover.
    };

    // Check if a fault occurred at a known fault entry, and return the recovery address if so.
    uintptr_t checkfault(uintptr_t faultaddr);
}

#endif