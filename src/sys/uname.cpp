#ifdef __x86_64__
#include <arch/x86_64/cpu.hpp>
#endif
#include <lib/errno.hpp>
#include <lib/string.hpp>
#include <mm/ucopy.hpp>
#include <sched/sched.hpp>
#include <stdint.h>
#include <sys/syscall.hpp>
#include <util/kprint.hpp>

namespace NSys {
    struct utsname {
        char sysname[65];
        char nodename[65];
        char release[65];
        char version[65];
        char machine[65];
    };

    extern "C" uint64_t sys_uname(struct utsname *buf) {
        SYSCALL_LOG("sys_uname(%p).\n", buf);

        if (!NMem::UserCopy::valid(buf, sizeof(struct utsname))) {
            return -EFAULT;
        }

        struct utsname kbuf;
        NLib::strncpy(kbuf.sysname, "Nomos", sizeof(kbuf.sysname));
        NLib::strncpy(kbuf.nodename, "nomos", sizeof(kbuf.nodename));
        NLib::strncpy(kbuf.release, VERSION, sizeof(kbuf.release));
        NLib::strncpy(kbuf.version, "Nomos " VERSION, sizeof(kbuf.version));
#ifdef __x86_64__
        NLib::strncpy(kbuf.machine, "x86_64", sizeof(kbuf.machine));
#endif

        if (NMem::UserCopy::copyto(buf, &kbuf, sizeof(struct utsname)) < 0) {
            return -EFAULT;
        }

        return 0;
    }
}