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
        char domainname[65];
    };

    // Kernel utsname instance, can be modified by certain syscalls.
    struct utsname kutsname = {
        { "Nomos" },
        { "nomos" },
        { VERSION },
        { BUILDDATE },
#ifdef __x86_64__
        { "x86_64" },
#else
        { "unknown" },
#endif
        { "nomos" }
    };

    extern "C" uint64_t sys_sethostname(const char *name, size_t len) {
        SYSCALL_LOG("sys_sethostname(%s, %lu).\n", name, len);

        {
            NSched::Process *current = NArch::CPU::get()->currthread->process;
            NLib::ScopeIRQSpinlock guard(&current->lock);
            if (current->euid != 0) { // Must be root to change hostname.
                SYSCALL_RET(-EPERM);
            }
        }


        ssize_t res = NMem::UserCopy::valid(name, len);
        if (res < 0) {
            SYSCALL_RET(res); // Contains errno.
        }

        ssize_t namesize = NMem::UserCopy::strnlen(name, len);
        if (namesize < 0) {
            SYSCALL_RET(namesize); // Contains errno.
        }
        if (namesize >= 65) {
            SYSCALL_RET(-ENAMETOOLONG);
        }

        char kname[65];
        res = NMem::UserCopy::strncpyfrom(kname, name, namesize);
        if (res < 0) {
            SYSCALL_RET(res); // Contains errno.
        }
        kname[namesize] = '\0';

        NLib::strncpy(kutsname.nodename, kname, sizeof(kutsname.nodename));

        SYSCALL_RET(0);
    }

    extern "C" uint64_t sys_uname(struct utsname *buf) {
        SYSCALL_LOG("sys_uname(%p).\n", buf);

        if (!NMem::UserCopy::valid(buf, sizeof(struct utsname))) {
            SYSCALL_RET(-EFAULT);
        }

        struct utsname kbuf;
        NLib::strncpy(kbuf.sysname, kutsname.sysname, sizeof(kbuf.sysname));
        NLib::strncpy(kbuf.nodename, kutsname.nodename, sizeof(kbuf.nodename));
        NLib::strncpy(kbuf.release, kutsname.release, sizeof(kbuf.release));
        NLib::strncpy(kbuf.version, kutsname.version, sizeof(kbuf.version));
        NLib::strncpy(kbuf.machine, kutsname.machine, sizeof(kbuf.machine));
        NLib::strncpy(kbuf.domainname, kutsname.domainname, sizeof(kbuf.domainname));

        if (NMem::UserCopy::copyto(buf, &kbuf, sizeof(struct utsname)) < 0) {
            SYSCALL_RET(-EFAULT);
        }

        SYSCALL_RET(0);
    }
}