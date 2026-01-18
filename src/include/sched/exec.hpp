#ifndef _SCHED__EXEC_HPP
#define _SCHED__EXEC_HPP

#ifdef __x86_64__
#include <arch/x86_64/vmm.hpp>
#endif
#include <fs/vfs.hpp>
#include <sys/elf.hpp>

#include <stddef.h>
#include <stdint.h>

namespace NSched {

    // Maximum depth of interpreter recursion (shebang scripts calling other scripts).
    static const int MAXINTERPDEPTH = 4;

    // Maximum length of shebang line (including #!).
    static const size_t MAXSHEBANGLEN = 256;

    // Maximum argument count for exec.
    static const size_t ARGMAX = 4096;

    struct execparams {
        const char *path; // Path to executable.

        char **argv;
        char **envp;
        size_t argc;
        size_t envc;

        // Execution context.
        NFS::VFS::INode *cwd;
        NFS::VFS::INode *root;

        // Credentials for permission checking.
        int uid, gid;
        int euid, egid;

        // Flags.
        bool checkperms; // Whether to check execute permission.
        bool issyscall; // True if called from syscall (vs kernel init).

        int interpdepth;
    };

    struct execresult {
        NArch::VMM::addrspace *addrspace; // New address space.

        // Entry point to start execution at.
        void *entry;

        // Initial stack pointer (virtual address in new space).
        void *stackptr;

        // Stack region info.
        uintptr_t stackbase; // Virtual base of stack.
        size_t stacksize; // Size of stack.

        // Credential changes (SUID/SGID).
        int neweuid, newegid;
        bool suid, sgid; // Whether SUID/SGID bits were applied.
    };

    // Shebang parse result.
    struct shebanginfo {
        char interpreter[256]; // Interpreter path.
        char arg[256]; // Optional single argument.
        bool hasarg; // Whether argument was present.
    };

    // Parse shebang from file.
    int parseshebang(NFS::VFS::INode *inode, struct shebanginfo *info);

    // Turn parameters into result.
    int exec(const struct execparams *params, struct execresult *result);

    void freeexecresult(struct execresult *result);

    void freeargsenvs(char **arr, size_t arrc);

}

#endif
