#ifdef __x86_64__
#include <arch/x86_64/apic.hpp>
#include <arch/x86_64/cpu.hpp>
#include <arch/x86_64/e9.hpp>
#include <arch/x86_64/smp.hpp>
#include <arch/x86_64/stacktrace.hpp>
#include <arch/x86_64/tsc.hpp>
#include <arch/x86_64/timer.hpp>
#endif
#include <fs/devfs.hpp>
#include <lib/assert.hpp>
#include <mm/slab.hpp>
#include <mm/ucopy.hpp>
#include <mm/vmalloc.hpp>
#include <sched/event.hpp>
#include <sched/exec.hpp>
#include <sched/sched.hpp>
#include <sys/clock.hpp>
#include <sys/elf.hpp>
#include <sys/syscall.hpp>
#include <sys/timer.hpp>

namespace NSched {
    using namespace NArch;

    // Stack constants.
    static const size_t STACKSIZE = 1 << 20; // 1MB stack. XXX: Investigate committing lazily, and growing on-demand.
    static const uintptr_t USTACKTOP = 0x0000800000000000 - NArch::PAGESIZE; // Top of userspace minus guard page.
    static const uintptr_t INTERPBASE = 0x400000000; // Base address for dynamic linker.
    static const uintptr_t PIEBASE = 0x400000; // Standard base for PIE executables.

    void freeargsenvs(char **arr, size_t arrc) {
        if (!arr) {
            return;
        }
        for (size_t i = 0; i < arrc; i++) {
            delete[] arr[i];
        }
        delete[] arr;
    }

    void freeexecresult(struct execresult *result) {
        if (!result) {
            return;
        }
        if (result->addrspace) {
            delete result->addrspace;
            result->addrspace = NULL;
        }
    }

    // Parse shebang line from file.
    int parseshebang(NFS::VFS::INode *inode, struct shebanginfo *info) {
        char buf[MAXSHEBANGLEN] = {0};

        ssize_t res = inode->read(buf, sizeof(buf) - 1, 0, 0);
        if (res < 2) {
            return -ENOEXEC;
        }

        // Check for #! magic.
        if (buf[0] != '#' || buf[1] != '!') {
            return -ENOEXEC;
        }

        // Find end of line.
        char *end = buf + res;
        for (char *p = buf; p < end; p++) {
            if (*p == '\n' || *p == '\r') {
                *p = '\0';
                end = p;
                break;
            }
        }

        char *p = buf + 2; // Skip #!
        while (p < end && (*p == ' ' || *p == '\t')) {
            p++; // Skip whitespace.
        }

        if (p >= end || *p == '\0') {
            return -ENOEXEC; // Empty interpreter.
        }

        // Extract interpreter path (until whitespace).
        char *interpstart = p;
        while (p < end && *p != ' ' && *p != '\t' && *p != '\0') {
            p++;
        }

        size_t interplen = p - interpstart;
        if (interplen == 0 || interplen >= sizeof(info->interpreter)) {
            return -ENOEXEC;
        }

        NLib::memcpy(info->interpreter, interpstart, interplen);
        info->interpreter[interplen] = '\0';

        // Interpreter must be absolute path.
        if (info->interpreter[0] != '/') {
            return -ENOEXEC;
        }

        // Skip whitespace after interpreter.
        while (p < end && (*p == ' ' || *p == '\t')) {
            p++;
        }

        // Extract optional argument (rest of line, trimmed).
        if (p < end && *p != '\0') {
            char *argstart = p;
            // Find end of argument.
            while (p < end && *p != '\0') {
                p++;
            }

            // Trim trailing whitespace.
            while (p > argstart && (*(p-1) == ' ' || *(p-1) == '\t')) {
                p--;
            }
            size_t arglen = p - argstart;
            if (arglen > 0 && arglen < sizeof(info->arg)) {
                NLib::memcpy(info->arg, argstart, arglen);
                info->arg[arglen] = '\0';
                info->hasarg = true;
            } else {
                info->arg[0] = '\0';
                info->hasarg = false;
            }
        } else {
            info->arg[0] = '\0';
            info->hasarg = false;
        }

        return 0;
    }

    static int resolveexecutable(
        const char *path,
        NFS::VFS::INode *cwd,
        NFS::VFS::INode *root,
        int euid, int egid,
        bool checkperms,
        NFS::VFS::INode **outinode,
        struct NFS::VFS::stat *outstat
    ) {
        ssize_t ret = NFS::VFS::vfs->resolve(path, outinode, cwd, true, root);
        if (ret < 0) {
            return ret;
        }

        if (checkperms) {
            if (!NFS::VFS::vfs->checkaccess(*outinode, NFS::VFS::O_EXEC, euid, egid)) {
                (*outinode)->unref();
                *outinode = NULL;
                return -EACCES;
            }
        }

        if (outstat) {
            *outstat = (*outinode)->getattr();
        }

        return 0;
    }

    static int loadexecutable(
        NFS::VFS::INode *inode,
        NFS::VFS::INode *cwd,
        NFS::VFS::INode *root,
        NArch::VMM::addrspace **outspace,
        void **outentry,
        uintptr_t *outphdr,
        bool *outisinterp
    ) {
        struct NSys::ELF::header elfhdr;
        ssize_t res = inode->read(&elfhdr, sizeof(elfhdr), 0, 0);
        if (res < (ssize_t)sizeof(elfhdr)) {
            return -ENOEXEC;
        }

        if (!NSys::ELF::verifyheader(&elfhdr)) {
            return -ENOEXEC;
        }

        if (elfhdr.type != NSys::ELF::ET_EXECUTABLE && elfhdr.type != NSys::ELF::ET_DYNAMIC) {
            return -ENOEXEC;
        }

        // Create new address space.
        NArch::VMM::addrspace *newspace;
        NArch::VMM::uclonecontext(&NArch::VMM::kspace, &newspace);

        // Determine base address.
        uintptr_t execbase = (elfhdr.type == NSys::ELF::ET_DYNAMIC) ? PIEBASE : 0;

        void *ent = NULL;
        uintptr_t phdraddr = 0;

        if (!NSys::ELF::loadfile(&elfhdr, inode, newspace, &ent, execbase, &phdraddr)) {
            delete newspace;
            return -ENOEXEC;
        }

        // Check for dynamic linker.
        char *interp = NSys::ELF::getinterpreter(&elfhdr, inode);
        void *interpent = NULL;
        bool isinterp = false;

        if (interp != NULL) {
            isinterp = true;

            // Resolve interpreter.
            NFS::VFS::INode *interpnode;
            ssize_t r = NFS::VFS::vfs->resolve(interp, &interpnode, NULL, true, root);
            delete[] interp;

            if (r < 0) {
                delete newspace;
                return r;
            }

            // Read interpreter ELF header.
            struct NSys::ELF::header interpelfhdr;
            ssize_t rd = interpnode->read(&interpelfhdr, sizeof(interpelfhdr), 0, 0);
            if (rd < (ssize_t)sizeof(interpelfhdr)) {
                interpnode->unref();
                delete newspace;
                return -ENOEXEC;
            }

            if (!NSys::ELF::verifyheader(&interpelfhdr)) {
                interpnode->unref();
                delete newspace;
                return -ENOEXEC;
            }

            // Load interpreter.
            if (!NSys::ELF::loadfile(&interpelfhdr, interpnode, newspace, &interpent, INTERPBASE, NULL)) {
                interpnode->unref();
                delete newspace;
                return -ENOEXEC;
            }

            interpnode->unref();

            if (!interpent || (uintptr_t)interpent >= 0x0000800000000000) {
                delete newspace;
                return -ENOEXEC;
            }
        }

        if (!ent || (uintptr_t)ent >= 0x0000800000000000) {
            delete newspace;
            return -ENOEXEC;
        }

        *outspace = newspace;
        *outentry = isinterp ? interpent : ent;
        if (outphdr) {
            *outphdr = phdraddr;
        }
        if (outisinterp) {
            *outisinterp = isinterp;
        }

        return 0;
    }

    static int setupexecstack(
        NArch::VMM::addrspace *space,
        NFS::VFS::INode *inode,
        const struct execparams *params,
        void *progentry,
        uintptr_t interpbase,
        uintptr_t phdraddr,
        void **outrsp,
        uintptr_t *outstackbase
    ) {
        // Allocate stack memory.
        uintptr_t ustack = (uintptr_t)NMem::VMalloc::alloc(STACKSIZE);
        if (!ustack) {
            return -ENOMEM;
        }

        uintptr_t ustackbottom = USTACKTOP - STACKSIZE;

        // Read ELF header for stack setup.
        struct NSys::ELF::header elfhdr;
        ssize_t res = inode->read(&elfhdr, sizeof(elfhdr), 0, 0);
        if (res < (ssize_t)sizeof(elfhdr)) {
            NMem::VMalloc::free((void *)ustack, STACKSIZE);
            return -ENOEXEC;
        }

        // Build exec info for stack preparation.
        struct NSys::ELF::execinfo einfo;
        NLib::memset(&einfo, 0, sizeof(einfo));
        einfo.argv = params->argv;
        einfo.envp = params->envp;
        einfo.execpath = params->path;
        einfo.entry = (uintptr_t)progentry;
        einfo.lnbase = interpbase;
        einfo.phdraddr = phdraddr;
        einfo.uid = params->uid;
        einfo.gid = params->gid;
        einfo.euid = params->euid;
        einfo.egid = params->egid;
        einfo.secure = false; // Will be updated by caller if SUID/SGID.

        // Generate random bytes for AT_RANDOM.
        NSys::Random::EntropyPool *pool = CPU::get()->entropypool;
        if (pool) {
            uint8_t randbuf[16];
            pool->getrandom(randbuf, sizeof(randbuf), false, false);
            NLib::memcpy(einfo.random, randbuf, sizeof(randbuf));
        }

        // Prepare stack.
        void *rsp = NSys::ELF::preparestack(ustack + STACKSIZE, &elfhdr, USTACKTOP, &einfo);
        if (!rsp) {
            NMem::VMalloc::free((void *)ustack, STACKSIZE);
            return -ENOMEM;
        }

        // Reserve guard page at top.
        space->vmaspace->reserve(USTACKTOP, 0x0000800000000000, 0);

        // Map stack into address space.
        NMem::VMalloc::mapintospace(space, ustack, ustackbottom, STACKSIZE,
            NMem::Virt::VIRT_NX | NMem::Virt::VIRT_RW | NMem::Virt::VIRT_USER);

        *outrsp = rsp;
        if (outstackbase) {
            *outstackbase = ustackbottom;
        }

        return 0;
    }

    // Forward declaration for recursion.
    static int execinternal(const struct execparams *params, struct execresult *result);

    // Handle shebang interpreter execution.
    static int execinterpreter(
        const struct shebanginfo *shebang,
        const struct execparams *origparams,
        struct execresult *result
    ) {
        // Check recursion limit.
        if (origparams->interpdepth >= MAXINTERPDEPTH) {
            return -ELOOP;
        }

        // Build new argv array.
        size_t newargc = 1 + (shebang->hasarg ? 1 : 0) + 1 + (origparams->argc > 0 ? origparams->argc - 1 : 0);

        char **newargv = new char *[newargc + 1];
        if (!newargv) {
            return -ENOMEM;
        }

        size_t idx = 0;

        // argv[0] = interpreter path.
        size_t interplen = NLib::strlen(shebang->interpreter);
        newargv[idx] = new char[interplen + 1];
        if (!newargv[idx]) {
            delete[] newargv;
            return -ENOMEM;
        }
        NLib::memcpy(newargv[idx], (void *)shebang->interpreter, interplen + 1);
        idx++;

        // argv[1] = shebang argument (optional).
        if (shebang->hasarg) {
            size_t arglen = NLib::strlen(shebang->arg);
            newargv[idx] = new char[arglen + 1];
            if (!newargv[idx]) {
                freeargsenvs(newargv, idx);
                return -ENOMEM;
            }
            NLib::memcpy(newargv[idx], (void *)shebang->arg, arglen + 1);
            idx++;
        }

        // Script path.
        size_t pathlen = NLib::strlen(origparams->path);
        newargv[idx] = new char[pathlen + 1];
        if (!newargv[idx]) {
            freeargsenvs(newargv, idx);
            return -ENOMEM;
        }
        NLib::memcpy(newargv[idx], (void *)origparams->path, pathlen + 1);
        idx++;

        // Original argv[1...].
        for (size_t i = 1; i < origparams->argc; i++) {
            size_t len = NLib::strlen(origparams->argv[i]);
            newargv[idx] = new char[len + 1];
            if (!newargv[idx]) {
                freeargsenvs(newargv, idx);
                return -ENOMEM;
            }
            NLib::memcpy(newargv[idx], origparams->argv[i], len + 1);
            idx++;
        }
        newargv[idx] = NULL;

        // Build new params.
        struct execparams newparams = *origparams;
        newparams.path = shebang->interpreter;
        newparams.argv = newargv;
        newparams.argc = newargc;
        newparams.interpdepth = origparams->interpdepth + 1;

        // Recurse.
        int ret = execinternal(&newparams, result);

        freeargsenvs(newargv, newargc);

        return ret;
    }

    // Internal exec implementation (handles recursion for shebang).
    static int execinternal(const struct execparams *params, struct execresult *result) {
        NLib::memset(result, 0, sizeof(*result));

        // Resolve executable.
        NFS::VFS::INode *inode = NULL;
        struct NFS::VFS::stat attr;
        int ret = resolveexecutable(params->path, params->cwd, params->root,
            params->euid, params->egid, params->checkperms, &inode, &attr);
        if (ret < 0) {
            return ret;
        }

        // Check for shebang script.
        struct shebanginfo shebang;
        ret = parseshebang(inode, &shebang);
        if (ret == 0) {
            // Keep stat from original script for SUID/SGID.
            inode->unref();

            ret = execinterpreter(&shebang, params, result);
            if (ret < 0) {
                return ret;
            }

            // Apply SUID/SGID from the script (not interpreter).
            if (NFS::VFS::S_ISSUID(attr.st_mode)) {
                result->neweuid = attr.st_uid;
                result->suid = true;
            }
            if (NFS::VFS::S_ISSGID(attr.st_mode)) {
                result->newegid = attr.st_gid;
                result->sgid = true;
            }

            return 0;
        }

        NArch::VMM::addrspace *newspace = NULL;
        void *entry = NULL;
        uintptr_t phdraddr = 0;
        bool isinterp = false;

        ret = loadexecutable(inode, params->cwd, params->root,
            &newspace, &entry, &phdraddr, &isinterp);
        if (ret < 0) {
            inode->unref();
            return ret;
        }

        // Set up stack.
        void *rsp = NULL;
        uintptr_t stackbase = 0;

        // Re-read to get program entry.
        struct NSys::ELF::header elfhdr;
        inode->read(&elfhdr, sizeof(elfhdr), 0, 0);
        void *progentry = (void *)elfhdr.entryoff;
        if (elfhdr.type == NSys::ELF::ET_DYNAMIC) {
            progentry = (void *)((uintptr_t)progentry + PIEBASE);
        }

        ret = setupexecstack(newspace, inode, params, progentry,
            isinterp ? INTERPBASE : 0, phdraddr, &rsp, &stackbase);

        inode->unref();

        if (ret < 0) {
            delete newspace;
            return ret;
        }

        // Fill result.
        result->addrspace = newspace;
        result->entry = entry;
        result->stackptr = rsp;
        result->stackbase = stackbase;
        result->stacksize = STACKSIZE;

        // Check SUID/SGID.
        if (NFS::VFS::S_ISSUID(attr.st_mode)) {
            result->neweuid = attr.st_uid;
            result->suid = true;
        } else {
            result->neweuid = params->euid;
        }

        if (NFS::VFS::S_ISSGID(attr.st_mode)) {
            result->newegid = attr.st_gid;
            result->sgid = true;
        } else {
            result->newegid = params->egid;
        }

        return 0;
    }

    int exec(const struct execparams *params, struct execresult *result) {
        return execinternal(params, result);
    }

    // Syscall wrapper for execve.
    extern "C" uint64_t sys_execve(const char *path, char *const argv[], char *const envp[]) {
        SYSCALL_LOG("sys_execve(%s, %p, %p).\n", path, argv, envp);

        // Copy path from userspace.
        ssize_t pathlen = NMem::UserCopy::strnlen(path, 4096);
        if (pathlen <= 0) {
            SYSCALL_RET(-EFAULT);
        }

        char *pathbuf = new char[pathlen + 1];
        if (!pathbuf) {
            SYSCALL_RET(-ENOMEM);
        }

        ssize_t ret = NMem::UserCopy::copyfrom(pathbuf, path, pathlen + 1);
        if (ret < 0) {
            delete[] pathbuf;
            SYSCALL_RET(-EFAULT);
        }
        pathbuf[pathlen] = 0;

        // Validate and count argv.
        if (!NMem::UserCopy::valid(argv, sizeof(char *))) {
            delete[] pathbuf;
            SYSCALL_RET(-EFAULT);
        }

        size_t argc = 0;
        while (true) {
            if (!NMem::UserCopy::valid(&argv[argc], sizeof(char *))) {
                delete[] pathbuf;
                SYSCALL_RET(-EFAULT);
            }
            if (!argv[argc]) {
                break;
            }
            argc++;
            if (argc > ARGMAX) {
                delete[] pathbuf;
                SYSCALL_RET(-E2BIG);
            }
        }

        // Copy argv from userspace.
        char **aargv = new char *[argc + 1];
        if (!aargv) {
            delete[] pathbuf;
            SYSCALL_RET(-ENOMEM);
        }
        for (size_t i = 0; i < argc; i++) {
            ssize_t arglen = NMem::UserCopy::strnlen(argv[i], 4096);
            if (arglen <= 0) {
                freeargsenvs(aargv, i);
                delete[] pathbuf;
                SYSCALL_RET(-EFAULT);
            }

            aargv[i] = new char[arglen + 1];
            if (!aargv[i]) {
                freeargsenvs(aargv, i);
                delete[] pathbuf;
                SYSCALL_RET(-ENOMEM);
            }

            ssize_t r = NMem::UserCopy::copyfrom(aargv[i], argv[i], arglen + 1);
            if (r < 0) {
                freeargsenvs(aargv, i + 1);
                delete[] pathbuf;
                SYSCALL_RET(-EFAULT);
            }
            aargv[i][arglen] = 0;
        }
        aargv[argc] = NULL;

        // Validate and count envp.
        if (!NMem::UserCopy::valid(envp, sizeof(char *))) {
            freeargsenvs(aargv, argc);
            delete[] pathbuf;
            SYSCALL_RET(-EFAULT);
        }

        size_t envc = 0;
        while (true) {
            if (!NMem::UserCopy::valid(&envp[envc], sizeof(char *))) {
                freeargsenvs(aargv, argc);
                delete[] pathbuf;
                SYSCALL_RET(-EFAULT);
            }
            if (!envp[envc]) {
                break;
            }
            envc++;
            if (envc > ARGMAX) {
                freeargsenvs(aargv, argc);
                delete[] pathbuf;
                SYSCALL_RET(-E2BIG);
            }
        }

        // Copy envp from userspace.
        char **aenvp = new char *[envc + 1];
        if (!aenvp) {
            freeargsenvs(aargv, argc);
            delete[] pathbuf;
            SYSCALL_RET(-ENOMEM);
        }
        for (size_t i = 0; i < envc; i++) {
            ssize_t envlen = NMem::UserCopy::strnlen(envp[i], 4096);
            if (envlen <= 0) {
                freeargsenvs(aenvp, i);
                freeargsenvs(aargv, argc);
                delete[] pathbuf;
                SYSCALL_RET(-EFAULT);
            }
            aenvp[i] = new char[envlen + 1];
            if (!aenvp[i]) {
                freeargsenvs(aenvp, i);
                freeargsenvs(aargv, argc);
                delete[] pathbuf;
                SYSCALL_RET(-ENOMEM);
            }
            ssize_t r = NMem::UserCopy::copyfrom(aenvp[i], envp[i], envlen + 1);
            if (r < 0) {
                freeargsenvs(aenvp, i + 1);
                freeargsenvs(aargv, argc);
                delete[] pathbuf;
                SYSCALL_RET(-EFAULT);
            }
            aenvp[i][envlen] = 0;
        }
        aenvp[envc] = NULL;

        // Get process context.
        Process *current = NArch::CPU::get()->currthread->process;
        current->lock.acquire();
        NFS::VFS::INode *cwd = current->cwd;
        if (cwd) {
            cwd->ref();
        }
        NFS::VFS::INode *procroot = current->root;
        if (procroot) {
            procroot->ref();
        }
        int uid = current->uid;
        int gid = current->gid;
        int euid = current->euid;
        int egid = current->egid;
        current->lock.release();

        // Build exec params.
        struct execparams params;
        NLib::memset(&params, 0, sizeof(params));
        params.path = pathbuf;
        params.argv = aargv;
        params.envp = aenvp;
        params.argc = argc;
        params.envc = envc;
        params.cwd = cwd;
        params.root = procroot;
        params.uid = uid;
        params.gid = gid;
        params.euid = euid;
        params.egid = egid;
        params.checkperms = true;
        params.issyscall = true;
        params.interpdepth = 0;

        // Execute.
        struct execresult result;
        ret = exec(&params, &result);

        // Clean up copied args/envs after exec (they've been copied to stack).
        freeargsenvs(aargv, argc);
        freeargsenvs(aenvp, envc);
        delete[] pathbuf;

        if (cwd) {
            cwd->unref();
        }

        if (ret < 0) {
            if (procroot) {
                procroot->unref();
            }
            SYSCALL_RET(ret);
        }

        // Kill other threads and await their death.
        termothers(current);

        current->lock.acquire();

        // Mark that this process has called execve.
        current->hasexeced = true;

        // Apply SUID/SGID changes.
        if (result.suid) {
            current->euid = result.neweuid;
        }
        if (result.sgid) {
            current->egid = result.newegid;
        }

        // "The effective UID of the process is copied to the saved set-user-ID"
        current->suid = current->euid;
        current->sgid = current->egid;

        // Replace address space.
        current->addrspace->lock.acquire();
        current->addrspace->ref--;
        size_t ref = current->addrspace->ref;
        current->addrspace->lock.release();
        if (ref == 0) {
            delete current->addrspace;
        }

        result.addrspace->ref++;
        current->addrspace = result.addrspace;

        current->fdtable->doexec(); // Close FDs with O_CLOEXEC.

        // Reset signal handlers to SIG_DFL on exec (except SIG_IGN remains SIG_IGN).
        for (size_t i = 0; i < NSIG; i++) {
            if (current->signalstate.actions[i].handler != SIG_IGN) {
                current->signalstate.actions[i].handler = SIG_DFL;
                current->signalstate.actions[i].mask = 0;
                current->signalstate.actions[i].flags = 0;
                current->signalstate.actions[i].restorer = NULL;
            }
        }
        // Pending signals are cleared on exec.
        current->signalstate.pending = 0;

        struct NArch::CPU::context *sysctx = NArch::CPU::get()->currthread->sysctx;
#ifdef __x86_64__
        NLib::memset(&NArch::CPU::get()->currthread->xctx, 0, sizeof(NArch::CPU::get()->currthread->xctx));

        sysctx->rip = (uint64_t)result.entry;
        sysctx->rsp = (uint64_t)result.stackptr;
        sysctx->rflags = 0x202; // Enable interrupts.

        NLib::memset(NArch::CPU::get()->currthread->fctx.fpustorage, 0, CPU::get()->fpusize);
        NArch::CPU::get()->currthread->fctx.mathused = false;

        if (CPU::get()->hasxsave) {
            uint64_t cr0 = CPU::rdcr0();
            asm volatile("clts");
            asm volatile("xsave (%0)" : : "r"(NArch::CPU::get()->currthread->fctx.fpustorage), "a"(0xffffffff), "d"(0xffffffff));
            CPU::wrcr0(cr0);
        }

        NArch::VMM::swapcontext(result.addrspace);
        current->lock.release();

        if (procroot) {
            procroot->unref();
        }

        SYSCALL_RET(sysctx->rax);
#else
        // Other architectures not implemented yet.
        current->lock.release();
        if (procroot) {
            procroot->unref();
        }
        freeexecresult(&result);
        SYSCALL_RET(-ENOSYS);
#endif
    }
}