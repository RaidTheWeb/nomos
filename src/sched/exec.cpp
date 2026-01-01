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
#include <sched/event.hpp>
#include <sched/sched.hpp>
#include <sys/clock.hpp>
#include <sys/elf.hpp>
#include <sys/syscall.hpp>
#include <sys/timer.hpp>

namespace NSched {
    using namespace NArch;

    static void freeargsenvs(char **arr, size_t arrc) {
        for (size_t i = 0; i < arrc; i++) {
            delete[] arr[i];
        }
        delete[] arr;
    }

    extern "C" uint64_t sys_execve(const char *path, char *const argv[], char *const envp[]) {
        SYSCALL_LOG("sys_execve(%s, %p, %p).\n", path, argv, envp);

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
        pathbuf[pathlen] = 0; // Null terminate.


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
            if (argc > 4096) { // XXX: ARGMAX limit.
                delete[] pathbuf;
                SYSCALL_RET(-E2BIG);
            }
        }

        char **aargv = new char *[argc + 1];
        if (!aargv) {
            delete[] pathbuf;
            SYSCALL_RET(-ENOMEM);
        }
        for (size_t i = 0; i < argc; i++) {
            ssize_t arglen = NMem::UserCopy::strnlen(argv[i], 4096);
            if (arglen <= 0) {
                delete[] pathbuf;
                delete[] aargv;
                SYSCALL_RET(-EFAULT);
            }

            aargv[i] = new char[arglen + 1];
            if (!aargv[i]) {
                for (size_t j = 0; j < i; j++) {
                    delete[] aargv[j];
                }
                delete[] pathbuf;
                delete[] aargv;
                SYSCALL_RET(-ENOMEM);
            }

            ssize_t r = NMem::UserCopy::copyfrom(aargv[i], argv[i], arglen + 1);
            if (r < 0) {
                for (size_t j = 0; j <= i; j++) {
                    delete[] aargv[j];
                }
                delete[] pathbuf;
                delete[] aargv;
                SYSCALL_RET(-EFAULT);
            }
            aargv[i][arglen] = 0; // Null terminate.
        }
        aargv[argc] = NULL; // Null terminate.

        if (!NMem::UserCopy::valid(envp, sizeof(char *))) {
            freeargsenvs(aargv, argc);
            delete[] pathbuf;
            SYSCALL_RET(-EFAULT);
        }

        // Copy envp array:
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
            if (envc > 4096) { // XXX: ARGMAX limit.
                freeargsenvs(aargv, argc);
                delete[] pathbuf;
                SYSCALL_RET(-E2BIG);
            }
        }

        char **aenvp = new char *[envc + 1];
        if (!aenvp) {
            freeargsenvs(aargv, argc);
            delete[] pathbuf;
            SYSCALL_RET(-ENOMEM);
        }
        for (size_t i = 0; i < envc; i++) {
            ssize_t envlen = NMem::UserCopy::strnlen(envp[i], 4096);
            if (envlen <= 0) {
                freeargsenvs(aargv, argc);
                delete[] pathbuf;
                delete[] aenvp;
                SYSCALL_RET(-EFAULT);
            }
            aenvp[i] = new char[envlen + 1];
            if (!aenvp[i]) {
                for (size_t j = 0; j < i; j++) {
                    delete[] aenvp[j];
                }
                freeargsenvs(aargv, argc);
                delete[] pathbuf;
                delete[] aenvp;
                SYSCALL_RET(-ENOMEM);
            }
            ssize_t r = NMem::UserCopy::copyfrom(aenvp[i], envp[i], envlen + 1);
            if (r < 0) {
                for (size_t j = 0; j <= i; j++) {
                    delete[] aenvp[j];
                }
                freeargsenvs(aargv, argc);
                delete[] pathbuf;
                delete[] aenvp;
                SYSCALL_RET(-EFAULT);
            }
            aenvp[i][envlen] = 0; // Null terminate.
        }
        aenvp[envc] = NULL; // Null terminate.


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
        int euid = current->euid;
        int egid = current->egid;
        current->lock.release();

        NFS::VFS::INode *inode;
        ret = NFS::VFS::vfs->resolve(pathbuf, &inode, cwd, true, procroot);
        if (cwd) {
            cwd->unref();
        }
        if (ret < 0) {
            if (procroot) {
                procroot->unref();
            }
            freeargsenvs(aargv, argc);
            freeargsenvs(aenvp, envc);
            delete[] pathbuf;
            SYSCALL_RET(ret);
        }

        // Check permission against EUID/EGID.
        if (!NFS::VFS::vfs->checkaccess(inode, NFS::VFS::O_EXEC, euid, egid)) {
            inode->unref();
            if (procroot) {
                procroot->unref();
            }
            freeargsenvs(aargv, argc);
            freeargsenvs(aenvp, envc);
            delete[] pathbuf;
            SYSCALL_RET(-EACCES);
        }

        // Check if interpreter script.
        char shebang[128] = {0};

        ssize_t res = inode->read(shebang, sizeof(shebang) - 1, 0, 0);
        if (res < 2) { // Failed to read shebang.
            inode->unref();
            if (procroot) {
                procroot->unref();
            }
            freeargsenvs(aargv, argc);
            freeargsenvs(aenvp, envc);
            delete[] pathbuf;
            SYSCALL_RET(-ENOEXEC);
        }

        if (shebang[0] == '#' && shebang[1] == '!') {
            // TODO: Handle interpreter scripts.
        }

        NUtil::printf("Loading ELF executable: %s\n", pathbuf);

        struct NSys::ELF::header elfhdr;
        res = inode->read(&elfhdr, sizeof(elfhdr), 0, 0);
        if (res < (ssize_t)sizeof(elfhdr)) {
            inode->unref();
            if (procroot) {
                procroot->unref();
            }
            freeargsenvs(aargv, argc);
            freeargsenvs(aenvp, envc);
            delete[] pathbuf;
            SYSCALL_RET(-ENOEXEC);
        }

        if (elfhdr.type != NSys::ELF::ET_EXECUTABLE && elfhdr.type != NSys::ELF::ET_DYNAMIC) {
            inode->unref();
            freeargsenvs(aargv, argc);
            freeargsenvs(aenvp, envc);
            delete[] pathbuf;
            SYSCALL_RET(-ENOEXEC);
        }

        if (!NSys::ELF::verifyheader(&elfhdr)) {
            inode->unref();
            if (procroot) {
                procroot->unref();
            }
            freeargsenvs(aargv, argc);
            freeargsenvs(aenvp, envc);
            delete[] pathbuf;
            SYSCALL_RET(-ENOEXEC);
        }

        struct VMM::addrspace *newspace;
        NArch::VMM::uclonecontext(&NArch::VMM::kspace, &newspace); // Start with a clone of the kernel address space.

        bool isinterp = false;

        void *ent = NULL;
        void *interpent = NULL;
        uintptr_t execbase = 0;
        uintptr_t interpbase = 0;
        uintptr_t phdraddr = 0;

        if (elfhdr.type == NSys::ELF::ET_DYNAMIC) {
            execbase = 0x400000; // Standard base for PIE.
        } else {
            execbase = 0; // Non-PIE executables load at fixed address.
        }

        NUtil::printf("Loading ELF file at base %p.\n", (void *)execbase);

        if (!NSys::ELF::loadfile(&elfhdr, inode, newspace, &ent, execbase, &phdraddr)) {
            inode->unref();
            if (procroot) {
                procroot->unref();
            }
            freeargsenvs(aargv, argc);
            freeargsenvs(aenvp, envc);
            delete[] pathbuf;
            delete newspace;
            SYSCALL_RET(-ENOEXEC);
        }

        NUtil::printf("Executable loaded at %p, entry point %p.\n", (void *)execbase, ent);

        char *interp = NSys::ELF::getinterpreter(&elfhdr, inode);

        if (interp != NULL) { // Dynamically linked executable.
            isinterp = true;

            // Load interpreter ELF.
            NFS::VFS::INode *interpnode;
            ssize_t r = NFS::VFS::vfs->resolve(interp, &interpnode, NULL, true, procroot);
            delete[] interp;
            if (r < 0) {
                inode->unref();
                if (procroot) {
                    procroot->unref();
                }
                freeargsenvs(aargv, argc);
                freeargsenvs(aenvp, envc);
                delete[] pathbuf;
                delete newspace;
                SYSCALL_RET(r);
            }

            struct NSys::ELF::header interpelfhdr;
            ssize_t rd = interpnode->read(&interpelfhdr, sizeof(interpelfhdr), 0, 0);
            if (rd < (ssize_t)sizeof(interpelfhdr)) {
                inode->unref();
                interpnode->unref();
                if (procroot) {
                    procroot->unref();
                }
                freeargsenvs(aargv, argc);
                freeargsenvs(aenvp, envc);
                delete[] pathbuf;
                delete newspace;
                SYSCALL_RET(-ENOEXEC);
            }

            if (!NSys::ELF::verifyheader(&interpelfhdr)) {
                inode->unref();
                interpnode->unref();
                if (procroot) {
                    procroot->unref();
                }
                freeargsenvs(aargv, argc);
                freeargsenvs(aenvp, envc);
                delete[] pathbuf;
                delete newspace;
                SYSCALL_RET(-ENOEXEC);
            }

            NUtil::printf("Loading ELF interpreter: %s\n", interp);

            // Load interpreter at different base address
            interpbase = 0x00000beef0000000;  // Place interpreter at a different address range
            if (!NSys::ELF::loadfile(&interpelfhdr, interpnode, newspace, &interpent, interpbase, NULL)) {
                inode->unref();
                interpnode->unref();
                freeargsenvs(aargv, argc);
                freeargsenvs(aenvp, envc);
                delete[] pathbuf;
                delete newspace;
                SYSCALL_RET(-ENOEXEC);
            }

            interpnode->unref();

            if (!interpent || (uintptr_t)interpent >= 0x0000800000000000) {
                inode->unref();
                if (procroot) {
                    procroot->unref();
                }
                freeargsenvs(aargv, argc);
                freeargsenvs(aenvp, envc);
                delete[] pathbuf;
                delete newspace;
                SYSCALL_RET(-ENOEXEC);
            }
        }

        if (!ent || (uintptr_t)ent >= 0x0000800000000000) {
            inode->unref();
            if (procroot) {
                procroot->unref();
            }
            freeargsenvs(aargv, argc);
            freeargsenvs(aenvp, envc);
            delete[] pathbuf;
            delete newspace;
            SYSCALL_RET(-ENOEXEC);
        }


        struct NFS::VFS::stat attr = inode->getattr();

        inode->unref();

        uintptr_t ustackphy = (uintptr_t)PMM::alloc(1 << 20); // This is the physical memory behind the stack.
        if (!ustackphy) {
            if (procroot) {
                procroot->unref();
            }
            freeargsenvs(aargv, argc);
            freeargsenvs(aenvp, envc);
            delete[] pathbuf;
            delete newspace;
            SYSCALL_RET(-ENOMEM);
        }

        uintptr_t ustacktop = 0x0000800000000000 - NArch::PAGESIZE; // Top of user space, minus a page for safety.
        uintptr_t ustackbottom = ustacktop - (1 << 20); // Virtual address of bottom of user stack (where ustackphy starts).

        struct NSys::ELF::execinfo einfo;
        NLib::memset(&einfo, 0, sizeof(einfo));
        einfo.argv = aargv;
        einfo.envp = aenvp;
        einfo.execpath = pathbuf;
        einfo.entry = (uintptr_t)ent; // Executable's entry point. NOT interpreter entry point, EVER.
        einfo.lnbase = interpbase;
        einfo.phdraddr = phdraddr;

        NSys::Random::EntropyPool *pool = CPU::get()->entropypool;
        uint8_t randbuf[16];
        pool->getrandom(randbuf, sizeof(randbuf), false, false); // Non-blocking, urandom source.
        NLib::memcpy(einfo.random, randbuf, sizeof(randbuf));

        current->lock.acquire();

        einfo.uid = current->uid;
        einfo.gid = current->gid;

        if (NFS::VFS::S_ISSUID(attr.st_mode)) {
            current->euid = attr.st_uid; // Run as owner of file.
            einfo.secure = true; // SUID programs are "secure" executables.
        }

        if (NFS::VFS::S_ISSGID(attr.st_mode)) {
            current->egid = attr.st_gid; // Run as owner of file.
            einfo.secure = true; // SGID programs are "secure" executables.
        }

        einfo.euid = current->euid;
        einfo.egid = current->egid;

        current->lock.release();

        void *rsp = NSys::ELF::preparestack((uintptr_t)NArch::hhdmoff((void *)(ustackphy + (1 << 20))), &elfhdr, ustacktop, &einfo);
        freeargsenvs(aargv, argc);
        freeargsenvs(aenvp, envc);
        delete[] pathbuf; // Clean up path after preparestack copies it.

        if (!rsp) {
            if (procroot) {
                procroot->unref();
            }
            PMM::free((void *)ustackphy, 1 << 20);
            delete newspace;
            SYSCALL_RET(-ENOMEM);
        }

        // Reserve user stack region.
        newspace->vmaspace->reserve(ustackbottom, ustacktop, NMem::Virt::VIRT_NX | NMem::Virt::VIRT_RW | NMem::Virt::VIRT_USER);
        newspace->vmaspace->reserve(ustacktop, 0x0000800000000000, 0); // Guard page.

        // Map user stack.
        NArch::VMM::maprange(newspace, ustackbottom, (uintptr_t)ustackphy, NArch::VMM::NOEXEC | NArch::VMM::WRITEABLE | NArch::VMM::USER | NArch::VMM::PRESENT, 1<< 20);

        // Kill other threads and await their death.
        termothers(current);

        current->lock.acquire();

        // Mark that this process has called execve.
        current->hasexeced = true;

        // "The effective UID of the process is copied to the saved set-user-ID"
        current->suid = current->euid;
        current->sgid = current->egid;

        // RUID and RGID remain unchanged.

        current->addrspace->lock.acquire();
        current->addrspace->ref--;
        size_t ref = current->addrspace->ref;
        current->addrspace->lock.release();
        if (ref == 0) {
            delete current->addrspace;
        }

        newspace->ref++;
        current->addrspace = newspace;

        current->fdtable->doexec(); // Close FDs with O_CLOEXEC.

        // Reset signal handlers to SIG_DFL on exec (except those set to SIG_IGN remain SIG_IGN).
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
        // Signal mask is preserved across exec.

        struct NArch::CPU::context *sysctx = NArch::CPU::get()->currthread->sysctx;
#ifdef __x86_64__
        NLib::memset(&NArch::CPU::get()->currthread->xctx, 0, sizeof(NArch::CPU::get()->currthread->xctx));

        sysctx->rip = isinterp ? (uint64_t)interpent : (uint64_t)ent; // Entry point.
        sysctx->rsp = (uint64_t)rsp;
        sysctx->rflags = 0x202; // Enable interrupts.

        NUtil::printf("Execve: Entry point at 0x%lx, stack at 0x%lx\n", sysctx->rip, sysctx->rsp);

        NLib::memset(NArch::CPU::get()->currthread->fctx.fpustorage, 0, CPU::get()->fpusize);
        NArch::CPU::get()->currthread->fctx.mathused = false; // Mark as unused.

        if (CPU::get()->hasxsave) {
            uint64_t cr0 = CPU::rdcr0();
            asm volatile("clts");
            // Initialise region.
            asm volatile("xsave (%0)" : : "r"(NArch::CPU::get()->currthread->fctx.fpustorage), "a"(0xffffffff), "d"(0xffffffff));
            CPU::wrcr0(cr0); // Restore original CR0 (restores TS).
        }

        NArch::VMM::swapcontext(newspace);
        current->lock.release();

        // Clean up procroot reference now that execve succeeded.
        if (procroot) {
            procroot->unref();
        }

        SYSCALL_RET(sysctx->rax); // Success. This should usually be the system call number of sys_execve.
#else
        // Other architectures not implemented yet.
        current->lock.release();
        if (procroot) {
            procroot->unref();
        }
        delete newspace;
        SYSCALL_RET(-ENOSYS);
#endif
    }
}