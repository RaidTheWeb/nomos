#ifdef __x86_64__
#include <arch/limine/arch.hpp>
#include <arch/limine/console.hpp>
#include <arch/limine/module.hpp>
#include <arch/limine/requests.hpp>
#include <arch/x86_64/arch.hpp>
#include <arch/x86_64/cpu.hpp>
#include <arch/x86_64/serial.hpp>
#include <backends/fb.h>
#include <flanterm.h>
#include <limine.h>
#endif

#include <dev/dev.hpp>
#include <dev/input/input.hpp>
#include <dev/pci.hpp>

#include <cxxruntime.hpp>
#include <fs/devfs.hpp>
#include <fs/pipefs.hpp>
#include <fs/posixtar.hpp>
#include <lib/align.hpp>
#include <lib/assert.hpp>
#include <lib/bitmap.hpp>
#include <lib/cmdline.hpp>
#include <lib/lz4.hpp>
#include <mm/pagecache.hpp>
#include <mm/slab.hpp>
#include <mm/vmalloc.hpp>
#include <util/kprint.hpp>
#include <sched/exec.hpp>
#include <sched/sched.hpp>
#include <sched/workqueue.hpp>
#include <stddef.h>
#include <sys/elf.hpp>

// These operators must be defined here, or else they won't apply everywhere.

void *operator new(size_t size) {
    return NMem::allocator.alloc(size);
}

void operator delete(void *ptr) {
    NMem::allocator.free(ptr);
}

void *operator new(size_t size, size_t align) {
    (void)align;
    return NMem::allocator.alloc(size);
}

void *operator new[](size_t size) {
    return operator new(size);
}

void operator delete[](void *ptr) {
    operator delete(ptr);
}

void operator delete(void *ptr, size_t align) {
    (void)align;
    NMem::allocator.free(ptr);
}

void operator delete[](void *ptr, size_t size) {
    (void)size;
    operator delete(ptr);
}

// Called within the architecture-specific initialisation thread. Stage 1 (early).
void kpostarch(void) {
    NFS::VFS::vfs = new NFS::VFS::VFS();

    // Initialise filesystem database from linker-provided registry.
    for (NFS::VFS::fsregentry *entry = (NFS::VFS::fsregentry *)NFS::VFS::__filesystems_start; (uintptr_t)entry < (uintptr_t)NFS::VFS::__filesystems_end; entry++) {
        if (entry->magic == NFS::VFS::FS_MAGIC) {
            NUtil::printf("[nomos]: Discovered filesystem: %s.\n", entry->info->name);
            NFS::VFS::vfs->filesystems.insert(entry->info->name, entry->factory);
        }
    }

    const char *initramfs = NArch::cmdline.get("initramfs");
    if (initramfs) { // Exists, load it.
        NArch::Module::Module *mod = NArch::Module::loadmodule(initramfs); // Try to load.
        assertarg(mod->valid(), "Failed to load `initramfs` specified: `%s`.\n", initramfs);

        if (NArch::cmdline.get("root") && !NLib::strcmp(NArch::cmdline.get("root"), "initramfs")) { // If the boot command line specifies that the initramfs should be used as the filesystem root, we should load it.
            NFS::POSIXTAR::POSIXTARFileSystem *fs = new NFS::POSIXTAR::POSIXTARFileSystem(NFS::VFS::vfs, mod); // Use heap for allocation, keeps it alive past this scope.
            NFS::VFS::vfs->mount(NULL, "/", fs, 0, NULL);
            fs->reclaim(); // Reclaim initramfs memory now that mount is complete.
        }
    }

    NFS::PipeFS::pipefs = new NFS::PipeFS::PipeFileSystem(NFS::VFS::vfs); // Create global PipeFS instance.

    NDev::setup(); // Initialise device registry.

    NMem::initpagecache(); // Initialise global page cache.
    NMem::startpagecachethread(); // Start writeback thread now that scheduler is running.

    NSched::WorkerPool::init(); // Initialise worker pools on all CPUs.
    NSched::WorkQueue::init(); // Initialise system workqueues.

    for (NDev::regentry *entry = (NDev::regentry *)NDev::__drivers_start; (uintptr_t)entry < (uintptr_t)NDev::__drivers_end; entry++) {
        if (entry->magic == NDev::MAGIC && entry->info->stage == NDev::reginfo::STAGE1) {
            NUtil::printf("[nomos]: Discovered stage 1 driver: %s of type %s.\n", entry->info->name, entry->info->type == NDev::reginfo::GENERIC ? "GENERIC" : "MATCHED");

            entry->instance = entry->create();
        }
    }

    NSys::Random::init(); // Initialise system random number generator.

    for (NDev::regentry *entry = (NDev::regentry *)NDev::__drivers_start; (uintptr_t)entry < (uintptr_t)NDev::__drivers_end; entry++) {
        if (entry->magic == NDev::MAGIC && entry->info->stage == NDev::reginfo::STAGE2) {
            NUtil::printf("[nomos]: Discovered stage 2 driver: %s of type %s.\n", entry->info->name, entry->info->type == NDev::reginfo::GENERIC ? "GENERIC" : "MATCHED");
            entry->instance = entry->create();
        }
    }

    NDev::PCI::init(); // Initialise PCI.


    char *initproc = NArch::cmdline.get("init");
    if (initproc) {
        NUtil::printf("[nomos]: Using init process from cmdline: `%s`.\n", initproc);
    } else {
        initproc = (char *)"/bin/init";
        NUtil::printf("[nomos]: No init process specified, defaulting to `%s`.\n", initproc);
    }

    // Build exec params for init.
    char *initargv[] = { initproc, NULL };

    struct NSched::execparams params;
    NLib::memset(&params, 0, sizeof(params));
    params.path = initproc;
    params.argv = initargv;
    params.envp = NULL;
    params.argc = 1;
    params.envc = 0;
    params.cwd = NFS::VFS::vfs->getroot();
    params.root = NFS::VFS::vfs->getroot();
    params.uid = 0;
    params.gid = 0;
    params.euid = 0;
    params.egid = 0;
    params.checkperms = false;  // Kernel doesn't need permission check.
    params.issyscall = false;
    params.interpdepth = 0;

    struct NSched::execresult result;
    int err = NSched::exec(&params, &result);
    assert(err == 0, "Failed to exec init process.\n");

    // PROCESS
    NSched::Process *proc = new NSched::Process(result.addrspace);
    proc->cwd = NFS::VFS::vfs->getroot();
    if (proc->cwd && proc->cwd->fs) {
        proc->cwd->fs->fsref();  // Filesystem reference for initial cwd
    }

    NSched::pidtable->insert(proc->id, proc); // PID 1

    // PGRP
    NSched::ProcessGroup *pgrp = new NSched::ProcessGroup();
    pgrp->id = proc->id;
    pgrp->procs.push(proc);
    pgrp->ref(); // Reference for proc->pgrp

    // SESSION
    NSched::Session *session = new NSched::Session();
    session->id = proc->id;
    session->ctty = 0; // No controlling terminal initially
    session->pgrps.push(pgrp);
    session->ref(); // Reference for proc->session

    pgrp->session = session;

    proc->session = session;
    proc->pgrp = pgrp;

    // Increment address space reference (exec() created it with ref=0).
    result.addrspace->ref++;

    // Create /dev folder in VFS.
    NFS::VFS::vfs->create("/dev", NULL, { .st_mode = NFS::VFS::S_IFDIR | 0755, .st_uid = 0, .st_gid = 0 });
    // Mount DevFS at /dev.
    ssize_t ret = NFS::VFS::vfs->mount("devtmpfs", "/dev", "devtmpfs", 0, NULL);
    if (ret < 0) {
        NUtil::printf("[nomos]: Warning: Failed to mount devtmpfs at /dev (%d).\n", ret);
    }


    NFS::VFS::INode *console = NULL;
    ret = NFS::VFS::vfs->resolve("/dev/console", &console);
    if (ret < 0) {
        NUtil::printf("[nomos]: Warning: /dev/console not found for init process.\n");
    } else {
        proc->fdtable->open(console, NFS::VFS::O_RDWR); // FD 0.
        proc->fdtable->dup2(0, 1); // FD 1.
        proc->fdtable->dup2(0, 2); // FD 2.
        console->unref();
    }


    // THREAD
    NSched::Thread *uthread = new NSched::Thread(proc, NSched::DEFAULTSTACKSIZE);

    NUtil::dropwrite(); // We're past the useful information. Use only debugging outputs from here.

#ifdef __x86_64__
    uthread->ctx.rip = (uint64_t)result.entry;
    uthread->ctx.rsp = (uint64_t)result.stackptr;

    NLimine::console_write("\x1b[2J\x1b[H", 7);
#else
    assert(false, "User thread setup not implemented on this architecture.");
#endif

    NUtil::printf("[nomos]: Starting user init.\n");
    NSched::schedulethread(uthread); // Dispatch!
}

extern "C" void kernel_main(void) {
    NUtil::printf("Nomos %s, built %s\n", VERSION, BUILDDATE);

    // Initialise freestanding C++ "runtime" support.
    NCxx::init();

    // Initialise architecture-specific.
    NArch::init();
    assert(false, "Reached end of kernel_main() instead of jumping to thread.\n");
}
