#ifdef __x86_64__
#include <arch/limine/arch.hpp>
#include <arch/limine/console.hpp>
#include <arch/limine/module.hpp>
#include <arch/limine/requests.hpp>
#include <arch/x86_64/arch.hpp>
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
#include <fs/ustar.hpp>
#include <lib/align.hpp>
#include <lib/assert.hpp>
#include <lib/bitmap.hpp>
#include <lib/cmdline.hpp>
#include <mm/slab.hpp>
#include <mm/vmalloc.hpp>
#include <util/kprint.hpp>
#include <sched/sched.hpp>
#include <stddef.h>
#include <sys/elf.hpp>

static void hcf(void) {
    for (;;) {
        asm ("hlt");
    }
}

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

    NDev::setup(); // Initialise device registry.

    NFS::DEVFS::DevFileSystem *devfs = new NFS::DEVFS::DevFileSystem(&NFS::VFS::vfs); // Create and mount device filesystem.
    NFS::VFS::vfs.mount("/dev", devfs);


    for (NDev::regentry *entry = (NDev::regentry *)NDev::__drivers_start; (uintptr_t)entry < (uintptr_t)NDev::__drivers_end; entry++) {
        if (entry->magic == NDev::MAGIC && entry->info->stage == NDev::reginfo::STAGE1) {
            NUtil::printf("[nomos]: Discovered stage 1 driver: %s of type %s.\n", entry->info->name, entry->info->type == NDev::reginfo::GENERIC ? "GENERIC" : "MATCHED");

            entry->instance = entry->create();
        }
    }

    for (NDev::regentry *entry = (NDev::regentry *)NDev::__drivers_start; (uintptr_t)entry < (uintptr_t)NDev::__drivers_end; entry++) {
        if (entry->magic == NDev::MAGIC && entry->info->stage == NDev::reginfo::STAGE2) {
            NUtil::printf("[nomos]: Discovered stage 2 driver: %s of type %s.\n", entry->info->name, entry->info->type == NDev::reginfo::GENERIC ? "GENERIC" : "MATCHED");
            entry->instance = entry->create();
        }
    }

    NDev::PCI::init(); // Initialise PCI.

    const char *initramfs = NArch::cmdline.get("initramfs");
    if (initramfs) { // Exists, load it.
        struct NArch::Module::modinfo mod = NArch::Module::loadmodule(initramfs); // Try to load.
        assertarg(ISMODULE(mod), "Failed to load `initramfs` specified: `%s`.\n", initramfs);

        if (NArch::cmdline.get("root") && !NLib::strcmp(NArch::cmdline.get("root"), "initramfs")) { // If the boot command line specifies that the initramfs should be used as the filesystem root, we should load it.
            NFS::USTAR::USTARFileSystem *fs = new NFS::USTAR::USTARFileSystem(&NFS::VFS::vfs, mod); // Use heap for allocation, keeps it alive past this scope.
            NFS::VFS::vfs.mount("/", fs);
        }
    }

    NFS::VFS::INode *node = NFS::VFS::vfs.resolve("/test");
    assert(node, "Failed to locate file.\n");

    struct NSys::ELF::header elfhdr;
    assert(node->read(&elfhdr, sizeof(elfhdr), 0, 0) == sizeof(elfhdr), "Failed to read ELF header.\n");

    assert(NSys::ELF::verifyheader(&elfhdr), "Failed to validate header.\n");

    assert(elfhdr.type == NSys::ELF::ELF_EXECUTABLE, "ELF is not executable.\n");

    struct NArch::VMM::addrspace *uspace;
    NArch::VMM::uclonecontext(&NArch::VMM::kspace, &uspace);

    void *ent = NULL;
    (void)ent;
    assert(NSys::ELF::loadfile(&elfhdr, node, uspace, &ent), "Failed to load ELF.\n");

    // PROCESS
    NSched::Process *proc = new NSched::Process(uspace);

    // PGRP
    NSched::ProcessGroup *pgrp = new NSched::ProcessGroup();
    pgrp->id = proc->id;
    pgrp->procs.push(proc);

    // SESSION
    NSched::Session *session = new NSched::Session();
    session->id = proc->id;
    session->ctty = NFS::DEVFS::makedev(4, 1);
    session->pgrps.push(pgrp);

    pgrp->session = session;

    proc->session = session;
    proc->pgrp = pgrp;

    // THREAD
    NSched::Thread *uthread = new NSched::Thread(proc, NSched::DEFAULTSTACKSIZE);

    // XXX: Be able to pass allocation to thread, so it knows to remove it on free.
    //uintptr_t ustack = (uintptr_t)NArch::PMM::alloc(1 << 20); // Allocate 1MB stack.
    //assert(ustack, "Failed to allocate memory for user stack.\n");
    uintptr_t ustack = (uintptr_t)NMem::VMalloc::alloc(1 << 20); // Allocate 1MB stack.
    assert(ustack, "Failed to allocate memory for user stack.\n");

    uintptr_t ustacktop = 0x0000800000000000 - NArch::PAGESIZE; // Subtract 4096 byte guard page from absolute maximum of userspace.

    uintptr_t ustackbottom = ustacktop - (1 << 20); // Bottom of stack.

    char *argv[] = { (char *)"/test", NULL };

    // We pass in the hhdm-offset physical stack top. The user will be given the mapped version.
    //void *rsp = NSys::ELF::preparestack((uintptr_t)NArch::hhdmoff((void *)(ustack + (1 << 20))), argv, NULL, &elfhdr, ustacktop);
    void *rsp = NSys::ELF::preparestack(ustack + (1 << 20), argv, NULL, &elfhdr, ustacktop);
    assert(rsp, "Stack alignment failed.\n");

    // Reserve stack location. We don't want to end up allocating into the stack region on requests for virtual memory.
    //uspace->vmaspace->reserve(ustackbottom, ustacktop, NMem::Virt::VIRT_NX | NMem::Virt::VIRT_RW | NMem::Virt::VIRT_USER);

    uspace->vmaspace->reserve(ustacktop, 0x0000800000000000, 0); // Reserve guard page.

    // Map stack into userspace memory.
    //NArch::VMM::maprange(uspace, ustackbottom, (uintptr_t)ustack, NArch::VMM::NOEXEC | NArch::VMM::WRITEABLE | NArch::VMM::USER | NArch::VMM::PRESENT, (1 << 20)); // Map range.
    NMem::VMalloc::mapintospace(uspace, ustack, ustackbottom, 1 << 20, NMem::Virt::VIRT_NX | NMem::Virt::VIRT_RW | NMem::Virt::VIRT_USER);

    uthread->ctx.rip = elfhdr.entryoff;
    uthread->ctx.rsp = (uint64_t)rsp;

    NLimine::console_write("\x1b[2J\x1b[H", 7);

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
