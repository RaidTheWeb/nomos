#include <arch/x86_64/apic.hpp>
#include <arch/x86_64/cpu.hpp>
#include <arch/x86_64/interrupts.hpp>
#include <arch/x86_64/io.hpp>
#include <arch/x86_64/panic.hpp>
#include <arch/x86_64/pmm.hpp>
#include <arch/x86_64/stacktrace.hpp>
#include <arch/x86_64/tsc.hpp>
#include <arch/x86_64/vmm.hpp>
#include <fs/vfs.hpp>
#include <lib/align.hpp>
#include <lib/assert.hpp>
#include <lib/string.hpp>
#include <mm/pagecache.hpp>
#include <mm/virt.hpp>
#include <util/kprint.hpp>
#include <sched/signal.hpp>
#include <sys/fault.hpp>

namespace NArch {
    namespace Interrupts {
        // Reference ISR table from assembly. This is for stubs, not handlers.
        extern "C" const uint64_t isr_table[256];

        struct idtentry idt[256];
        static struct idtr idtr;

        static const char *exceptions[] = {
            "Division Error (#DE)",
            "Debug (#DB)",
            "Non-Maskable Interrupt",
            "Breakpoint (#BP)",
            "Overflow (#OF)",
            "Bound Range Exceeded (#BR)",
            "Invalid Opcode (#UD)",
            "Device Not Available (#NM)",
            "Double Fault (#DF)",
            "???",
            "Invalid TSS (#TS)",
            "Segment Not Present (#NP)",
            "Stack Segment Fault (#SS)",
            "General Protection Fault (#GP)",
            "Page Fault (#PF)",
            "???",
            "x87 Floating Point Exception (#MF)",
            "Alignment Check (#AC)",
            "Machine Check (#MC)",
            "SIMD Floating Point Exception (#XM)",
            "Virtualisation Exception (#VE)",
            "Control Protection Exception (#CP)",
            "???",
            "???",
            "???",
            "???",
            "???",
            "???",
            "Hypervisor Injection Exception (#HV)",
            "VMM Communication Exception (#VC)",
            "Security Exception (#SX)",
            "???"
        };

        struct isr *regisr(uint8_t vec, void (*func)(struct isr *self, struct CPU::context *ctx), bool eoi) {
            CPU::get()->veclock.acquire();

            struct isr *isr = &CPU::get()->isrtable[vec];
            isr->eoi = eoi;
            isr->func = func;
            isr->id = ((uint64_t)CPU::get()->lapicid << 32) | vec;

            // Mark vector as allocated in the bitmap.
            size_t idx = vec / 64;
            uint64_t bit = 1ULL << (vec % 64);
            CPU::get()->vecbitmap[idx] |= bit;

            CPU::get()->veclock.release();
            return isr;
        }

        uint8_t allocvec(void) {
            CPU::get()->veclock.acquire();

            // Start from vector 32 to skip exception vectors 0-31.
            for (size_t i = 32; i < 255; i++) {
                size_t idx = i / 64;
                uint64_t bit = 1ULL << (i % 64);
                if (!(CPU::get()->vecbitmap[idx] & bit)) {
                    CPU::get()->vecbitmap[idx] |= bit; // Mark as allocated.
                    CPU::get()->veclock.release();
                    return (uint8_t)i;
                }
            }
            assert(false, "No free interrupt vectors on this CPU.\n");
            CPU::get()->veclock.release();
            return 0;
        }

        void freevec(uint8_t vec) {
            CPU::get()->veclock.acquire();

            size_t idx = vec / 64;
            uint64_t bit = 1ULL << (vec % 64);
            CPU::get()->vecbitmap[idx] &= ~bit;
            CPU::get()->isrtable[vec].func = NULL;

            CPU::get()->veclock.release();
        }

        uint8_t allocvecon(struct CPU::cpulocal *cpu) {
            cpu->veclock.acquire();

            for (size_t i = 32; i < 255; i++) {
                size_t idx = i / 64;
                uint64_t bit = 1ULL << (i % 64);
                if (!(cpu->vecbitmap[idx] & bit)) {
                    cpu->vecbitmap[idx] |= bit;
                    cpu->veclock.release();
                    return (uint8_t)i;
                }
            }
            assert(false, "No free interrupt vectors on target CPU.\n");
            cpu->veclock.release();
            return 0;
        }

        struct isr *regisron(struct CPU::cpulocal *cpu, uint8_t vec, void (*func)(struct isr *self, struct CPU::context *ctx), bool eoi) {
            cpu->veclock.acquire();

            struct isr *isr = &cpu->isrtable[vec];
            isr->eoi = eoi;
            isr->id = ((uint64_t)cpu->lapicid << 32) | vec;

            // Write func last so the target CPU sees consistent eoi/id before the handler.
            asm volatile("" ::: "memory");
            isr->func = func;

            size_t idx = vec / 64;
            uint64_t bit = 1ULL << (vec % 64);
            cpu->vecbitmap[idx] |= bit;

            cpu->veclock.release();
            return isr;
        }

        void freevecon(struct CPU::cpulocal *cpu, uint8_t vec) {
            cpu->veclock.acquire();

            size_t idx = vec / 64;
            uint64_t bit = 1ULL << (vec % 64);
            cpu->vecbitmap[idx] &= ~bit;
            cpu->isrtable[vec].func = NULL;

            cpu->veclock.release();
        }

        extern "C" void isr_handle(uint64_t vec, struct CPU::context *ctx) {
            struct isr *isr = &CPU::get()->isrtable[vec];
            bool oldininterrupt = CPU::get()->ininterrupt; // Save for nesting.
            CPU::get()->intstatus = false;
            CPU::get()->ininterrupt = true;
            CPU::get()->handlingvec = vec;

            NSched::Thread *pendmig = CPU::get()->pendingmigrate;
            if (pendmig) {
                CPU::get()->pendingmigrate = NULL;
                pendmig->enablemigrate();
            }

            if (NArch::CPU::get()->intcntr == __SIZE_MAX__) {
                NArch::CPU::get()->intcntr = 0; // Handle wraparound. We do not care about intcntr for statistics purposes, only for ratelimiting.
            }

            if (NArch::CPU::get()->entropypool != NULL && (++NArch::CPU::get()->intcntr % 100) == 0) {
                uint64_t tsc = TSC::query();
                uint64_t seed = vec ^ tsc ^ (tsc >> 32); // Combine vector and TSC for some entropy.
                NArch::CPU::get()->entropypool->addentropy((uint8_t *)&seed, sizeof(seed), 1);
            }

            if (isr->func != NULL) { // If this ISR has been allocated.
                if (isr->eoi) { // Should this ISR trigger an EOI?
                    APIC::eoi();
                }
                isr->func(isr, ctx); // Call ISR function.
            } else if(vec >= 32 && vec != 0xff) {
                APIC::eoi();
            }

            if ((ctx->cs & 0x3) == 0x3) {
                NSched::signal_checkpending(ctx, NSched::POSTINT); // Check for pending signals before returning to userspace.
            }

            CPU::get()->ininterrupt = oldininterrupt; // Restore previous nesting state.
            CPU::get()->handlingvec = 0;
            CPU::get()->intstatus = ctx->rflags & 0x200 ? true : false; // If we initially had interrupts enabled, re-enable them on return.
        }

        void exception_handler(struct isr *isr, struct CPU::context *ctx) {
            char errbuffer[2048];

            // Map exception number to signal for userspace faults.
            int sig = 0;
            bool isuserspace = (ctx->cs & 0x3) == 0x3;

            if ((isr->id & 0xffffffff) == 14) { // #PF
                uintptr_t fixup = 0;

                uintptr_t addr = 0;
                asm volatile(
                    "mov %%cr2, %0"
                    : "=r"(addr) : : "memory"
                );

                if (!NArch::CPU::get()->currthread || !NArch::CPU::get()->currthread->process) {
                    NUtil::snprintf(errbuffer, sizeof(errbuffer), "CPU Exception: %s.\nPage fault at %p with no current process.\n", exceptions[isr->id & 0xffffffff], addr);
                    panic(errbuffer);
                }

                struct VMM::addrspace *space = NArch::CPU::get()->currthread->process->addrspace;
                if (!space) {
                    NUtil::snprintf(errbuffer, sizeof(errbuffer), "CPU Exception: %s.\nPage fault at %p with no address space.\n", exceptions[isr->id & 0xffffffff], addr);
                    panic(errbuffer);
                }

                space->lock.acquire();
                uint64_t *pte = VMM::_resolvepte(space, addr);

                if (!pte || !(*pte & VMM::PRESENT)) {
                    // Check if this address belongs to a valid VMA that needs demand paging.
                    NMem::Virt::vmanode *vma = space->vmaspace->findcontaining(addr);
                    if (vma && vma->used && !(vma->flags & NMem::Virt::VIRT_CHRSPECIAL)) {
                        if (!vma->backingfile) { // No backing file. Probably anonymous.
                            uintptr_t pagestart = NLib::aligndown(addr, PAGESIZE);
                            uint8_t vmaflags = vma->flags;

                            void *newpage = PMM::alloc(PAGESIZE);
                            if (!newpage) {
                                space->lock.release();
                                if (isuserspace) {
                                    NSched::signalproc(NArch::CPU::get()->currthread->process, SIGKILL);
                                    return;
                                }
                                panic("Out of memory during anonymous demand paging.\n");
                            }

                            NLib::memset(hhdmoff(newpage), 0, PAGESIZE);

                            uint64_t mapflags = VMM::PRESENT | VMM::USER;
                            if (vmaflags & NMem::Virt::VIRT_RW) {
                                mapflags |= VMM::WRITEABLE;
                            }
                            if (vmaflags & NMem::Virt::VIRT_NX) {
                                mapflags |= VMM::NOEXEC;
                            }

                            VMM::_mappage(space, pagestart, (uintptr_t)newpage, mapflags, false);
                            space->lock.release();
                            return;
                        }

                        // File-backed demand paging.
                        uintptr_t vmastart = vma->start;
                        uintptr_t vmaend = vma->end;
                        off_t vmafileoffset = vma->fileoffset;
                        size_t vmafilemapsize = vma->filemapsize;
                        uint8_t vmaflags = vma->flags;
                        NFS::VFS::INode *backingfile = vma->backingfile;
                        backingfile->ref();
                        space->lock.release();
                        NArch::CPU::get()->preemptdisabled = true; // Prevent timer preemption before we block.
                        NSched::Thread *currthread = NArch::CPU::get()->currthread;
                        bool oldmigrate = __atomic_load_n(&currthread->migratedisabled, memory_order_acquire);
                        currthread->disablemigrate(); // Prevent migration, so we aren't handling the page fault on one CPU and then get migrated to another CPU before we finish.
                        NArch::CPU::get()->ininterrupt = false;
                        asm volatile("" ::: "memory"); // Ensure flags are visible.
                        bool oldint = NArch::CPU::get()->setint(true); // Let other stuff happen while we block.

                        // Calculate file offset for this page.
                        uintptr_t pagestart = NLib::aligndown(addr, PAGESIZE);
                        size_t pageoffsetinvma = pagestart - vmastart;

                        if (pageoffsetinvma >= vmafilemapsize) { // Send SIGBUS for accesses beyond file-backed region.
                            NArch::CPU::get()->setint(oldint);
                            if (!oldmigrate) {
                                currthread->enablemigrate();
                            }
                            backingfile->unref();
                            if (isuserspace) {
                                NSched::signalproc(NArch::CPU::get()->currthread->process, SIGBUS);
                                return;
                            }
                            panic("Page fault beyond file-backed region.\n");
                        }

                        off_t fileoff = vmafileoffset + pageoffsetinvma;

                        NMem::CachePage *cachepage = backingfile->getorcachepage(fileoff);
                        if (!cachepage) {
                            NArch::CPU::get()->setint(oldint);
                            if (!oldmigrate) {
                                currthread->enablemigrate();
                            }
                            backingfile->unref();
                            if (isuserspace) {
                                NSched::signalproc(NArch::CPU::get()->currthread->process, SIGKILL);
                                return;
                            }
                            panic("Out of memory during demand paging.\n");
                        }

                        // Page is returned locked. Check if it needs to be read from disk.
                        if (!cachepage->testflag(NMem::PAGE_UPTODATE)) {
                            int err = backingfile->readpage(cachepage); // May block on disk I/O.
                            if (err < 0) {
                                NArch::CPU::get()->setint(oldint);
                                if (!oldmigrate) {
                                    currthread->enablemigrate();
                                }
                                cachepage->pageunlock();
                                cachepage->unref();
                                backingfile->unref();
                                if (isuserspace) {
                                    NSched::signalproc(NArch::CPU::get()->currthread->process, SIGBUS);
                                    return;
                                }
                                panic("File read failed during demand paging.\n");
                            }

                            // Check if this page contains the EOF boundary.
                            size_t bytesinthispage = vmafilemapsize - pageoffsetinvma;
                            if (bytesinthispage < PAGESIZE) {
                                // This page partially contains file data. Zero-fill the rest.
                                void *pagedata = hhdmoff((void *)cachepage->physaddr);
                                NLib::memset((char *)pagedata + bytesinthispage, 0, PAGESIZE - bytesinthispage);
                            }
                        }

                        if (isuserspace) { // Handle signal (otherwise, we'd never get it handled until disk I/O has stopped).
                            NLib::sigset_t pending = __atomic_load_n(
                                &NArch::CPU::get()->currthread->process->signalstate.pending,
                                memory_order_acquire);
                            NLib::sigset_t blocked = __atomic_load_n(
                                &NArch::CPU::get()->currthread->blocked,
                                memory_order_acquire);
                            if (pending & ~blocked) {
                                NArch::CPU::get()->setint(oldint);
                                if (!oldmigrate) {
                                    currthread->enablemigrate();
                                }
                                cachepage->pageunlock();
                                cachepage->unref();
                                backingfile->unref();
                                return; // Abort. We'll be thrown back in here when we fault again, but we'd like signals to be done.
                            }
                        }

                        // Re-acquire space lock and verify VMA is still valid.
                        space->lock.acquire();
                        vma = space->vmaspace->findcontaining(addr);
                        if (!vma || !vma->used || vma->backingfile != backingfile ||
                            vma->start != vmastart || vma->end != vmaend) {
                            // VMA was changed while we were sleeping, discard mapping.
                            space->lock.release();
                            NArch::CPU::get()->setint(oldint); // Restore interrupt state now.
                            if (!oldmigrate) {
                                currthread->enablemigrate();
                            }
                            cachepage->pageunlock();
                            cachepage->unref();
                            backingfile->unref();
                            if (isuserspace) {
                                NSched::signalproc(NArch::CPU::get()->currthread->process, SIGSEGV);
                                return;
                            }
                            panic("VMA changed during demand paging.\n");
                        }

                        // Map the cached page into the process address space.
                        bool privatecow = (vmaflags & NMem::Virt::VIRT_RW) && !(vmaflags & NMem::Virt::VIRT_SHARED);
                        uint64_t mapflags = VMM::PRESENT | VMM::USER;
                        if (privatecow) { // Mark private mappings as CoW (if writeable) so we get a copy.
                            mapflags |= VMM::COW; // Read-only + CoW.
                        } else if (vmaflags & NMem::Virt::VIRT_RW) {
                            mapflags |= VMM::WRITEABLE; // Direct access.
                        }
                        if (vmaflags & NMem::Virt::VIRT_NX) {
                            mapflags |= VMM::NOEXEC;
                        }

                        // Increment reference count for the mapping.
                        cachepage->pagemeta->ref();

                        // Track this mapping in the cache page for reverse mapping.
                        cachepage->addmapping(space, pagestart);

                        VMM::_mappage(space, pagestart, cachepage->physaddr, mapflags, false);
                        space->lock.release();

                        cachepage->pageunlock();
                        cachepage->unref();

                        // Trigger readahead for sequential access patterns.
                        backingfile->readahead(fileoff + PAGESIZE);

                        backingfile->unref();

                        VMM::doshootdown(VMM::SHOOTDOWN_SINGLE, pagestart, pagestart + PAGESIZE);

                        // Now restore original interrupt state before returning.
                        NArch::CPU::get()->setint(oldint);
                        if (!oldmigrate) {
                            currthread->enablemigrate();
                        }
                        return;
                    }

                    space->lock.release();
                    // Send SIGSEGV for non-present page in userspace.
                    if (isuserspace) {
                        NUtil::printf("[arch/x86_64/interrupts] (%u:%u) Page fault at %p: non-present page.\n", NArch::CPU::get()->currthread->process->id, NArch::CPU::get()->currthread->id, addr);
                        NSched::signalproc(NArch::CPU::get()->currthread->process, SIGSEGV);
                        return;
                    }

                    // Handle usercopy and other *known* fault points. Only handles non-present faults.
                    fixup = NSys::checkfault((uintptr_t)ctx->rip);
                    if (fixup) { // Is this fault fixable?
                        ctx->rip = fixup;
                        return; // Return to fixed-up instruction.
                    }

                    goto pffault;
                }

                // Handle copy-on-write page fault (checks if the fault was caused by a write and the page is marked as copy-on-write).
                if (ctx->err & (1 << 1) && (*pte) & VMM::COW) {
                    void *newpage = PMM::alloc(PAGESIZE);
                    if (!newpage) {
                        space->lock.release();
                        // Out of memory, send SIGKILL to process.
                        if (isuserspace) {
                            NSched::signalproc(NArch::CPU::get()->currthread->process, SIGKILL);
                            return;
                        }
                        // Kernel OOM is fatal.
                        panic("Out of memory during COW page fault handling.\n");
                    }

                    // Resolve physical page from old address space.
                    void *oldpage = (void *)(*pte & VMM::ADDRMASK);
                    NLib::memcpy(hhdmoff(newpage), hhdmoff(oldpage), PAGESIZE);

                    // Construct new PTE: use properly masked physical address with preserved flags.
                    uint64_t newpte = ((uint64_t)newpage & VMM::ADDRMASK) | (*pte & ~VMM::ADDRMASK);
                    newpte |= VMM::WRITEABLE;
                    newpte &= ~VMM::COW;
                    *pte = newpte;
                    space->lock.release();

                    PMM::PageMeta *meta = PMM::phystometa((uintptr_t)oldpage);
                    assertarg(meta, "Failed to get page metadata for physical address %p during COW handling.\n", oldpage);

                    if (meta->flags & PMM::PageMeta::PAGEMETA_PAGECACHE) { // Remove old mappings.
                        NMem::CachePage *cachepage = (NMem::CachePage *)meta->cacheentry;
                        if (cachepage) {
                            uintptr_t pagestart = NLib::aligndown(addr, PAGESIZE);
                            cachepage->removemapping(space, pagestart);
                        }
                    }

                    meta->unref(); // Unref old page, free if needed.

                    // Disable migration before enabling interrupts for the TLB
                    NSched::Thread *currthread = NArch::CPU::get()->currthread;
                    bool oldmigrate = __atomic_load_n(&currthread->migratedisabled, memory_order_acquire);
                    currthread->disablemigrate();
                    NArch::CPU::get()->ininterrupt = false;
                    asm volatile("" ::: "memory");
                    bool oldint = NArch::CPU::get()->setint(true);

                    VMM::doshootdown(VMM::SHOOTDOWN_SINGLE, addr, addr + PAGESIZE);

                    NArch::CPU::get()->setint(oldint);
                    if (!oldmigrate) {
                        currthread->enablemigrate();
                    }
                    return;
                } else {
                    space->lock.release();
                    // Send SIGSEGV for write to non-writeable page in userspace.
                    if (isuserspace) {
                        NUtil::printf("[arch/x86_64/interrupts] (%u:%u) Page fault at %p: access violation on page.\n", NArch::CPU::get()->currthread->process->id, NArch::CPU::get()->currthread->id, addr);
                        NSched::signalproc(NArch::CPU::get()->currthread->process, SIGSEGV);
                        return;
                    }

                    // Handle usercopy and other *known* fault points. Handles any other protection fault.
                    fixup = NSys::checkfault((uintptr_t)ctx->rip);
                    if (fixup) { // Is this fault fixable?
                        ctx->rip = fixup;
                        return; // Return to fixed-up instruction.
                    }

                    goto pffault;
                }
pffault:
                NUtil::snprintf(errbuffer, sizeof(errbuffer), "CPU Exception: %s.\nPage fault at %p occurred due to %s %s in %p during %s as %s(%lu).\n", exceptions[isr->id & 0xffffffff], ctx->rip, ctx->err & (1 << 1) ? "Write" : "Read", ctx->err & (1 << 0) ? "Page protection violation" : "Non-present page violation", addr, ctx->err & (1 << 4) ? "Instruction Fetch" : "Normal Operation", ctx->err & (1 << 2) ? "User" : "Supervisor", NArch::CPU::get()->currthread ? NArch::CPU::get()->currthread->process->id : 0);
                sig = SIGSEGV;
            } else if ((isr->id & 0xffffffff) == 13) { // #GP
                NUtil::snprintf(errbuffer, sizeof(errbuffer), "CPU Exception: %s.\nGeneral Protection Fault occurred at %p.\n", exceptions[isr->id & 0xffffffff], ctx->rip);
                sig = SIGSEGV;
            } else if ((isr->id & 0xffffffff) == 7) { // #NM
                NSched::handlelazyfpu();
                return;
            } else if ((isr->id & 0xffffffff) == 0) { // #DE - Divide by zero
                NUtil::snprintf(errbuffer, sizeof(errbuffer), "CPU Exception: %s.\nOccurred at %p.\n", exceptions[isr->id & 0xffffffff], ctx->rip);
                sig = SIGFPE;
            } else if ((isr->id & 0xffffffff) == 6) { // #UD - Invalid opcode
                NUtil::snprintf(errbuffer, sizeof(errbuffer), "CPU Exception: %s.\nOccurred at %p.\n", exceptions[isr->id & 0xffffffff], ctx->rip);
                sig = SIGILL;
            } else if ((isr->id & 0xffffffff) == 16) { // #MF - x87 FPU error
                NUtil::snprintf(errbuffer, sizeof(errbuffer), "CPU Exception: %s.\nOccurred at %p.\n", exceptions[isr->id & 0xffffffff], ctx->rip);
                sig = SIGFPE;
            } else if ((isr->id & 0xffffffff) == 19) { // #XM - SIMD exception
                NUtil::snprintf(errbuffer, sizeof(errbuffer), "CPU Exception: %s.\nOccurred at %p.\n", exceptions[isr->id & 0xffffffff], ctx->rip);
                sig = SIGFPE;
            } else if ((isr->id & 0xffffffff) == 5) { // #BR - Bound range exceeded
                NUtil::snprintf(errbuffer, sizeof(errbuffer), "CPU Exception: %s.\nOccurred at %p.\n", exceptions[isr->id & 0xffffffff], ctx->rip);
                sig = SIGSEGV;
            } else if ((isr->id & 0xffffffff) == 17) { // #AC - Alignment check
                NUtil::snprintf(errbuffer, sizeof(errbuffer), "CPU Exception: %s.\nOccurred at %p.\n", exceptions[isr->id & 0xffffffff], ctx->rip);
                sig = SIGBUS;
            } else {
                NUtil::snprintf(errbuffer, sizeof(errbuffer), "CPU Exception: %s.\nOccurred at %p.\n", exceptions[isr->id & 0xffffffff], ctx->rip);
            }

            // If this is a userspace exception and we have a signal, send it instead of panicking.
            if (isuserspace && sig > 0) {
                NUtil::printf("[arch/x86_64/interrupts] (%u:%u) Exception: %s\n", NArch::CPU::get()->currthread->process->id, NArch::CPU::get()->currthread->id, errbuffer);
                NSched::signalproc(NArch::CPU::get()->currthread->process, sig);
                return;
            }

            // Print register dump and stack trace for kernel exceptions.
            NUtil::printf("Register dump:\n");
            NUtil::printf("  RAX=%016lx RBX=%016lx RCX=%016lx RDX=%016lx\n", ctx->rax, ctx->rbx, ctx->rcx, ctx->rdx);
            NUtil::printf("  RSI=%016lx RDI=%016lx RBP=%016lx RSP=%016lx\n", ctx->rsi, ctx->rdi, ctx->rbp, ctx->rsp);
            NUtil::printf("  R8 =%016lx R9 =%016lx R10=%016lx R11=%016lx\n", ctx->r8, ctx->r9, ctx->r10, ctx->r11);
            NUtil::printf("  R12=%016lx R13=%016lx R14=%016lx R15=%016lx\n", ctx->r12, ctx->r13, ctx->r14, ctx->r15);
            NUtil::printf("  RIP=%016lx RFLAGS=%016lx CS=%04lx SS=%04lx\n", ctx->rip, ctx->rflags, ctx->cs, ctx->ss);
            NUtil::printf("  CR2=%016lx ERR=%016lx\n", ctx->cr2, ctx->err);

            // Print stack trace starting from exception context.
            printstacktrace(ctx->rbp, ctx->rip);

            // Kernel exceptions are always fatal.
            panic(errbuffer);
        }

        void setup(void) {
            idtr = {
                .size = sizeof(idt) - 1,
                .offset = (uint64_t)&idt[0]
            };

        // Register the entire set of 256 vectors for the sake of directing them towards a generic handler.
            for (size_t i = 0; i < 256; i++) {
                // Offset to handler:
                idt[i].offlow = isr_table[i] & 0xffff;
                idt[i].offmid = (isr_table[i] >> 16) & 0xffff;
                idt[i].offhigh = (isr_table[i] >> 32) & 0xffffffff;
                idt[i].ist = 0;
                idt[i].flags = 0x8e;
                idt[i].cs = 0x08; // Kernel code segment -> We want the kernel to be handling all interrupts.
                idt[i].rsvd = 0;
            }

            idt[2].ist = 1;  // NMI uses IST1.
            idt[8].ist = 2;  // Double Fault uses IST2.
            idt[13].ist = 3; // #GP uses IST3.
        }

        void reload(void) {
            asm volatile("lidt (%%rax)" : : "a"(&idtr));

            for (size_t i = 0; i < 32; i++) { // Register ISRs for exceptions.
                regisr(i, exception_handler, false);
            }

            CPU::get()->setint(true);
        }
    }
}
