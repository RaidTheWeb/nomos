#include <arch/x86_64/apic.hpp>
#include <arch/x86_64/cpu.hpp>
#include <arch/x86_64/interrupts.hpp>
#include <arch/x86_64/io.hpp>
#include <arch/x86_64/panic.hpp>
#include <arch/x86_64/pmm.hpp>
#include <arch/x86_64/stacktrace.hpp>
#include <arch/x86_64/vmm.hpp>
#include <fs/vfs.hpp>
#include <lib/align.hpp>
#include <lib/assert.hpp>
#include <lib/string.hpp>
#include <mm/virt.hpp>
#include <util/kprint.hpp>
#include <sched/signal.hpp>

namespace NArch {
    namespace VMM {
        // Perform a TLB shootdown, also handles the TLB work on the calling CPU.
        extern void doshootdown(enum CPU::shootdown type, uintptr_t start, uintptr_t end);
    }

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
            bool old = CPU::get()->setint(false); // Clear.

            struct isr *isr = &CPU::get()->isrtable[vec];
            isr->eoi = eoi;
            isr->func = func;
            isr->id = ((uint64_t)CPU::get()->lapicid << 32) | vec;

            CPU::get()->setint(old); // Restore.
            return isr;
        }

        uint8_t allocvec(void) {
            bool old = CPU::get()->setint(false); // Clear.

            for (size_t i = 0; i < 256; i++) {
                if (!CPU::get()->isrtable[i].func) {
                    CPU::get()->setint(old);
                    return i;
                }
            }
            assert(false, "Could not find a vector to allocate.\n");
            return 0;
        }

        extern "C" void isr_handle(uint64_t vec, struct CPU::context *ctx) {
            struct isr *isr = &CPU::get()->isrtable[vec];
            CPU::get()->intstatus = false;

            if (isr->func != NULL) { // If this ISR has been allocated.

                if (isr->eoi) { // Should this ISR trigger an EOI?
                    APIC::eoi();
                }
                isr->func(isr, ctx); // Call ISR function.
            }

            if ((ctx->cs & 0x3) == 0x3) {
                NSched::signal_checkpending(ctx, NSched::POSTINT); // Check for pending signals before returning to userspace.
            }

            CPU::get()->intstatus = ctx->rflags & 0x200 ? true : false;
        }

        void exception_handler(struct isr *isr, struct CPU::context *ctx) {
            char errbuffer[2048];

            // Map exception number to signal for userspace faults.
            int sig = 0;
            bool isuserspace = (ctx->cs & 0x3) == 0x3;

            if ((isr->id & 0xffffffff) == 14) { // #PF
                uintptr_t addr = 0;
                asm volatile(
                    "mov %%cr2, %0"
                    : "=r"(addr) : : "memory"
                );

                struct VMM::addrspace *space = NArch::CPU::get()->currthread->process->addrspace;
                space->lock.acquire();
                uint64_t *pte = VMM::_resolvepte(space, addr);

                if (!pte || !(*pte & VMM::PRESENT)) {
                    // Check if this is a file-backed VMA that needs demand paging.
                    NMem::Virt::vmanode *vma = space->vmaspace->findcontaining(addr);
                    if (vma && vma->used && vma->backingfile && !(vma->flags & NMem::Virt::VIRT_CHRSPECIAL)) {
                        uintptr_t vmastart = vma->start;
                        uintptr_t vmaend = vma->end;
                        off_t vmafileoffset = vma->fileoffset;
                        uint8_t vmaflags = vma->flags;
                        NFS::VFS::INode *backingfile = vma->backingfile;
                        backingfile->ref();
                        space->lock.release();

                        void *newpage = PMM::alloc(PAGESIZE);
                        if (!newpage) {
                            backingfile->unref();
                            if (isuserspace) {
                                NSched::signalproc(NArch::CPU::get()->currthread->process, SIGKILL);
                                return;
                            }
                            panic("Out of memory during demand paging.\n");
                        }

                        NLib::memset(hhdmoff(newpage), 0, PAGESIZE);

                        // Calculate file offset for this page.
                        uintptr_t pagestart = NLib::aligndown(addr, PAGESIZE);
                        off_t fileoff = vmafileoffset + (pagestart - vmastart);

                        // Read from backing file into the new page (may sleep).
                        ssize_t nread = backingfile->read(hhdmoff(newpage), PAGESIZE, fileoff, 0);
                        if (nread < 0) {
                            PMM::free(newpage, PAGESIZE);
                            backingfile->unref();
                            if (isuserspace) {
                                NSched::signalproc(NArch::CPU::get()->currthread->process, SIGBUS);
                                return;
                            }
                            panic("File read failed during demand paging.\n");
                        }

                        // Re-acquire lock and verify VMA is still valid.
                        space->lock.acquire();
                        vma = space->vmaspace->findcontaining(addr);
                        if (!vma || !vma->used || vma->backingfile != backingfile ||
                            vma->start != vmastart || vma->end != vmaend) {
                            // VMA was changed while we were sleeping, discard page.
                            space->lock.release();
                            PMM::free(newpage, PAGESIZE);
                            backingfile->unref();
                            if (isuserspace) {
                                NSched::signalproc(NArch::CPU::get()->currthread->process, SIGSEGV);
                                return;
                            }
                            panic("VMA changed during demand paging.\n");
                        }
                        backingfile->unref();

                        // Map the page with appropriate flags from VMA.
                        uint64_t mapflags = VMM::PRESENT | VMM::USER;
                        if (vmaflags & NMem::Virt::VIRT_RW) {
                            mapflags |= VMM::WRITEABLE;
                        }
                        if (vmaflags & NMem::Virt::VIRT_NX) {
                            mapflags |= VMM::NOEXEC;
                        }

                        VMM::_mappage(space, pagestart, (uintptr_t)newpage, mapflags);
                        space->lock.release();

                        NArch::VMM::doshootdown(CPU::TLBSHOOTDOWN_SINGLE, pagestart, pagestart + PAGESIZE);
                        return;
                    }

                    space->lock.release();
                    // Send SIGSEGV for non-present page in userspace.
                    if (isuserspace) {
                        NUtil::printf("[arch/x86_64/interrupts] (%u:%u) Page fault at %p: non-present page.\n", NArch::CPU::get()->currthread->process->id, NArch::CPU::get()->currthread->id, addr);
                        NSched::signalproc(NArch::CPU::get()->currthread->process, SIGSEGV);
                        return;
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
                    meta->unref(); // Unref old page, free if needed.

                    // XXX: Free pages with no more references from any thread.
                    NArch::VMM::doshootdown(CPU::TLBSHOOTDOWN_SINGLE, addr, addr + PAGESIZE);
                    return;
                }
pffault:
                NUtil::snprintf(errbuffer, sizeof(errbuffer), "CPU Exception: %s.\nPage fault at %p occurred due to %s %s in %p during %s as %s(%lu).\n", exceptions[isr->id & 0xffffffff], ctx->rip, ctx->err & (1 << 1) ? "Write" : "Read", ctx->err & (1 << 0) ? "Page protection violation" : "Non-present page violation", addr, ctx->err & (1 << 4) ? "Instruction Fetch" : "Normal Operation", ctx->err & (1 << 2) ? "User" : "Supervisor", NArch::CPU::get()->currthread->process->id);
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
