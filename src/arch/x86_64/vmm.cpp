#include <arch/limine/requests.hpp>
#include <arch/x86_64/apic.hpp>
#include <arch/x86_64/cpu.hpp>
#include <arch/x86_64/smp.hpp>
#include <arch/x86_64/vmm.hpp>
#include <lib/align.hpp>
#include <lib/assert.hpp>
#include <lib/errno.hpp>
#include <lib/string.hpp>
#include <sys/syscall.hpp>
#include <util/kprint.hpp>
#include <sched/sched.hpp>
#include <fs/vfs.hpp>

extern void *_text_start;
extern void *_text_end;
extern void *_data_start;
extern void *_data_end;
extern void *_rodata_start;
extern void *_rodata_end;

namespace NArch {
    namespace VMM {
        struct addrspace kspace;


        void waittlbshootdown(uint32_t caller, size_t expected) {
            uint64_t timeout = 1000000; // Arbitrary number of "cycles" to wait before declaring that the TLB shootdown failed.

            for (size_t i = 0; i < SMP::awakecpus; i++) {
                if (SMP::cpulist[i]->id == caller) {
                    continue; // Skip the calling CPU.
                }

                while (__atomic_load_n(&SMP::cpulist[i]->tlblocal.completion, memory_order_acquire) < expected) {
                    if (--timeout == 0) {
                        panic("Timeout on TLB shootdown.");
                        break;
                    }
                    asm volatile ("pause");
                }
            }
        }

        void doshootdown(enum CPU::shootdown type, uintptr_t start, uintptr_t end) {
            uint32_t caller = 0;
            if (SMP::initialised && SMP::awakecpus >= 2) {

                caller = CPU::get()->id;

                __atomic_fetch_add(&CPU::tlbglobal.activereqs, 1, memory_order_acquire);

                for (size_t i = 0; i < SMP::awakecpus; i++) {
                    if (SMP::cpulist[i]->id == caller) {
                        continue;
                    }

                    struct CPU::tlblocal *state = &SMP::cpulist[i]->tlblocal;

                    // Wait for previous operation to complete.
                    while (__atomic_load_n(&state->pending, memory_order_acquire)) {
                        asm volatile("pause");
                    }

                    state->type = type;
                    state->start = start;
                    state->end = end;
                    __atomic_store_n(&state->pending, true, memory_order_release);
                }

                APIC::sendipi(0, 0xfc, APIC::IPIFIXED, APIC::IPIPHYS, APIC::IPIOTHER); // Send TLB shootdown to all other CPUs.
            }

            // Handle for ourselves.
            switch (type) {
                case CPU::TLBSHOOTDOWN_SINGLE:
                    invlpg(start);
                    break;
                case CPU::TLBSHOOTDOWN_FULL:
                    flushtlb();
                    break;
                case CPU::TLBSHOOTDOWN_RANGE:
                    invlrange(start, end - start);
                    break;
                default:
                    break;
            }

            if (SMP::initialised && SMP::awakecpus >= 2) {
                waittlbshootdown(caller, 1); // Wait for pending TLB shootdown.
                __atomic_fetch_sub(&CPU::tlbglobal.activereqs, 1, memory_order_release);
            }
        }

        void tlbshootdown(struct Interrupts::isr *isr, struct CPU::context *ctx) {
            (void)isr;
            (void)ctx;

            struct CPU::cpulocal *cpu = CPU::get();
            struct CPU::tlblocal *state = &cpu->tlblocal;

            if (!__atomic_load_n(&state->pending, memory_order_acquire)) { // Don't even bother without a pending operation.
                return;
            }

            switch (state->type) {
                case CPU::TLBSHOOTDOWN_SINGLE:
                    invlpg(state->start);
                    break;
                case CPU::TLBSHOOTDOWN_RANGE:
                    invlrange(state->start, state->end - state->start);
                    break;
                case CPU::TLBSHOOTDOWN_FULL:
                    flushtlb();
                    break;
                case CPU::TLBSHOOTDOWN_NONE:
                    break;
            }

            // Mark as done.
            __atomic_fetch_add(&state->completion, 1, memory_order_release);
            __atomic_store_n(&state->pending, false, memory_order_release);
        }


        struct pagetable *walk(uint64_t entry) {
            // Walk down into the next entry.

            if (!(entry & PRESENT)) { // Isn't marked present.
                return NULL; // Nothing to work with.
            }

            // Adds HHDM offset to allow access in a higher half kernel.
            return (struct pagetable *)(hhdmoff((void *)(entry & ADDRMASK)));
        }

        void swapcontext(struct addrspace *space) {
            swaptopml4(space->pml4phy);
        }

        void uclonecontext(struct addrspace *src, struct addrspace **dest) {
            assert(src, "Invalid source.\n");
            assert(dest, "Invalid destination.\n");

            NLib::ScopeIRQSpinlock sguard(&src->lock);

            *dest = new struct VMM::addrspace;
            NLib::ScopeIRQSpinlock dguard(&(*dest)->lock);

            (*dest)->pml4 = (struct VMM::pagetable *)PMM::alloc(PAGESIZE);
            assert((*dest)->pml4, "Failed to allocate memory for user space PML4.\n");
            (*dest)->pml4phy = (uintptr_t)(*dest)->pml4;
            (*dest)->pml4 = (struct VMM::pagetable *)hhdmoff((*dest)->pml4);
            NLib::memset((*dest)->pml4, 0, PAGESIZE);

            (*dest)->vmaspace = new NMem::Virt::VMASpace(0x0000000000001000, 0x0000800000000000);

            for (size_t i = 0; i < 256; i++) { // Map user
                uint64_t *entry = (uint64_t *)PMM::alloc(PAGESIZE);
                assert(entry, "Failed to allocate initial intermediate entry.\n");
                NLib::memset(hhdmoff(entry), 0, PAGESIZE);
                (*dest)->pml4->entries[i] = (uint64_t)entry | VMM::WRITEABLE | VMM::USER;
            }

            for (size_t i = 256; i < 512; i++) {
                (*dest)->pml4->entries[i] = src->pml4->entries[i];
            }
        }

        struct dupwork {
            struct addrspace *src;
            struct addrspace *dest;
        };

        static inline uint64_t vmatovmm(uint64_t vma, bool cow) {
            return 0 |
                PRESENT | // Mark as present.
                (vma & NMem::Virt::VIRT_USER ? USER : 0) |
                (vma & NMem::Virt::VIRT_NX ? NOEXEC : 0) |
                (cow ? COW : (
                    vma & NMem::Virt::VIRT_RW ? WRITEABLE : 0 // Non-COW writeable.
                ));
        }

        static void dupvmanode(struct NMem::Virt::vmanode *node, void *data) {
            struct dupwork *work = (struct dupwork *)data;

            if (node->used) { // We should only attempt to duplicate stuff we've used.

                void *reserved = work->dest->vmaspace->reserve(node->start, node->end, node->flags);
                assertarg(reserved, "Failed to reserve VMA region %p-%p in destination during fork.\n", (void *)node->start, (void *)node->end);

                size_t size = node->end - node->start;

                bool cowexempt = node->flags & NMem::Virt::VIRT_SHARED; // Is this mapped exempt from CoW?
                bool readonly = !(node->flags & NMem::Virt::VIRT_RW);

                for (size_t i = 0; i < size; i += PAGESIZE) {

                    uintptr_t phys = _virt2phys(work->src, node->start + i);

                    // Only map if the physical address is valid.
                    if (phys == 0) {
                        continue;
                    }

                    PMM::PageMeta *meta = PMM::phystometa(phys);
                    assertarg(meta, "Failed to get page metadata for physical address %p during address space fork.\n", (void *)phys);
                    meta->ref();

                    bool make_cow = !cowexempt && !readonly;

                    // Map page into destination address space.
                    if (!_mappage(work->dest, node->start + i, phys, vmatovmm(node->flags, make_cow))) {
                        meta->unref(); // Release the reference we just took on failure.
                        assertarg(false, "Failed to destination map page %p during address space fork.\n", node->start + i);
                    }
                    if (make_cow) { // Only bother remapping the source if we're doing CoW.
                        if (!_mappage(work->src, node->start + i, phys, vmatovmm(node->flags, true))) {
                            // Note: We do not unref here since dest mapping succeeded and holds a ref.
                            // The page will be cleaned up when the dest address space is destroyed.
                            assertarg(false, "Failed to source remap page during %p address space fork.\n", node->start + i);
                        }
                    }
                }
            }
        }

        addrspace::~addrspace(void) {
            NLib::ScopeIRQSpinlock guard(&this->lock);

            // Perform full TLB shootdown (we're about to free a LOT of pages).
            doshootdown(CPU::TLBSHOOTDOWN_FULL, 0, 0);

            this->vmaspace->traversedata(this->vmaspace->getroot(), [](struct NMem::Virt::vmanode *node, void *data) {
                struct addrspace *space = (struct addrspace *)data;

                if (node->used) {
                    size_t size = node->end - node->start;

                    // Unreference backing file if present.
                    if (node->backingfile) {
                        node->backingfile->unref();
                        node->backingfile = NULL;
                    }

                    for (size_t i = 0; i < size; i += PAGESIZE) {
                        uintptr_t phys = VMM::_virt2phys(space, node->start + i);
                        if (phys == 0) {
                            continue;
                        }

                        PMM::PageMeta *meta = PMM::phystometa(phys);
                        if (!meta) {
                            continue; // Skip.
                        }
                        meta->unref();
                    }
                }
            }, this);

            delete this->vmaspace;

            for (size_t i = 0; i < 256; i++) { // Only need to free user tables, kernel tables are shared.
                uint64_t pml4e = this->pml4->entries[i];
                if (!(pml4e & PRESENT)) {
                    continue;
                }

                struct pagetable *pdp = walk(pml4e);
                if (!pdp) {
                    continue;
                }

                for (size_t j = 0; j < 512; j++) {
                    uint64_t pdpe = pdp->entries[j];
                    if (!(pdpe & PRESENT)) {
                        continue;
                    }

                    struct pagetable *pd = walk(pdpe);
                    if (!pd) {
                        continue;
                    }

                    for (size_t k = 0; k < 512; k++) {
                        uint64_t pde = pd->entries[k];
                        if (!(pde & PRESENT)) {
                            continue;
                        }

                        struct pagetable *pt = walk(pde);
                        if (!pt) {
                            continue;
                        }

                        PMM::free((void *)hhdmsub(pt), PAGESIZE);
                    }

                    PMM::free((void *)hhdmsub(pd), PAGESIZE);
                }

                PMM::free((void *)hhdmsub(pdp), PAGESIZE);
            }
            PMM::free((void *)this->pml4phy, PAGESIZE);
        }

        struct addrspace *forkcontext(struct addrspace *src) {
            assert(src, "Invalid source.\n");

            NLib::ScopeIRQSpinlock sguard(&src->lock);

            struct addrspace *dest = new struct VMM::addrspace;
            NLib::ScopeIRQSpinlock dguard(&dest->lock);

            dest->pml4 = (struct VMM::pagetable *)PMM::alloc(PAGESIZE);
            assert(dest->pml4, "Failed to allocate memory for user space PML4.\n");
            dest->pml4phy = (uintptr_t)dest->pml4;
            dest->pml4 = (struct VMM::pagetable *)hhdmoff(dest->pml4);
            NLib::memset(dest->pml4, 0, PAGESIZE);

            dest->vmaspace = new NMem::Virt::VMASpace(0x0000000000001000, 0x0000800000000000);

            struct dupwork work {
                .src = src,
                .dest = dest
            };

            for (size_t i = 0; i < 512; i++) {
                uint64_t entry = src->pml4->entries[i];

                if (!entry || !(entry & PRESENT)) {
                    dest->pml4->entries[i] = 0;
                    continue;
                }

                if (!(entry & USER)) {
                    dest->pml4->entries[i] = src->pml4->entries[i]; // Copy kernel mappings as-is.
                }
            }

            src->vmaspace->traversedata(src->vmaspace->getroot(), dupvmanode, &work);

            asm volatile("mfence" : : : "memory");

            return dest;
        }

        void enterucontext(struct pagetable *pt, struct addrspace *space) {
            NLib::ScopeIRQSpinlock kguard(&kspace.lock);
            NLib::ScopeIRQSpinlock uguard(&space->lock);

            for (size_t i = 0; i < 256; i++) { // Copy lower half userspace tables to kernel map.
                pt->entries[i] = space->pml4->entries[i];
            }

            asm volatile("sfence" : : : "memory");
            doshootdown(CPU::TLBSHOOTDOWN_FULL, 0, 0);
        }

        uint64_t *_resolvepte(struct addrspace *space, uintptr_t virt) {

            // Decode virtual address:
            uint64_t pml4idx = (virt & PML4MASK) >> 39;
            uint64_t pdpidx = (virt & PDPMASK) >> 30;
            uint64_t pdidx = (virt & PDMASK) >> 21;
            uint64_t ptidx = (virt & PTMASK) >> 12;

            // Resolve virtual address:

            // Get reference to PML4 table.
            uint64_t pml4e = space->pml4->entries[pml4idx];
            if (!(pml4e & PRESENT)) {
                return NULL;
            }

            // Get reference to PDP table.
            struct pagetable *pdp = walk(pml4e);
            if (!pdp) {
                return NULL;
            }
            uint64_t pdpe = pdp->entries[pdpidx];
            if (!(pdpe & PRESENT)) {
                return NULL;
            }

            if (pdpe & HUGE) {
                return &pdp->entries[pdpidx];
            }

            // Get reference to PD table.
            struct pagetable *pd = walk(pdpe);
            if (!pd) {
                return NULL;
            }
            uint64_t pde = pd->entries[pdidx];
            if (!(pde & PRESENT)) {
                return NULL;
            }

            if (pde & HUGE) {
                return &pd->entries[pdidx];
            }

            // Get reference to PT table.
            struct pagetable *pt = walk(pde);
            if (!pt) {
                return NULL;
            }
            uint64_t pte = pt->entries[ptidx];
            if (!(pte & PRESENT)) {
                return NULL;
            }

            return &pt->entries[ptidx];
        }

        uintptr_t _virt2phys(struct addrspace *space, uintptr_t virt) {
            uint64_t *pte = _resolvepte(space, virt);
            if (!pte) {
                return 0;
            }

            // Construct physical address from address mask with offset.
            return (*pte & ADDRMASK) | (virt & OFFMASK);
        }

        bool _mappage(struct addrspace *space, uintptr_t virt, uintptr_t phys, uint64_t flags) {
            bool user = flags & USER; // If flags contain user, we should mark the intermediate pages as user too.

            // Align down to base of the page the address exists in.
            phys = NLib::aligndown(phys, PAGESIZE);
            virt = NLib::aligndown(virt, PAGESIZE);

            // Decode virtual address:
            uint64_t pml4idx = (virt & PML4MASK) >> 39;
            uint64_t pdpidx = (virt & PDPMASK) >> 30;
            uint64_t pdidx = (virt & PDMASK) >> 21;
            uint64_t ptidx = (virt & PTMASK) >> 12;

            // Step through the same process for decoding, but to create non-existent entries.
            struct pagetable *pdp = walk(space->pml4->entries[pml4idx]);
            if (!pdp) { // If this entry hasn't already been allocated.
                void *pdp_phys = PMM::alloc(PAGESIZE);
                if (!pdp_phys) {
                    return false; // Failed to allocate page.
                }

                // Zero the page BEFORE making it visible via the entry.
                pdp = (struct pagetable *)hhdmoff(pdp_phys);
                NLib::memset(pdp, 0, PAGESIZE);
                asm volatile("sfence" : : : "memory"); // Ensure zeroing is visible before entry is set.

                // Set pml4 entry to point to new page, has to be a non-higher half address.
                space->pml4->entries[pml4idx] = (uint64_t)pdp_phys | WRITEABLE | PRESENT | (user ? USER : 0);
            }

            struct pagetable *pd = walk(pdp->entries[pdpidx]);
            if (!pd) { // If this entry hasn't already been allocated.
                void *pd_phys = PMM::alloc(PAGESIZE);
                if (!pd_phys) {
                    return false; // Failed to allocate page.
                }

                // Zero the page BEFORE making it visible via the entry.
                pd = (struct pagetable *)hhdmoff(pd_phys);
                NLib::memset(pd, 0, PAGESIZE);
                asm volatile("sfence" : : : "memory"); // Ensure zeroing is visible before entry is set.

                pdp->entries[pdpidx] = (uint64_t)pd_phys | WRITEABLE | PRESENT | (user ? USER : 0);
            }

            struct pagetable *pt = walk(pd->entries[pdidx]);
            if (!pt) { // If this entry hasn't already been allocated.
                void *pt_phys = PMM::alloc(PAGESIZE);
                if (!pt_phys) {
                    return false; // Failed to allocate page.
                }

                // Zero the page BEFORE making it visible via the entry.
                pt = (struct pagetable *)hhdmoff(pt_phys);
                NLib::memset(pt, 0, PAGESIZE);
                asm volatile("sfence" : : : "memory"); // Ensure zeroing is visible before entry is set.

                pd->entries[pdidx] = (uint64_t)pt_phys | WRITEABLE | PRESENT | (user ? USER : 0);
            }

            bool wasPresent = pt->entries[ptidx] & PRESENT;

            // At the end of all the indirection:
            pt->entries[ptidx] = (phys & ADDRMASK) | flags;

            if (wasPresent) {
                doshootdown(CPU::TLBSHOOTDOWN_SINGLE, virt, virt + PAGESIZE);
            }
            return true;
        }

        void _unmappage(struct addrspace *space, uintptr_t virt) {
            uint64_t *pte = _resolvepte(space, virt);
            if (pte) {
                *pte = 0; // Blank page table entry, so that it now points NOWHERE.
                doshootdown(CPU::TLBSHOOTDOWN_SINGLE, virt, virt + PAGESIZE); // Invalidate, so that the CPU will know that it's lost this page.
            }
        }

        bool _maprange(struct addrspace *space, uintptr_t virt, uintptr_t phys, uint64_t flags, size_t size) {
            size_t end = NLib::alignup(virt + size, PAGESIZE); // Align length to page.
            // Align down to base.
            phys = NLib::aligndown(phys, PAGESIZE);
            virt = NLib::aligndown(virt, PAGESIZE);
            size = end - virt; // Overwrite size of range to represent page alignmentment.

            for (size_t i = 0; i < size; i += PAGESIZE) {
                assertarg(_mappage(space, virt + i, phys + i, flags), "Failed to map page in range 0x%016llx->0x%016llx.\n", virt, virt + size);
            }
            return true;
        }

        void _unmaprange(struct addrspace *space, uintptr_t virt, size_t size) {
            size_t end = NLib::alignup(virt + size, PAGESIZE); // Align length to page.
            virt = NLib::aligndown(virt, PAGESIZE);
            size = end - virt;

            for (size_t i = 0; i < size; i += PAGESIZE) {
                uint64_t *pte = _resolvepte(space, virt + i);
                if (pte) {
                    *pte = 0;
                }
            }

            doshootdown(CPU::TLBSHOOTDOWN_RANGE, virt, end);
        }

        static inline uint8_t convertflags(uint64_t flags) {
            return 0 |
                ((flags & VMM::WRITEABLE) ? NMem::Virt::VIRT_RW : 0) |
                ((flags & VMM::USER) ? NMem::Virt::VIRT_USER : 0) |
                ((flags & VMM::NOEXEC) ? NMem::Virt::VIRT_NX : 0);
        }

        void mapkernel(void *start, void *end, uint64_t flags) {
            size_t len = (uintptr_t)end - (uintptr_t)start;
            uintptr_t base = (uintptr_t)start;
            uintptr_t phyaddr = (uintptr_t)start - NLimine::eareq.response->virtual_base + NLimine::eareq.response->physical_base;

            kspace.vmaspace->reserve((uintptr_t)start, (uintptr_t)end, convertflags(flags)); // Reserve kernel sections in VMA space.
            maprange(&kspace, base, phyaddr, flags, len);
        }

        #define PROT_NONE       0x00
        #define PROT_READ       0x01
        #define PROT_WRITE      0x02
        #define PROT_EXEC       0x04

        #define MAP_FILE        0x00
        #define MAP_SHARED      0x01
        #define MAP_PRIVATE     0x02
        #define MAP_FIXED       0x10
        #define MAP_ANONYMOUS   0x20

        // Convert libc prot into VMA flags.
        static inline uint64_t prottovma(int prot) {
            return 0 |
                NMem::Virt::VIRT_USER |
                (prot & PROT_WRITE ? NMem::Virt::VIRT_RW : 0) |
                (prot & PROT_EXEC ? 0 : NMem::Virt::VIRT_NX);
        }

        // Convert libc prot into VMM flags.
        static inline uint64_t prottovmm(int prot) {
            return 0 |
                USER | PRESENT |
                (prot & PROT_WRITE ? WRITEABLE : 0) |
                (prot & PROT_EXEC ? 0 : NOEXEC);
        }

        extern "C" uint64_t sys_mmap(void *hint, size_t size, int prot, int flags, int fd, off_t off) {
            SYSCALL_LOG("sys_mmap(%p, %lu, %u, %u, %d, %lu).\n", hint, size, prot, flags, fd, off);

            if (size == 0) {
                SYSCALL_RET(-EINVAL);
            }

            size = NLib::alignup(size, PAGESIZE);

            struct CPU::cpulocal *cpu = CPU::get();
            NSched::Thread *thread = cpu->currthread;
            NSched::Process *proc = thread->process;
            struct addrspace *space = proc->addrspace;

            uint64_t vmaflags = prottovma(prot);
            if (flags & MAP_SHARED) {
                vmaflags |= NMem::Virt::VIRT_SHARED; // Map as shared, it won't be copy-on-write (changes visible to all processes sharing the mapping).
            }

            NFS::VFS::FileDescriptor *filedesc = NULL;
            NFS::VFS::INode *node = NULL;
            int fdflags = 0;
            struct NFS::VFS::stat nodeattr = {};
            bool isfilebacked = !(flags & MAP_ANONYMOUS);

            if (isfilebacked) {
                if (fd < 0) {
                    SYSCALL_RET(-EBADF);
                }

                // POSIX: offset must be page-aligned for file-backed mappings.
                if ((uintptr_t)off % PAGESIZE != 0) {
                    SYSCALL_RET(-EINVAL);
                }

                filedesc = proc->fdtable->get(fd);
                if (!filedesc) {
                    SYSCALL_RET(-EBADF);
                }

                node = filedesc->getnode();
                if (!node) {
                    filedesc->unref();
                    SYSCALL_RET(-EBADF);
                }

                fdflags = filedesc->getflags();
                nodeattr = node->getattr();

                // File not opened with read access?
                if (!((fdflags & NFS::VFS::O_ACCMODE) == NFS::VFS::O_RDWR || (fdflags & NFS::VFS::O_ACCMODE) == NFS::VFS::O_RDONLY)) {
                    node->unref();
                    filedesc->unref();
                    SYSCALL_RET(-EACCES);
                }

                if ((fdflags & NFS::VFS::O_APPEND) && (prot & PROT_WRITE)) {
                    // Can't map with write access if opened in append mode.
                    node->unref();
                    filedesc->unref();
                    SYSCALL_RET(-EACCES);
                }

                if (NFS::VFS::S_ISDIR(nodeattr.st_mode)) {
                    // Can't map a directory.
                    node->unref();
                    filedesc->unref();
                    SYSCALL_RET(-EISDIR);
                }

                if (off < 0 || (size_t)off + size > nodeattr.st_size) {
                    // Mapping beyond end of file.
                    node->unref();
                    filedesc->unref();
                    SYSCALL_RET(-EINVAL);
                }
            }

            // Now acquire the address space lock for the actual memory operations.
            NLib::ScopeIRQSpinlock guard(&space->lock);

            void *addr = NULL;

            if (flags & MAP_FIXED) {
                if ((uintptr_t)hint % PAGESIZE != 0) {
                    // Misaligned hint address.
                    if (node) {
                        node->unref();
                    }
                    if (filedesc) {
                        filedesc->unref();
                    }
                    SYSCALL_RET(-EINVAL);
                }
                space->vmaspace->free(hint, size); // Free any existing mappings in the range.
                addr = space->vmaspace->reserve((uintptr_t)hint, (uintptr_t)hint + size, vmaflags);
                if (!addr) {
                    // Failed to reserve at fixed address.
                    if (node) {
                        node->unref();
                    }
                    if (filedesc) {
                        filedesc->unref();
                    }
                    SYSCALL_RET(-ENOMEM);
                }
            } else {
                // Allocate anywhere, it really doesn't matter.
                addr = space->vmaspace->alloc(size, vmaflags);
                if (!addr) {
                    if (node) {
                        node->unref();
                    }
                    if (filedesc) {
                        filedesc->unref();
                    }
                    SYSCALL_RET(-ENOMEM);
                }
            }

            if (flags & MAP_ANONYMOUS) {
                for (size_t i = 0; i < size; i += PAGESIZE) {
                    void *page = PMM::alloc(PAGESIZE);
                    if (!page) {
                        // Free already-allocated pages before unmapping
                        for (size_t j = 0; j < i; j += PAGESIZE) {
                            uint64_t *pte = _resolvepte(space, (uintptr_t)addr + j);
                            if (pte && (*pte & PRESENT)) {
                                void *phys = (void *)(*pte & ADDRMASK);
                                PMM::free(phys, PAGESIZE);
                            }
                        }
                        _unmaprange(space, (uintptr_t)addr, i);
                        space->vmaspace->free(addr, size);
                        SYSCALL_RET(-ENOMEM);
                    }
                    NLib::memset(hhdmoff(page), 0, PAGESIZE);
                    if (!_mappage(space, (uintptr_t)addr + i, (uintptr_t)page, prottovmm(prot))) {
                        // Free the page we just allocated plus all previously allocated pages
                        PMM::free(page, PAGESIZE);
                        for (size_t j = 0; j < i; j += PAGESIZE) {
                            uint64_t *pte = _resolvepte(space, (uintptr_t)addr + j);
                            if (pte && (*pte & PRESENT)) {
                                void *phys = (void *)(*pte & ADDRMASK);
                                PMM::free(phys, PAGESIZE);
                            }
                        }
                        _unmaprange(space, (uintptr_t)addr, i);
                        space->vmaspace->free(addr, size);
                        SYSCALL_RET(-ENOMEM);
                    }
                }
            } else { // File-backed mapping.
                // Demand paging:
                bool demandback = NFS::VFS::S_ISBLK(nodeattr.st_mode) || NFS::VFS::S_ISREG(nodeattr.st_mode);
                // Character devices are demand paged unless MAP_SHARED is specified (in which case, they're DMA).
                demandback = demandback || (NFS::VFS::S_ISCHR(nodeattr.st_mode) && !(flags & MAP_SHARED));

                if (demandback) { // We can map regular files and block devices.
                    // Allocate file-backed VMA with demand paging.
                    if (flags & MAP_FIXED) {
                        // Find and update the VMA node with file backing info.
                        NMem::Virt::vmanode *vma = space->vmaspace->findcontaining((uintptr_t)addr);
                        if (vma) {
                            vma->backingfile = node;
                            vma->fileoffset = off;
                            node->ref(); // Keep a reference to the file.
                        }
                    } else {
                        NMem::Virt::vmanode *vma = space->vmaspace->findcontaining((uintptr_t)addr);
                        vma->backingfile = node;
                        vma->fileoffset = off;
                        node->ref(); // Keep a reference to the file.
                    }
                } else if (NFS::VFS::S_ISCHR(nodeattr.st_mode)) {
                    // Character devices fall through to implementation-specific mapping.

                    NMem::Virt::vmanode *vma = space->vmaspace->findcontaining((uintptr_t)addr);
                    if (vma) {
                        vma->backingfile = node;
                        vma->fileoffset = off;
                        vma->flags |= NMem::Virt::VIRT_CHRSPECIAL;
                    } else {
                        node->unref();
                        filedesc->unref();
                        space->vmaspace->free(addr, size);
                        SYSCALL_RET(-EINVAL);
                    }

                    int ret = node->mmap(addr, size, off, vmaflags, fdflags);
                    if (ret < 0) {
                        node->unref();
                        filedesc->unref();
                        space->vmaspace->free(addr, size);
                        SYSCALL_RET(ret);
                    }
                } else {
                    // Unsupported file type for mapping.
                    node->unref();
                    filedesc->unref();
                    space->vmaspace->free(addr, size);
                    SYSCALL_RET(-EINVAL);
                }

                filedesc->unref();
                node->unref();
            }

            SYSCALL_RET((uint64_t)addr);
        }

        extern "C" uint64_t sys_munmap(void *ptr, size_t size) {
            SYSCALL_LOG("sys_munmap(%p, %lu).\n", ptr, size);

            if ((uintptr_t)ptr % PAGESIZE != 0 || size == 0) {
                SYSCALL_RET(-EINVAL);
            }

            size = NLib::alignup(size, PAGESIZE);

            struct CPU::cpulocal *cpu = CPU::get();
            NSched::Thread *thread = cpu->currthread;
            NSched::Process *proc = thread->process;
            struct addrspace *space = proc->addrspace;

            NLib::ScopeIRQSpinlock guard(&space->lock);

            // Check if this is a file-backed mapping.
            NMem::Virt::vmanode *vma = space->vmaspace->findcontaining((uintptr_t)ptr);
            NFS::VFS::INode *backingfile = NULL;
            off_t fileoffset = 0;
            uintptr_t vmastart = 0;
            bool ischrspecial = false;

            if (vma && vma->used && vma->backingfile) {
                backingfile = vma->backingfile;
                fileoffset = vma->fileoffset;
                vmastart = vma->start;
                ischrspecial = (vma->flags & NMem::Virt::VIRT_CHRSPECIAL) != 0;
            }

            if (ischrspecial && (vma->flags & NMem::Virt::VIRT_SHARED)) {
                // Inform underlying character special file of unmap.
                // XXX: Pass fdflags.
                ssize_t ret = vma->backingfile->munmap(ptr, size, fileoffset, 0);
                if (ret < 0) {
                    SYSCALL_RET(ret);
                }
                goto nophys;
            }

            // Shared mapping doesn't have its own copy, so we need to write back dirty pages.
            if (backingfile && (vma->flags & NMem::Virt::VIRT_SHARED)) {
                for (size_t i = 0; i < size; i += PAGESIZE) {
                    uintptr_t pageaddr = (uintptr_t)ptr + i;
                    uint64_t *pte = _resolvepte(space, pageaddr);
                    if (pte && (*pte & PRESENT) && (*pte & DIRTY)) {
                        off_t fileoff = fileoffset + (pageaddr - vmastart);
                        void *phys = (void *)(*pte & ADDRMASK);
                        backingfile->write(hhdmoff(phys), PAGESIZE, fileoff, 0);
                    }
                }
            }

            // Free physical pages before unmapping
            for (size_t i = 0; i < size; i += PAGESIZE) {
                uint64_t *pte = _resolvepte(space, (uintptr_t)ptr + i);
                if (pte && (*pte & PRESENT)) {
                    void *phys = (void *)(*pte & ADDRMASK);
                    PMM::free(phys, PAGESIZE);
                }
            }
nophys: // Jump label to skip unmapping physical pages for character special files.

            _unmaprange(space, (uintptr_t)ptr, size);

            // Unref the backing file if present before freeing VMA.
            if (backingfile) {
                backingfile->unref();
            }

            space->vmaspace->free(ptr, size);

            SYSCALL_RET(0);
        }

        extern "C" uint64_t sys_mprotect(void *ptr, size_t size, int prot) {
            SYSCALL_LOG("sys_mprotect(%p, %lu, %d).\n", ptr, size, prot);

            if ((uintptr_t)ptr % PAGESIZE != 0 || size == 0) {
                SYSCALL_RET(-EINVAL);
            }

            size = NLib::alignup(size, PAGESIZE);

            struct CPU::cpulocal *cpu = CPU::get();
            NSched::Thread *thread = cpu->currthread;
            NSched::Process *proc = thread->process;
            struct addrspace *space = proc->addrspace;

            NLib::ScopeIRQSpinlock guard(&space->lock);

            uint64_t vmaflags = prottovma(prot);

            // Update VMA flags for specified range.
            space->vmaspace->protect((uintptr_t)ptr, (uintptr_t)ptr + size, vmaflags);

            for (size_t i = 0; i < size; i += PAGESIZE) {
                uint64_t *pte = _resolvepte(space, (uintptr_t)ptr + i);
                if (pte && (*pte & PRESENT)) {
                    uint64_t phys = *pte & ADDRMASK;
                    uint64_t newflags = prottovmm(prot);
                    *pte = phys | newflags;
                    doshootdown(CPU::TLBSHOOTDOWN_SINGLE, (uintptr_t)ptr + i, (uintptr_t)ptr + i + PAGESIZE);
                }
            }

            SYSCALL_RET(0);
        }

        extern "C" uint64_t sys_msync(void *ptr, size_t size, int flags) {
            SYSCALL_LOG("sys_msync(%p, %lu, %d).\n", ptr, size, flags);

            if ((uintptr_t)ptr % PAGESIZE != 0) {
                SYSCALL_RET(-EINVAL);
            }

            if (size == 0) {
                SYSCALL_RET(0); // Nothing to sync.
            }

            size = NLib::alignup(size, PAGESIZE);

            struct CPU::cpulocal *cpu = CPU::get();
            NSched::Thread *thread = cpu->currthread;
            NSched::Process *proc = thread->process;
            struct addrspace *space = proc->addrspace;

            NLib::ScopeIRQSpinlock guard(&space->lock);

            // Find the VMA containing this range.
            NMem::Virt::vmanode *vma = space->vmaspace->findcontaining((uintptr_t)ptr);
            if (!vma || !vma->used) {
                SYSCALL_RET(-ENOMEM);
            }

            // Only file-backed shared mappings need writeback.
            if (!vma->backingfile || !(vma->flags & NMem::Virt::VIRT_SHARED) || (vma->flags & NMem::Virt::VIRT_CHRSPECIAL)) {
                SYSCALL_RET(0); // Anonymous or private mapping, nothing to do.
            }

            // Write back dirty pages to the file.
            for (size_t i = 0; i < size; i += PAGESIZE) {
                uintptr_t pageaddr = (uintptr_t)ptr + i;
                if (pageaddr >= vma->end) {
                    break; // Past end of VMA.
                }

                uint64_t *pte = _resolvepte(space, pageaddr);
                if (!pte || !(*pte & PRESENT)) {
                    continue; // Page not present, nothing to sync.
                }

                if (*pte & DIRTY) { // Writeback dirty pages.
                    off_t fileoff = vma->fileoffset + (pageaddr - vma->start);

                    void *phys = (void *)(*pte & ADDRMASK);

                    // Write page data back to file.
                    ssize_t nwritten = vma->backingfile->write(hhdmoff(phys), PAGESIZE, fileoff, 0);
                    if (nwritten < 0) {
                        SYSCALL_RET(nwritten); // Return error.
                    }

                    // Clear dirty bit.
                    *pte &= ~DIRTY;
                    doshootdown(CPU::TLBSHOOTDOWN_SINGLE, pageaddr, pageaddr + PAGESIZE);
                }
            }

            SYSCALL_RET(0);
        }

        void setup(void) {

            kspace.pml4 = (struct pagetable *)PMM::alloc(PAGESIZE);
            assert(kspace.pml4 != NULL, "Failed to allocate top level page for kernel address space.\n");

            kspace.pml4phy = (uintptr_t)kspace.pml4;
            kspace.pml4 = (struct pagetable *)hhdmoff(kspace.pml4);
            NLib::memset(kspace.pml4, 0, PAGESIZE); // Blank page.

            kspace.vmaspace = new NMem::Virt::VMASpace(0xffff800000000000, 0xffffffffffffffff);
            kspace.vmaspace->reserve(0xffff800000000000, 0xffff800000001000, 0); // Reserve NULL page, otherwise, this region will end up being allocated at some point.


            for (size_t i = 256; i < 512; i++) {
                uint64_t *entry = (uint64_t *)PMM::alloc(PAGESIZE);
                assert(entry != NULL, "Failed to allocate intermediate entries.\n");
                NLib::memset(hhdmoff(entry), 0, PAGESIZE);
                kspace.pml4->entries[i] = (uint64_t)entry | PRESENT | WRITEABLE;
            }

            // Map entire memory range:
            for (size_t i = 0; i < NLimine::mmreq.response->entry_count; i++) {
                struct limine_memmap_entry *entry = NLimine::mmreq.response->entries[i];
                // For every actually useful bit of memory.
                if (entry->type == LIMINE_MEMMAP_USABLE ||
                    entry->type == LIMINE_MEMMAP_FRAMEBUFFER ||
                    entry->type == LIMINE_MEMMAP_BOOTLOADER_RECLAIMABLE ||
                    entry->type == LIMINE_MEMMAP_EXECUTABLE_AND_MODULES) {

                    // Map entire region.
                    uintptr_t virt = (uintptr_t)hhdmoff((void *)entry->base);
                    // Reserve the region, so the VMA doesn't try to allocate over the HHDM (only reserved/completely unused regions will be available!).
                    kspace.vmaspace->reserve(virt, virt + entry->length, NMem::Virt::VIRT_RW | NMem::Virt::VIRT_NX | NMem::Virt::VIRT_USER); // Reserve this range.
                    maprange(&kspace, virt, entry->base, NOEXEC | WRITEABLE | PRESENT, entry->length);
                }
            }

            // Map executable section of kernel:
            mapkernel(&_text_start, &_text_end, 0 | PRESENT); // Read-only + Executable.
            mapkernel(&_data_start, &_data_end, 0 | WRITEABLE | NOEXEC | PRESENT); // R/W + Not executable.
            mapkernel(&_rodata_start, &_rodata_end, 0 | NOEXEC | PRESENT); // Read-only + Not executable.

            uint64_t efer = 0;
            // Read EFER CPU register from 0xc0000080.
            asm volatile("rdmsr" : "=A"(efer) : "c"(CPU::MSREFER));

            efer |= (1 << 11); // Flip the Execute Disable Bit Enable bit, to allow NOEXEC pages.

            // Write EFER CPU register into 0xc0000080.
            asm volatile("wrmsr" : : "A"(efer), "c"(CPU::MSREFER));

            asm volatile("mov %0, %%cr3" : : "r"((uint64_t)kspace.pml4phy));
            asm volatile("lfence" : : : "memory");

            NUtil::printf("[arch/x86_64/vmm]: Successfully swapped to kernel page table.\n");

            NUtil::printf("[arch/x86_64/vmm]: VMM initialised.\n");
        }
    }
}
