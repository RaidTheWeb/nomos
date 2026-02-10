#include <arch/x86_64/cpu.hpp>
#include <lib/errno.hpp>
#include <mm/ucopy.hpp>
#include <sys/syscall.hpp>

namespace NArch {
    namespace CPU {

        static struct cpulocal bspinst;

        struct cpulocal *getbsp(void) {
            return &bspinst;
        }

        void savexctx(struct extracontext *ctx) {
            (*ctx).fsbase = rdmsr(MSRFSBASE);
        }

        void savefctx(struct fpucontext *ctx) {
            if (CPU::get()->hasxsave) {
                uint64_t xsavemask = CPU::get()->xsavemask;
                asm volatile(
                    "xsave (%0)"
                    : : "r"(ctx->fpustorage),
                    "a"(xsavemask & 0xffffffff), "d"(xsavemask >> 32)
                );
            } else {
                asm volatile("fxsave %0" : "=m"(ctx->fpustorage));
            }

            ctx->mathused = true;
        }

        void restorexctx(struct extracontext *ctx) {
            wrmsr(MSRFSBASE, ctx->fsbase);
        }

        void restorefctx(struct fpucontext *ctx) {
            if (ctx->mathused) {
                if (CPU::get()->hasxsave) {
                    assert(((uintptr_t)ctx->fpustorage & 0x3f) == 0, "Misaligned region.\n");
                    uint64_t xsavemask = CPU::get()->xsavemask;
                    asm volatile(
                        "xrstor (%0)"
                        : : "r"(ctx->fpustorage), "a"(xsavemask), "d"(xsavemask >> 32)
                    );
                } else {
                    asm volatile("fxrstor %0" : : "m"(ctx->fpustorage));
                }
            }
        }

        extern "C" uint64_t sys_prctl(uint64_t option, uint64_t arg1) {
            switch (option) {
                case 0x1002:
                    if (!arg1) {
                        return -EINVAL;
                    }

                    wrmsr(MSRFSBASE, arg1);
                    return 0;
                default:
                    return -EINVAL;
            }
        }

        extern "C" ssize_t sys_debug(char *text) {
            // XXX: Disable in "production".
            if (!text) {
                return -EFAULT;
            }

            // Validate and get string length from userspace.
            ssize_t textlen = NMem::UserCopy::strnlen(text, 4096); // Max 4KB debug string
            if (textlen < 0) {
                return -EFAULT;
            }

            if (textlen == 0) {
                return 0;
            }

            char *kbuf = new char[textlen + 1];
            if (!kbuf) {
                return -ENOMEM;
            }

            ssize_t ret = NMem::UserCopy::copyfrom(kbuf, text, textlen + 1);
            if (ret < 0) {
                delete[] kbuf;
                return -EFAULT;
            }

            kbuf[textlen] = '\0';
            NUtil::printf("%s\n", kbuf);
            delete[] kbuf;

            return 0;
        }

        // Entrypoint for system calls.
        extern "C" void syscall_entry(void);

        void init(void) {
            CPU::get()->kcr3 = VMM::kspace.pml4phy;
            wrmsr(MSRKGSBASE, 0x01); // We need to initialise this GS base, even if we aren't going to use it (CPU won't be happy).

            uint64_t efer = rdmsr(MSREFER);
            efer |= 1; // Set SYSCALL/SYSRET bit.
            wrmsr(MSREFER, efer);

            uint64_t star = 0;
            star |= (uint64_t)(0x23 - 16) << 48; // AMD64 Architecture Programmer's Manual states that SYSRET CS and SS selectors will be field + 16 for CS. So, We subtract 16 from 0x23 (user code), so that SYSRET plonks us right back into ring 3.
            star |= (uint64_t)(0x08) << 32; // Manual states that the field for SYSCALL CS will be interpreted as is, so we just need to pass in 0x08 (kernel code), to have SYSCALL place us into kernel space for the system call.
            wrmsr(MSRSTAR, star); // Write to STAR register. We overwrite because we really don't care about the 32-bit SYSCALL target EIP within the rest of the register.

            wrmsr(MSRCSTAR, 0); // Zero SYSCALL target RIP for compat-mode. We're using REAL x86_64 SYSCALLs.

            wrmsr(MSRLSTAR, (uint64_t)syscall_entry); // Pass address of system call handler to LSTAR register, so SYSCALL knows where to place us.

            wrmsr(MSRFMASK, 0x200); // The interrupt enable bits should be cleared from RFLAGS before syscall work (prevents interrupts from getting in the way). It'll be restored afterwards.


            uint32_t eax, ebx, ecx, edx;
            asm volatile(
                "cpuid"
                : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
                : "a"(1)
            );

            assert(edx & (1 << 24), "CPU does not support at least FXSAVE/FXRSTOR (required for FPU states).");

            // Enable x87.
            uint64_t cr0 = rdcr0();
            cr0 &= ~((uint64_t)1 << 2); // Clear EM. We don't want x87 emulation.
            cr0 |= (uint64_t)1 << 1; // Set NE.
            wrcr0(cr0);

            asm volatile("fninit"); // Initialise FPU.
            asm volatile("clts");

            // Enable SSE.
            uint64_t cr4 = rdcr4();
            cr4 |= (uint64_t)(1 << 9) | (uint64_t)(1 << 10); // Set OSFXSR and OSXMMEXCPT to enable FPU state work.
            wrcr4(cr4);

            if (ecx & (1 << 26)) { // Check if XSAVE/XRSTOR are supported by the CPU.
                cr4 = rdcr4();
                cr4 |= (uint64_t)1 << 18; // Enable OSXSAVE. Required before XGETBV/XSETBV.
                wrcr4(cr4);

                uint32_t xcr0l, xcr0h;
                // Get current state of XCR0.
                asm volatile("xgetbv" : "=a"(xcr0l), "=d"(xcr0h) : "c"(0) : "memory");

                // Build XSAVE mask out of the CPU's - and our - supported features.

                if (edx & (1 << 0)) { // x87.
                    xcr0l |= (1 << 0);
                }

                if (edx & (1 << 25)) {
                    xcr0l |= (1 << 1);
                }

                if (ecx & (1 << 28)) { // AVX supported.
                    xcr0l |= (1 << 2);
                }

                // Set XCR0 register to enable support for our mask.
                asm volatile("xsetbv" : : "a"(xcr0l), "d"(xcr0h), "c"(0) : "memory");

                asm volatile(
                    "cpuid"
                    : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx) // Acquire XSAVE region size.
                    : "a"(0x0d), "ecx"(0)
                );


                CPU::get()->xsavemask = ((uint64_t)xcr0h << 32) | xcr0l;
                CPU::get()->fpusize = ecx; // ECX contains the FPU size (according to CPU manual). Used by scheduler to lazy allocate for FPU state.
                CPU::get()->hasxsave = true;
                if (CPU::get() == CPU::getbsp()) {
                    NUtil::printf("[arch/x86_64/cpu]: Using XSAVE for FPU states.\n");
                }
            } else { // XSAVE is not supported, we should use legacy mode.
                CPU::get()->fpusize = 512; // Default is 512 bytes.
                CPU::get()->hasxsave = false;
                if (CPU::get() == CPU::getbsp()) {
                    NUtil::printf("[arch/x86_64/cpu]: Using FXSAVE for FPU states.\n");
                }
            }

            if (ecx & (1 << 30)) {
                CPU::get()->hasrdrand = true;
            }

            asm volatile(
                "cpuid"
                : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
                : "a"(7), "c"(0)
            );
            if (ebx & (1 << 18)) {
                CPU::get()->hasrdseed = true;
            }

            // Initialise TLB shootdown generation tracking for this CPU.
            struct cpulocal *local = CPU::get();
            __atomic_store_n(&local->tlbgeneration, 0, memory_order_seq_cst);
        }
    }
}
