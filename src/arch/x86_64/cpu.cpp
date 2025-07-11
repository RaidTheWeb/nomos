#include <arch/x86_64/cpu.hpp>
#include <lib/errno.hpp>

namespace NArch {
    namespace CPU {

        static struct CPU::cpulocal bspinst;

        struct cpulocal *getbsp(void) {
            return &bspinst;
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

        extern "C" void sys_debug(char *text) {
            NUtil::printf("%s\n", text);
        }

        // Entrypoint for system calls.
        extern "C" void syscall_entry(void);

        void init(void) {
            CPU::get()->kcr3 = VMM::kspace.pml4phy;
            wrmsr(MSRKGSBASE, 0x01);

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


            uint64_t cr0 = rdcr0();
            cr0 &= ~((uint64_t)1 << 2);
            cr0 |= (uint64_t)1 << 1;
            wrcr0(cr0);

            uint64_t cr4 = rdcr4();
            cr4 |= (uint64_t)3 << 9;
            wrcr4(cr4);
        }
    }
}
