#include <arch/x86_64/cpu.hpp>
#include <arch/x86_64/kpti.hpp>

namespace NArch {
    namespace CPU {

        static struct CPU::cpulocal bspinst;

        struct cpulocal *getbsp(void) {
            return &bspinst;
        }

        // Entrypoint for system calls.
        extern "C" void syscall_entry(void);
        extern "C" void trampoline_entry(void);

        void init(void) {

            uint64_t efer = rdmsr(MSREFER);
            efer |= 1; // Set SYSCALL/SYSRET bit.
            wrmsr(MSREFER, efer);

            uint64_t star = 0;
            star |= (uint64_t)(0x23 - 16) << 48; // AMD64 Architecture Programmer's Manual states that SYSRET CS and SS selectors will be field + 16 for CS. So, We subtract 16 from 0x23 (user code), so that SYSRET plonks us right back into ring 3.
            star |= (uint64_t)(0x08) << 32; // Manual states that the field for SYSCALL CS will be interpreted as is, so we just need to pass in 0x08 (kernel code), to have SYSCALL place us into kernel space for the system call.
            wrmsr(MSRSTAR, star); // Write to STAR register. We overwrite because we really don't care about the 32-bit SYSCALL target EIP within the rest of the register.

            wrmsr(MSRCSTAR, 0); // Zero SYSCALL target RIP for compat-mode. We're using REAL x86_64 SYSCALLs.


            // Calculate offset for trampoline syscall entry, relative to the trampoline entry (start of trampoline page).
            uintptr_t syscall = (uintptr_t)syscall_entry - (uintptr_t)trampoline_entry;

            // System call entry begins at the start of the page (its file comes before the trampoline).
            wrmsr(MSRLSTAR, (uint64_t)KPTI::TRAMPOLINEVIRT + syscall); // Pass address of system call handler to LSTAR register, so SYSCALL knows where to place us.

            wrmsr(MSRFMASK, 0x200); // The interrupt enable bits should be cleared from RFLAGS post-syscall (prevents interrupts from getting in the way).
        }
    }
}
