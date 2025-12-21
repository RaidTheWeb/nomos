#include <arch/x86_64/stacktrace.hpp>
#include <arch/x86_64/vmm.hpp>
#include <util/kprint.hpp>

namespace NArch {

    // Check if an address looks like a valid kernel address.
    static inline bool isvalidkerneladdr(uint64_t addr) {
        return addr >= 0xffff800000000000ULL && addr < 0xffffffffffffffffULL;
    }

    // Safely validate a frame pointer before dereferencing.
    static inline bool isvalidframeptr(uint64_t rbp) {
        // Frame pointer should be aligned to at least 8 bytes.
        if (rbp & 0x7) {
            return false;
        }

        // Check if it's in a valid kernel address range.
        if (!isvalidkerneladdr(rbp)) {
            return false;
        }

        return true;
    }

    void printstacktrace(void) {
        uint64_t rbp;
        asm volatile("mov %%rbp, %0" : "=r"(rbp));
        printstacktrace(rbp, 0);
    }

    void printstacktrace(uint64_t rbp) {
        printstacktrace(rbp, 0);
    }

    void printstacktrace(uint64_t rbp, uint64_t rip) {
        NUtil::printf("Stack trace:\n");

        // If we have an initial RIP (from exception context), print it first.
        if (rip != 0) {
            NUtil::printf("  [0] %p\n", rip);
        }

        size_t frame = (rip != 0) ? 1 : 0;
        struct stackframe *fp = (struct stackframe *)rbp;

        while (frame < STACKTRACEMAXFRAMES && fp != NULL) {
            // Validate the frame pointer before accessing it.
            if (!isvalidframeptr((uint64_t)fp)) {
                NUtil::printf("  [%lu] <invalid frame pointer: %p>\n", frame, fp);
                break;
            }

            // Read return address from the frame.
            uint64_t retaddr = fp->rip;

            // Check if return address looks valid.
            if (retaddr == 0) {
                // Reached end of stack (null return address).
                break;
            }

            // Print the frame.
            NUtil::printf("  [%lu] %p\n", frame, retaddr);

            // Move to the previous frame.
            struct stackframe *prevfp = fp->rbp;

            // Basic sanity check: prevent infinite loops by ensuring we're moving backwards in the stack.
            if ((uint64_t)prevfp <= (uint64_t)fp && prevfp != NULL) {
                NUtil::printf("  [%lu] <stack frame loop detected>\n", frame + 1);
                break;
            }

            fp = prevfp;
            frame++;
        }

        if (frame >= STACKTRACEMAXFRAMES) {
            NUtil::printf("  ... (truncated after %lu frames)\n", STACKTRACEMAXFRAMES);
        }
    }
}
