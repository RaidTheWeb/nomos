#include <arch/x86_64/e9.hpp>

namespace NArch {
    namespace E9 {
        bool enabled = false;

        void puts(const char *str) {
            if (!enabled) {
                return;
            }

            while (*str) {
                outb(0xe9, *str++);
            }
        }


    }
}
