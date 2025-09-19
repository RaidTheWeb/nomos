#ifndef _DEV__PCI_HPP
#define _DEV__PCI_HPP

#include <dev/dev.hpp>
#include <stdint.h>

namespace NDev {
    namespace PCI {
        struct bar {
            size_t len;
            uintptr_t base;
            bool mmio;
        };

        uint32_t read(struct devinfo *dev, uint32_t off, int size);
        void write(struct devinfo *dev, uint32_t off, uint32_t val, int size);
        struct bar getbar(struct devinfo *dev, uint8_t idx);
        void unmapbar(struct bar bar);

        void init(void);
    }
}

#endif
