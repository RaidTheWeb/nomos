#ifndef _DEV__PCI_HPP
#define _DEV__PCI_HPP

#include <dev/dev.hpp>
#include <stdint.h>

namespace NDev {
    namespace PCI {
        uint32_t read(struct devinfo *dev, uint32_t off, int size);
        void write(struct devinfo *dev, uint32_t off, uint32_t val, int size);

        void init(void);
    }
}

#endif
