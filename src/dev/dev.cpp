#include <dev/dev.hpp>
#include <lib/list.hpp>
#include <lib/sync.hpp>

namespace NDev {
    DeviceRegistry *registry = NULL;

    void setup(void) {
        registry = new DeviceRegistry();
    }
}
