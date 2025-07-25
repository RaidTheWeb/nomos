#include <mm/slab.hpp>
#include <util/kprint.hpp>

// C++ Global Constructors.
extern void (*__init_array[])();
extern void (*__init_array_end[])();

extern "C" void *__dso_handle = NULL;
extern "C" int __cxa_atexit(void (*destructor)(void *), void *arg, void *dso) {
    (void)destructor;
    (void)arg;
    (void)dso;
    return 0;
}

namespace NCxx {
    void init(void) {

        // Initialise global constructors.
        // Required to let us initialise classes outside of stack-based scopes, such as functions.
        for (size_t i = 0; &__init_array[i] != __init_array_end; i++) {
            // Call the constructor for every globally defined class variable.
            __init_array[i]();
        }
    }
}
