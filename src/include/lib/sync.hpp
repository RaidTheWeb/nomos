#ifndef _LIB__SYNC_HPP
#define _LIB__SYNC_HPP

#ifdef __x86_64__
#include <arch/x86_64/sync.hpp>
#endif
#include <util/kprint.hpp>

namespace NLib {

    class ScopeSpinlock {
        private:
            NArch::Spinlock *spin;
        public:
            ScopeSpinlock(NArch::Spinlock *spin) {
                this->spin = spin;
                this->spin->acquire();
            }

            ~ScopeSpinlock(void) {
                // Release on object destroy (scope end).
                this->spin->release();
            }
    };

    class ScopeMCSSpinlock {
        private:
            NArch::MCSSpinlock *spin;
        public:
            ScopeMCSSpinlock(NArch::MCSSpinlock *spin) {
                this->spin = spin;
                this->spin->acquire();
            }

            ~ScopeMCSSpinlock(void) {
                // Release on object destroy (scope end).
                this->spin->release();
            }
    };
}

#endif
