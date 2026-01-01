#ifndef _LIB__SYNC_HPP
#define _LIB__SYNC_HPP

#ifdef __x86_64__
#include <arch/x86_64/sync.hpp>
#endif
#include <util/kprint.hpp>

namespace NSched {
    void yield(void);
}

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

    class ScopeIRQSpinlock {
        private:
            NArch::IRQSpinlock *lock;
        public:
            ScopeIRQSpinlock(NArch::IRQSpinlock *lock) {
                this->lock = lock;
                this->lock->acquire();
            }

            ~ScopeIRQSpinlock(void) {
                this->lock->release();
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

    // Bog-standard readers-writer "mutex" implementation. Handles the sleeping of threads under contention.
    class RWLock {
        private:
            static const uint32_t WRITER_BIT = 0x80000000;
            volatile uint32_t state = 0;  // Combined reader count + writer active bit
            volatile uint32_t writers = 0; // Pending writer count
        public:
            RWLock(void) {}

            void readacquire(void) {
                size_t spins = 0;
                while (true) {
                    // Wait while there are pending or active writers
                    while (__atomic_load_n(&this->writers, memory_order_seq_cst) > 0 ||
                           (__atomic_load_n(&this->state, memory_order_seq_cst) & WRITER_BIT)) {
                        if (++spins > 100) {
                            NSched::yield();
                            spins = 0;
                        } else {
                            asm volatile("pause");
                        }
                    }

                    // Try to increment reader count atomically
                    uint32_t oldstate = __atomic_load_n(&this->state, memory_order_acquire);
                    if (oldstate & WRITER_BIT) {
                        continue; // Writer became active, retry
                    }
                    if (__atomic_compare_exchange_n(&this->state, &oldstate, oldstate + 1, false, memory_order_acq_rel, memory_order_acquire)) {
                        break; // Successfully acquired read lock
                    }
                }
            }

            void readrelease(void) {
                __atomic_fetch_sub(&this->state, 1, memory_order_seq_cst);
            }

            void writeacquire(void) {
                // Signal intent to write (blocks new readers)
                __atomic_fetch_add(&this->writers, 1, memory_order_seq_cst);

                size_t spins = 0;
                while (true) {
                    // Wait for all readers to drain and no active writer
                    uint32_t oldstate = __atomic_load_n(&this->state, memory_order_acquire);
                    while (oldstate != 0) {
                        if (++spins > 100) {
                            NSched::yield();
                            spins = 0;
                        } else {
                            asm volatile("pause");
                        }
                        oldstate = __atomic_load_n(&this->state, memory_order_acquire);
                    }

                    // Try to set writer bit atomically
                    if (__atomic_compare_exchange_n(&this->state, &oldstate, WRITER_BIT, false, memory_order_acq_rel, memory_order_acquire)) {
                        // Successfully acquired write lock
                        __atomic_fetch_sub(&this->writers, 1, memory_order_seq_cst);
                        break;
                    }
                }
            }

            void writerelease(void) {
                __atomic_store_n(&this->state, 0, memory_order_seq_cst);
            }
    };



    class ScopeReadLock {
        private:
            RWLock *rwlock;
        public:
            ScopeReadLock(RWLock *rwlock) {
                this->rwlock = rwlock;
                this->rwlock->readacquire();
            }

            ~ScopeReadLock(void) {
                this->rwlock->readrelease();
            }
    };

    class ScopeWriteLock {
        private:
            RWLock *rwlock;
        public:
            ScopeWriteLock(RWLock *rwlock) {
                this->rwlock = rwlock;
                this->rwlock->writeacquire();
            }

            ~ScopeWriteLock(void) {
                this->rwlock->writerelease();
            }
    };
}

#endif
