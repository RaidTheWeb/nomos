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
            volatile uint32_t readers = 0;
            volatile uint32_t writers = 0;
            bool writeractive = false;
        public:
            RWLock(void) {}

            void readacquire(void) {
                size_t spins = 0;
                while (__atomic_load_n(&this->writers, memory_order_seq_cst) > 0 || __atomic_load_n(&this->writeractive, memory_order_seq_cst)) {
                    if (++spins > 100) { // If we spent too long waiting, yield.
                        NSched::yield();
                        spins = 0;
                    } else {
                        asm volatile("pause"); // Start by just pausing, so we can immediately start working after
                    }
                }

                __atomic_fetch_add(&this->readers, 1, memory_order_seq_cst);
            }

            void readrelease(void) {
                __atomic_fetch_sub(&this->readers, 1, memory_order_seq_cst);
            }

            void writeacquire(void) {

                __atomic_fetch_add(&this->writers, 1, memory_order_seq_cst);

                size_t spins = 0;
                while (__atomic_load_n(&this->readers, memory_order_seq_cst) > 0 || __atomic_load_n(&this->writeractive, memory_order_seq_cst)) {
                    if (++spins > 100) { // If we spent too long waiting, yield.
                        NSched::yield();
                        spins = 0;
                    } else {
                        asm volatile("pause"); // Start by just pausing, so we can immediately start working after
                    }
                }

                __atomic_fetch_sub(&this->writers, 1, memory_order_seq_cst);
                __atomic_store_n(&this->writeractive, true, memory_order_seq_cst);
            }

            void writerelease(void) {
                __atomic_store_n(&this->writeractive, false, memory_order_seq_cst);
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
