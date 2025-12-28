#ifndef _SYS__RANDOM_HPP
#define _SYS__RANDOM_HPP

#ifdef __x86_64__
#include <arch/x86_64/sync.hpp>
#endif
#include <lib/list.hpp>
#include <sched/event.hpp>
#include <std/stddef.h>
#include <stdint.h>

#define GRND_NONBLOCK   0x0001  // Don't block if entropy pool not ready.
#define GRND_RANDOM     0x0002  // Use /dev/random (blocking) source.
#define GRND_INSECURE   0x0004  // Ignore entropy pool state (non-blocking, weaker).

namespace NSys {
    namespace Random {

        // XXX: Not exactly cryptographically sound, but pretty okay.

        // Per-CPU entropy pool using ChaCha20 (RFC 8439).
        class EntropyPool {
            private:
                NArch::IRQSpinlock lock;
                NLib::CircularBuffer<uint8_t> pool;

                volatile size_t entropybits; // Amount of entropy in bits. Accessed atomically.

                uint32_t chacha20state[16]; // ChaCha20 state.
                uint8_t keystream[64]; // Current keystream block.
                size_t keystreampos; // Current position in keystream.

                bool initialised = false;

                // Wait queue for threads waiting for random data.
                NSched::WaitQueue wq;
            public:
                EntropyPool(void);

                // I'd like to establish the "entropy" estimations here:
                // - RDRAND provides ~0.5 bits of entropy per byte.
                // - RDSEED provides ~4 bits of entropy per byte.
                // - Keyboard/mouse input provides 4 bits of entropy per event (human input variance is pretty good).
                // - Block I/O timings provide 1 bit of entropy.
                // - Interrupt timings provide 1 bit of entropy (pretty crap, considering how often timings will be near-exactly the quantum deadline).

                // Mix entropy into pool. Bits varies based on how good the entropy is, poorer sources contribute less.
                void addentropy(const uint8_t *data, size_t len, size_t bits);

                // Pulls out random data from the pool. Blocks if insufficient entropy is available and blocking=true.
                ssize_t getrandom(uint8_t *buf, size_t len, bool blocking, bool randomsource);

                // Reseed the ChaCha20 state from the pool.
                void reseed(void);
        };

        void init(void);
    }
}

#endif