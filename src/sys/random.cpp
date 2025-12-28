#ifdef __x86_64__
#include <arch/x86_64/cpu.hpp>
#include <arch/x86_64/smp.hpp>
#endif

#include <dev/input/input.hpp>
#include <mm/ucopy.hpp>
#include <std/stdatomic.h>
#include <sys/random.hpp>
#include <sys/syscall.hpp>

namespace NSys {
    namespace Random {
        // Entropy collection from input events.
        static struct NDev::Input::eventhandler handler;

        static void event(uint64_t tmstmp, uint16_t type, uint16_t code, int32_t value) {
            uint8_t data[sizeof(tmstmp) + sizeof(type) + sizeof(code) + sizeof(value)];

            // Pack data in interleaved fashion for slightly better entropy distribution.
            size_t halfsize = sizeof(data) / 2;
            NLib::memcpy(data, &tmstmp, sizeof(tmstmp));
            NLib::memcpy(data + 1, &type, sizeof(type));
            NLib::memcpy(data + halfsize, &code, sizeof(code));
            NLib::memcpy(data + halfsize + 1, &value, sizeof(value));

#ifdef __x86_64__
            NArch::CPU::get()->entropypool->addentropy(data, sizeof(data), 4);

            // Also distribute to one other CPU in round-robin fashion, lower overhead than distributing to all (XXX: Still pretty crap, try input handler load balancing across CPUs?).
            static volatile size_t next_cpu = 0;
            size_t target = __atomic_fetch_add(&next_cpu, 1, memory_order_relaxed) % NArch::SMP::awakecpus;
            if (target != NArch::CPU::get()->id) {
                NArch::SMP::cpulist[target]->entropypool->addentropy(data, sizeof(data), 4);
            }
#endif
        }

        static inline uint32_t rol(uint32_t value, int amount) {
            return (value << amount) | (value >> (32 - amount));
        }

        static inline void quarterround(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d) {
            // According to pseudocode:
            // (a+=b; d^=a; d=rol(d,16); c+=d; b^=c; b=rol(b,12); a+=b; d^=a; d=rol(d,8); c+=d; b^=c; b=rol(b,7))
            // Best I can do.

            *a += *b; *d ^= *a; *d = rol(*d, 16);
            *c += *d; *b ^= *c; *b = rol(*b, 12);
            *a += *b; *d ^= *a; *d = rol(*d, 8);
            *c += *d; *b ^= *c; *b = rol(*b, 7);
        }

        static inline void chacha20block(const uint32_t in[16], uint8_t out[64]) {
            // "Copy input to working state, run 10-double rounds, calling quarterrounds on columns then diagonals, then add original input to working state, serialise to output bytes (little-endian)."
            // Hopefully this is correct.

            uint32_t state[16];
            for (size_t i = 0; i < 16; i++) {
                state[i] = in[i];
            }

            for (size_t i = 0; i < 10; i++) {
                // Column rounds. (constitutes a single round).
                quarterround(&state[0], &state[4], &state[8], &state[12]);
                quarterround(&state[1], &state[5], &state[9], &state[13]);
                quarterround(&state[2], &state[6], &state[10], &state[14]);
                quarterround(&state[3], &state[7], &state[11], &state[15]);

                // Diagonal rounds. (constitutes the other round).
                quarterround(&state[0], &state[5], &state[10], &state[15]);
                quarterround(&state[1], &state[6], &state[11], &state[12]);
                quarterround(&state[2], &state[7], &state[8], &state[13]);
                quarterround(&state[3], &state[4], &state[9], &state[14]);
            }

            for (size_t i = 0; i < 16; i++) {
                state[i] += in[i];
            }

            for (size_t i = 0; i < 16; i++) {
                out[i * 4] = state[i] & 0xFF;
                out[i * 4 + 1] = (state[i] >> 8) & 0xFF;
                out[i * 4 + 2] = (state[i] >> 16) & 0xFF;
                out[i * 4 + 3] = (state[i] >> 24) & 0xFF;
            }
        }

        void EntropyPool::addentropy(const uint8_t *data, size_t len, size_t bits) {
            bool shouldwake = false;

            {
                NLib::ScopeIRQSpinlock guard(&this->lock);

                for (size_t i = 0; i < len; i++) {
                    this->pool.push(data[i]);
                }
                // Increment entropy bits, capped at 4096 * 8 (pool size in bits).
                size_t oldbits = __atomic_load_n(&this->entropybits, memory_order_seq_cst);
                size_t newbits = oldbits + bits;
                if (newbits > this->pool.size() * 8) {
                    newbits = this->pool.size() * 8;
                }
                __atomic_store_n(&this->entropybits, newbits, memory_order_seq_cst);

                if (!this->initialised && newbits >= 256) {
                    this->initialised = true;
                    shouldwake = true;
                }
            }

            if (shouldwake) {
                this->wq.wake();
            }
        }

        void EntropyPool::reseed(void) {
            // Assumes caller holds lock.

            uint8_t key[32];
            NLib::memset(key, 0, sizeof(key));

            for (size_t i = 0; i < this->pool.size(); i++) {
                key[i % 32] ^= this->pool.peek(i); // DO NOT CONSUME.
            }

            // RFC 8439 ChaCha20 state layout:
            // [0-3]: Constants "expand 32-byte k"
            // [4-11]: 256-bit key
            // [12-13]: 64-bit counter
            // [14-15]: 64-bit nonce

            this->chacha20state[0] = 0x61707865; // "expa"
            this->chacha20state[1] = 0x3320646e; // "nd 3"
            this->chacha20state[2] = 0x79622d32; // "2-by"
            this->chacha20state[3] = 0x6b206574; // "te k"

            // Copy key into state [4-11].
            for (size_t i = 0; i < 8; i++) {
                this->chacha20state[4 + i] = key[i * 4] | (key[i * 4 + 1] << 8) | (key[i * 4 + 2] << 16) | (key[i * 4 + 3] << 24);
            }

            // Initialize counter to 0.
            this->chacha20state[12] = 0;
            this->chacha20state[13] = 0;

            // Initialize nonce to 0.
            this->chacha20state[14] = 0;
            this->chacha20state[15] = 0;

            this->keystreampos = 64; // Force generation of new keystream block on next use.

            this->pool.clear(); // Clear pool after reseed.

            // Deduct 256 bits for the cost of reseeding.
            size_t oldbits = __atomic_load_n(&this->entropybits, memory_order_seq_cst);
            size_t newbits = (oldbits > 256) ? (oldbits - 256) : 0;
            __atomic_store_n(&this->entropybits, newbits, memory_order_seq_cst);
        }

        ssize_t EntropyPool::getrandom(uint8_t *buf, size_t len, bool blocking, bool randomsource) {
            NUtil::printf("[sys/random]: getrandom(%p, %lu, %s, %s).\n", buf, len, blocking ? "blocking" : "non-blocking", randomsource ? "random" : "urandom");

            this->lock.acquire();

            // Minimum entropy threshold for blocking reads (128 bits = 16 bytes of true entropy).
            size_t needed = 128;

            if (blocking) {
                // Wait for entropy pool to be initialised and have sufficient entropy.
                int ret;
                waiteventinterruptiblelocked(&this->wq, this->initialised && this->entropybits >= needed, &this->lock, ret);
                if (ret < 0) {
                    this->lock.release();
                    return ret;
                }
            } else {
                // Non-blocking: if pool not initialised, return EAGAIN.
                if (!this->initialised) {
                    this->lock.release();
                    return -EAGAIN;
                }
            }

            size_t maxbytes = len;
            if (randomsource) { // /dev/random source.
                // Limit output to available entropy (1 byte per 8 bits of entropy).
                size_t availbytes = this->entropybits / 8;
                if (availbytes == 0) {
                    if (blocking) {
                        // Wait for at least some entropy.
                        int ret;
                        waiteventinterruptiblelocked(&this->wq, this->entropybits >= 8, &this->lock, ret);
                        if (ret < 0) {
                            this->lock.release();
                            return ret;
                        }
                        availbytes = this->entropybits / 8;
                    } else {
                        this->lock.release();
                        return -EAGAIN;
                    }
                }
                if (availbytes < maxbytes) {
                    maxbytes = availbytes;
                }
                // Cap at 512 bytes per call for /dev/random (Linux semantics).
                if (maxbytes > 512) {
                    maxbytes = 512;
                }
            }

            for (size_t i = 0; i < maxbytes; i++) {
                // Check if we should reseed before generating keystream.
                if (this->keystreampos >= 64 && this->entropybits >= 256) {
                    this->reseed();
                }

                if (this->keystreampos >= 64) {
                    // Regenerate keystream.
                    // Increment counter.
                    this->chacha20state[12]++;
                    if (this->chacha20state[12] == 0) {
                        this->chacha20state[13]++;
                    }
                    chacha20block(this->chacha20state, this->keystream);
                    this->keystreampos = 0;
                }
                buf[i] = this->keystream[this->keystreampos++];
            }

            // For /dev/random, deduct entropy bits for the bytes we returned.
            if (randomsource) {
                size_t deductbits = maxbytes * 8;
                size_t oldbits = __atomic_load_n(&this->entropybits, memory_order_seq_cst);
                size_t newbits = (oldbits > deductbits) ? (oldbits - deductbits) : 0;
                __atomic_store_n(&this->entropybits, newbits, memory_order_seq_cst);
            }

            this->lock.release();
            return maxbytes;
        }

        EntropyPool::EntropyPool() : pool(4096) {
            this->keystreampos = 64; // Force initial reseed.

            // "Nothing up my sleeve" numbers. Sure buddy.
            this->chacha20state[0] = 0x61707865; // "expa"
            this->chacha20state[1] = 0x3320646e; // "nd 3"
            this->chacha20state[2] = 0x79622d32; // "2-by"
            this->chacha20state[3] = 0x6b206574; // "te k"

            for (size_t i = 4; i < 16; i++) {
                this->chacha20state[i] = 0;
            }
            this->initialised = false;
        }

        extern "C" ssize_t sys_getrandom(uint8_t *buf, size_t len, uint32_t flags) {
            SYSCALL_LOG("sys_getrandom(%p, %lu, 0x%X).\n", buf, len, flags);

            const uint32_t validflags = GRND_NONBLOCK | GRND_RANDOM | GRND_INSECURE;
            if (flags & ~validflags) { // Invalid flags.
                SYSCALL_RET(-EINVAL);
            }

            // GRND_INSECURE and GRND_RANDOM are mutually exclusive.
            if ((flags & GRND_INSECURE) && (flags & GRND_RANDOM)) {
                SYSCALL_RET(-EINVAL);
            }

            // Validate buffer address is in userspace.
            if (!NMem::UserCopy::valid(buf, len)) {
                SYSCALL_RET(-EFAULT);
            }

            // Zero-length read is valid and returns 0.
            if (len == 0) {
                SYSCALL_RET(0);
            }

            struct NArch::CPU::cpulocal *cpu = NArch::CPU::get();
            if (!cpu || !cpu->entropypool) {
                SYSCALL_RET(-ENODEV);
            }

            bool blocking = !(flags & (GRND_NONBLOCK | GRND_INSECURE));
            bool randomsource = (flags & GRND_RANDOM) != 0;

            ssize_t ret = cpu->entropypool->getrandom(buf, len, blocking, randomsource);
            SYSCALL_RET(ret);
        }

        void init(void) {

            // Allocate per-CPU entropy pools.

#ifdef __x86_64__
            for (size_t i = 0; i < NArch::SMP::awakecpus; i++) {
                NArch::SMP::cpulist[i]->entropypool = new EntropyPool();
                assert(NArch::SMP::cpulist[i]->entropypool, "Failed to allocate per-CPU entropy pool.\n");
            }

            // Add entropy from RDRAND/RDSEED if supported.
            for (size_t i = 0; i < NArch::SMP::awakecpus; i++) {
                struct NArch::CPU::cpulocal *cpu = NArch::SMP::cpulist[i];
                if (cpu->hasrdseed) { // Prefer RDSEED if available (it has better entropy).
                    uint64_t val;
                    for (size_t i = 0; i < 8; i++) { // Pull 64-bytes at 4 bits of entropy per byte = 256 bits total.
                        assert(NArch::CPU::rdseed(&val), "RDSEED failed to provide entropy.\n");
                        cpu->entropypool->addentropy((uint8_t *)&val, sizeof(val), 32); // 8 bytes * 4 bits/byte = 32 bits.
                    }
                } else if (cpu->hasrdrand) {
                    uint64_t val;
                    for (size_t i = 0; i < 64; i++) { // Pull 512-bytes at 0.5 bits/byte = 256 bits total.
                        assert(NArch::CPU::rdrand(&val), "RDRAND failed to provide entropy.\n");
                        cpu->entropypool->addentropy((uint8_t *)&val, sizeof(val), 4); // 8 bytes * 0.5 bits/byte = 4 bits.
                    }
                }
            }
#endif

            // Subscribe to input events for entropy. Other sources of entropy are handled in their respective subsystems.
            handler.connect = NULL;
            handler.disconnect = NULL;
            handler.evsubscription = NDev::Input::event::KEY; // XXX: As we get new events, they should be crammed into entropy.
            handler.event = event;
            NDev::Input::registerhandler(&handler);
        }
    }
}