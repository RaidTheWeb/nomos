#ifndef _SYS__CLOCK_HPP
#define _SYS__CLOCK_HPP

#ifdef __x86_64__
#include <arch/x86_64/sync.hpp>
#endif

#include <stdint.h>

namespace NSys {
    namespace Clock {

        enum id {
            CLOCK_REALTIME = 0,           // System-wide real-time clock.
            CLOCK_MONOTONIC = 1,          // Monotonic clock, counts from clock subsystem initialisation.
            CLOCK_PROCESS_CPUTIME_ID = 2, // Per-process count of CPU-time spent executing.
            CLOCK_THREAD_CPUTIME_ID = 3,  // Per-thread count of CPU-time spent executing.
            CLOCK_MONOTONIC_RAW = 4,      // Monotonic clock, raw hardware ticks.
            CLOCK_REALTIME_COARSE = 5,    // Fast but coarse system-wide real-time clock.
            CLOCK_MONOTONIC_COARSE = 6,   // Fast but coarse monotonic clock.
            CLOCK_BOOTTIME = 7,           // Clock since boot time. XXX: Not suspend-aware.

            CLOCK_MAX = 8
        };

        enum setperm {
            CLOCK_ROOT = 1,   // Clock can only be set by root.
            CLOCK_NOONE = 2   // Clock cannot be set (i.e. CLOCK_MONOTONIC).
        };

        const uint64_t NSEC_PER_SEC = 1000000000;
        const uint64_t USEC_PER_SEC = 1000000;
        const uint64_t MSEC_PER_SEC = 1000;

        struct timespec {
            long tv_sec;  // Seconds.
            long tv_nsec; // Nanoseconds.
        };

        struct timeval {
            long tv_sec;   // Seconds.
            long tv_usec;  // Microseconds.
        };

        class Clock {
            protected:
                NArch::IRQSpinlock lock;
                uint64_t freq;            // Frequency in Hz.
                uint64_t baseoffset;      // Base offset in hardware ticks.
                struct timespec basetime; // Base time for realtime clocks.

            public:
                uint64_t id;
                enum setperm permissions;

                Clock(uint64_t id, enum setperm permission = CLOCK_ROOT);
                virtual ~Clock(void) = default;

                virtual int settime(struct timespec *ts) = 0;
                virtual int gettime(struct timespec *ts) = 0;
                virtual int getres(struct timespec *ts) = 0;

                // Get hardware tick count (architecture-specific).
                uint64_t gethdcnt(void);

                // Initialise clock with hardware frequency and offset.
                void initclock(uint64_t hwfreq, uint64_t hwoffset);
        };

        // Access individual clocks by ID.
        Clock *getclock(enum id clockid);

        void init(void);
    }
}

#endif