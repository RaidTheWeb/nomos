#ifdef __x86_64__
#include <arch/x86_64/cpu.hpp>
#include <arch/x86_64/hpet.hpp>
#include <arch/x86_64/rtc.hpp>
#include <arch/x86_64/tsc.hpp>
#endif

#include <lib/errno.hpp>
#include <lib/sync.hpp>
#include <mm/ucopy.hpp>
#include <std/stddef.h>
#include <sys/clock.hpp>
#include <sys/syscall.hpp>
#include <util/kprint.hpp>

namespace NSys {
    namespace Clock {
        // Get hardware tick count from architecture-specific timer.
        uint64_t Clock::gethdcnt(void) {
#ifdef __x86_64__
            return NArch::TSC::query();
#else
            return 0; // Not implemented for this architecture.
#endif
        }

        // Initialize clock with hardware parameters.
        void Clock::initclock(uint64_t hwfreq, uint64_t hwoffset) {
            NLib::ScopeIRQSpinlock guard(&this->lock);
            this->freq = hwfreq;
            this->baseoffset = hwoffset;
            this->basetime.tv_sec = 0;
            this->basetime.tv_nsec = 0;
        }

        Clock::Clock(uint64_t id, enum setperm permission) {
            this->id = id;
            this->permissions = permission;
            this->freq = 0;
            this->baseoffset = 0;
            this->basetime.tv_sec = 0;
            this->basetime.tv_nsec = 0;
        }

        // Realtime clock implementation.
        class RealtimeClock : public Clock {
            public:
                RealtimeClock(uint64_t id, enum setperm permission = CLOCK_ROOT) : Clock(id, permission) { }

                int settime(struct timespec *ts) override {
                    if (this->permissions == CLOCK_NOONE) {
                        return -EPERM;
                    }

                    NLib::ScopeIRQSpinlock guard(&this->lock);

                    // Update base time and reset offset to current hardware count.
                    this->basetime.tv_sec = ts->tv_sec;
                    this->basetime.tv_nsec = ts->tv_nsec;
                    this->baseoffset = this->gethdcnt();

                    return 0;
                }

                int gettime(struct timespec *ts) override {
                    uint64_t now = this->gethdcnt();
                    NLib::ScopeIRQSpinlock guard(&this->lock);

                    if (this->freq == 0) {
                        return -EINVAL; // Clock not initialized.
                    }

                    uint64_t elapsedticks = now - this->baseoffset;
                    uint64_t elapsedsec = elapsedticks / this->freq;
                    uint64_t elapsednsec = ((elapsedticks % this->freq) * NSEC_PER_SEC) / this->freq;

                    ts->tv_sec = this->basetime.tv_sec + (long)elapsedsec;
                    ts->tv_nsec = this->basetime.tv_nsec + (long)elapsednsec;

                    // Handle nanosecond overflow/underflow.
                    while (ts->tv_nsec >= (long)NSEC_PER_SEC) {
                        ts->tv_sec += 1;
                        ts->tv_nsec -= NSEC_PER_SEC;
                    }
                    while (ts->tv_nsec < 0) {
                        ts->tv_sec -= 1;
                        ts->tv_nsec += NSEC_PER_SEC;
                    }

                    return 0;
                }

                int getres(struct timespec *ts) override {
                    NLib::ScopeIRQSpinlock guard(&this->lock);

                    if (this->freq == 0) {
                        return -EINVAL;
                    }

                    ts->tv_sec = 0;
                    ts->tv_nsec = NSEC_PER_SEC / this->freq;
                    return 0;
                }
        };

        // Monotonic clock implementation.
        class MonotonicClock : public Clock {
            public:
                MonotonicClock(uint64_t id, enum setperm permission = CLOCK_NOONE) : Clock(id, permission) { }

                int settime(struct timespec *ts) override {
                    (void)ts;
                    return -EPERM; // Monotonic clocks cannot be set.
                }

                int gettime(struct timespec *ts) override {
                    uint64_t now = this->gethdcnt();
                    NLib::ScopeIRQSpinlock guard(&this->lock);

                    if (this->freq == 0) {
                        return -EINVAL; // Clock not initialized.
                    }

                    uint64_t elapsedticks = now - this->baseoffset;
                    uint64_t elapsedsec = elapsedticks / this->freq;
                    uint64_t elapsednsec = ((elapsedticks % this->freq) * NSEC_PER_SEC) / this->freq;

                    ts->tv_sec = elapsedsec;
                    ts->tv_nsec = elapsednsec;

                    return 0;
                }

                int getres(struct timespec *ts) override {
                    NLib::ScopeIRQSpinlock guard(&this->lock);

                    if (this->freq == 0) {
                        return -EINVAL;
                    }

                    ts->tv_sec = 0;
                    ts->tv_nsec = NSEC_PER_SEC / this->freq;
                    return 0;
                }
        };

        // Process CPU time clock (stub implementation).
        class ProcessCPUTimeClock : public Clock {
            public:
                ProcessCPUTimeClock(uint64_t id, enum setperm permission = CLOCK_NOONE) : Clock(id, permission) { }

                int settime(struct timespec *ts) override {
                    (void)ts;
                    return -EPERM;
                }

                int gettime(struct timespec *ts) override {
                    (void)ts;
                    return -ENOSYS; // Not yet implemented.
                }

                int getres(struct timespec *ts) override {
                    (void)ts;
                    return -ENOSYS;
                }
        };

        // Thread CPU time clock (stub implementation).
        class ThreadCPUTimeClock : public Clock {
            public:
                ThreadCPUTimeClock(uint64_t id, enum setperm permission = CLOCK_NOONE) : Clock(id, permission) { }

                int settime(struct timespec *ts) override {
                    (void)ts;
                    return -EPERM;
                }

                int gettime(struct timespec *ts) override {
                    (void)ts;
                    return -ENOSYS; // Not yet implemented.
                }

                int getres(struct timespec *ts) override {
                    (void)ts;
                    return -ENOSYS;
                }
        };

        // Global clock instances.
        static RealtimeClock realtimeclock(CLOCK_REALTIME, CLOCK_ROOT);
        static MonotonicClock monotonicclock(CLOCK_MONOTONIC, CLOCK_NOONE);
        static ProcessCPUTimeClock processclock(CLOCK_PROCESS_CPUTIME_ID, CLOCK_NOONE); // XXX: Calculate (add delta in schedule()).
        static ThreadCPUTimeClock threadclock(CLOCK_THREAD_CPUTIME_ID, CLOCK_NOONE); // XXX: Calculate (add delta in schedule()).
        static MonotonicClock rawclock(CLOCK_MONOTONIC_RAW, CLOCK_NOONE); // XXX: Don't process.
        static RealtimeClock coarserealtimeclock(CLOCK_REALTIME_COARSE, CLOCK_ROOT);
        static MonotonicClock coarsemonotonicclock(CLOCK_MONOTONIC_COARSE, CLOCK_NOONE);
        static MonotonicClock boottimeclock(CLOCK_BOOTTIME, CLOCK_NOONE); // XXX: Make suspend-aware (obviously, only when we have suspension).

        // Clock table for lookup.
        static Clock *clocktable[CLOCK_MAX] = {
            &realtimeclock,
            &monotonicclock,
            &processclock,
            &threadclock,
            &rawclock,
            &coarserealtimeclock,
            &coarsemonotonicclock,
            &boottimeclock
        };

        // Get clock by ID.
        Clock *getclock(enum id clockid) {
            if (clockid >= CLOCK_MAX) {
                return NULL;
            }
            return clocktable[clockid];
        }

        void init(void) {
#ifdef __x86_64__
            // Ensure TSC is calibrated before initializing clocks.
            if (NArch::TSC::hz == 0) {
                NUtil::printf("[sys/clock]: Warning - TSC not calibrated, cannot initialize clocks.\n");
                return;
            }

            uint64_t tscfreq = NArch::TSC::hz;
            uint64_t tscnow = NArch::TSC::query();

            // Initialize all monotonic clocks with TSC parameters.
            monotonicclock.initclock(tscfreq, tscnow);
            rawclock.initclock(tscfreq, tscnow);
            coarsemonotonicclock.initclock(tscfreq, tscnow);
            boottimeclock.initclock(tscfreq, tscnow);

            // Initialize realtime clocks with TSC parameters.
            realtimeclock.initclock(tscfreq, tscnow);
            struct timespec ts = { 0, 0 };
            int rtcres = NArch::RTC::gettime(&ts);
            if (rtcres == 0 && (ts.tv_sec != 0 || ts.tv_nsec != 0)) {
                realtimeclock.settime(&ts);
            } else {
                NUtil::printf("[sys/clock]: RTC not available (error %d), starting from epoch.\n", rtcres);
            }
            coarserealtimeclock.initclock(tscfreq, tscnow);

            NUtil::printf("[sys/clock]: Clock subsystem initialized with TSC frequency %lu Hz.\n", tscfreq);
#else
            NUtil::printf("[sys/clock]: Clock subsystem initialized (no hardware support).\n");
#endif
        }

        enum clockop {
            CLOCK_GETRES = 0,
            CLOCK_GET = 1,
            CLOCK_SET = 2
        };

        extern "C" int sys_clock(int clockop, enum id id, struct timespec *ts) {
            SYSCALL_LOG("sys_clock(%d, %d, %p).\n", clockop, id, ts);
            Clock *clk = getclock(id);
            if (!clk) {
                SYSCALL_RET(-EINVAL);
            }

            struct timespec kts;
            ssize_t res = NMem::UserCopy::copyfrom(&kts, ts, sizeof(struct timespec));
            if (res < 0) {
                SYSCALL_RET(-EFAULT);
            }

            switch (clockop) {
                case CLOCK_GETRES:
                    res = clk->getres(&kts);
                    break;
                case CLOCK_GET:
                    res = clk->gettime(&kts);
                    break;
                case CLOCK_SET:
                    res = clk->settime(&kts);
                    break;
                default:
                    res = -EINVAL;
                    break;
            }


            if (res < 0) {
                SYSCALL_RET(res);
            }

            res = NMem::UserCopy::copyto(ts, &kts, sizeof(struct timespec));

            SYSCALL_RET(res);
        }
    }
}