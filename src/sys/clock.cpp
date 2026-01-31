#ifdef __x86_64__
#include <arch/x86_64/cpu.hpp>
#include <arch/x86_64/hpet.hpp>
#include <arch/x86_64/rtc.hpp>
#include <arch/x86_64/tsc.hpp>
#endif

#include <lib/errno.hpp>
#include <lib/sync.hpp>
#include <mm/ucopy.hpp>
#include <sched/sched.hpp>
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
            assert(false, "gethdcnt not implemented on this architecture.");
            return 0; // Not implemented for this architecture.
#endif
        }

        // Initialise clock with hardware parameters.
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
                        return -EINVAL; // Clock not initialised.
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
                        return -EINVAL; // Clock not initialised.
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

        // Process CPU time clock implementation.
        class ProcessCPUTimeClock : public Clock {
            public:
                ProcessCPUTimeClock(uint64_t id, enum setperm permission = CLOCK_NOONE) : Clock(id, permission) { }

                int settime(struct timespec *ts) override {
                    (void)ts;
                    return -EPERM;
                }

                int gettime(struct timespec *ts) override {
#ifdef __x86_64__
                    NSched::Thread *thread = NArch::CPU::get()->currthread;
                    if (!thread || !thread->process) {
                        return -EINVAL;
                    }

                    uint64_t ticks = __atomic_load_n(&thread->process->cputimeticks, memory_order_relaxed);
                    uint64_t freq = NArch::TSC::hz;
                    if (freq == 0) {
                        return -EINVAL;
                    }

                    ts->tv_sec = ticks / freq;
                    ts->tv_nsec = ((ticks % freq) * NSEC_PER_SEC) / freq;
                    return 0;
#else
                    (void)ts;
                    return -ENOSYS;
#endif
                }

                int getres(struct timespec *ts) override {
#ifdef __x86_64__
                    uint64_t freq = NArch::TSC::hz;
                    if (freq == 0) {
                        return -EINVAL;
                    }
                    ts->tv_sec = 0;
                    ts->tv_nsec = NSEC_PER_SEC / freq;
                    return 0;
#else
                    (void)ts;
                    return -ENOSYS;
#endif
                }
        };

        // Thread CPU time clock implementation.
        class ThreadCPUTimeClock : public Clock {
            public:
                ThreadCPUTimeClock(uint64_t id, enum setperm permission = CLOCK_NOONE) : Clock(id, permission) { }

                int settime(struct timespec *ts) override {
                    (void)ts;
                    return -EPERM;
                }

                int gettime(struct timespec *ts) override {
#ifdef __x86_64__
                    NSched::Thread *thread = NArch::CPU::get()->currthread;
                    if (!thread) {
                        return -EINVAL;
                    }

                    uint64_t ticks = __atomic_load_n(&thread->cputimeticks, memory_order_relaxed);
                    uint64_t freq = NArch::TSC::hz;
                    if (freq == 0) {
                        return -EINVAL;
                    }

                    ts->tv_sec = ticks / freq;
                    ts->tv_nsec = ((ticks % freq) * NSEC_PER_SEC) / freq;
                    return 0;
#else
                    (void)ts;
                    return -ENOSYS;
#endif
                }

                int getres(struct timespec *ts) override {
#ifdef __x86_64__
                    uint64_t freq = NArch::TSC::hz;
                    if (freq == 0) {
                        return -EINVAL;
                    }
                    ts->tv_sec = 0;
                    ts->tv_nsec = NSEC_PER_SEC / freq;
                    return 0;
#else
                    (void)ts;
                    return -ENOSYS;
#endif
                }
        };

        // Global clock instances.
        static RealtimeClock realtimeclock(CLOCK_REALTIME, CLOCK_ROOT);
        static MonotonicClock monotonicclock(CLOCK_MONOTONIC, CLOCK_NOONE);
        static ProcessCPUTimeClock processclock(CLOCK_PROCESS_CPUTIME_ID, CLOCK_NOONE);
        static ThreadCPUTimeClock threadclock(CLOCK_THREAD_CPUTIME_ID, CLOCK_NOONE);
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
            // Ensure TSC is calibrated before initialising clocks.
            if (NArch::TSC::hz == 0) {
                NUtil::printf("[sys/clock]: Warning - TSC not calibrated, cannot initialise clocks.\n");
                return;
            }

            uint64_t tscfreq = NArch::TSC::hz;
            uint64_t tscnow = NArch::TSC::query();

            // Initialise all monotonic clocks with TSC parameters.
            monotonicclock.initclock(tscfreq, tscnow);
            rawclock.initclock(tscfreq, tscnow);
            coarsemonotonicclock.initclock(tscfreq, tscnow);
            boottimeclock.initclock(tscfreq, tscnow);

            // Initialise realtime clocks with TSC parameters.
            realtimeclock.initclock(tscfreq, tscnow);
            struct timespec ts = { 0, 0 };
            int rtcres = NArch::RTC::gettime(&ts);
            if (rtcres == 0 && (ts.tv_sec != 0 || ts.tv_nsec != 0)) {
                realtimeclock.settime(&ts);
            } else {
                NUtil::printf("[sys/clock]: RTC not available (error %d), starting from epoch.\n", rtcres);
            }
            coarserealtimeclock.initclock(tscfreq, tscnow);

            NUtil::printf("[sys/clock]: Clock subsystem initialised with TSC frequency %lu Hz.\n", tscfreq);
#else
            NUtil::printf("[sys/clock]: Clock subsystem initialised (no hardware support).\n");
#endif
        }

        enum clockop {
            CLOCK_GETRES = 0,
            CLOCK_GET = 1,
            CLOCK_SET = 2
        };

        extern "C" int sys_clock(int clockop, enum id id, struct timespec *ts) {
            SYSCALL_LOG("sys_clock(%d, %d, %p).\n", clockop, id, ts);

            if (!ts) {
                SYSCALL_RET(-EFAULT);
            }

            Clock *clk = getclock(id);
            if (!clk) {
                SYSCALL_RET(-EINVAL);
            }

            struct timespec kts = {};
            ssize_t res;

            switch (clockop) {
                case CLOCK_GETRES:
                    res = clk->getres(&kts);
                    if (res < 0) {
                        SYSCALL_RET(res);
                    }
                    res = NMem::UserCopy::copyto(ts, &kts, sizeof(struct timespec));
                    SYSCALL_RET(res < 0 ? -EFAULT : 0);
                case CLOCK_GET:
                    res = clk->gettime(&kts);
                    if (res < 0) {
                        SYSCALL_RET(res);
                    }
                    res = NMem::UserCopy::copyto(ts, &kts, sizeof(struct timespec));
                    SYSCALL_RET(res < 0 ? -EFAULT : 0);
                case CLOCK_SET:
                    res = NMem::UserCopy::copyfrom(&kts, ts, sizeof(struct timespec));
                    if (res < 0) {
                        SYSCALL_RET(-EFAULT);
                    }
                    res = clk->settime(&kts);
                    SYSCALL_RET(res);
                default:
                    SYSCALL_RET(-EINVAL);
            }
        }

        // XXX: Only guaranteed millisecond precision, as we convert from timespec to milliseconds.
        extern "C" ssize_t sys_sleep(struct NSys::Clock::timespec *req, struct NSys::Clock::timespec *rem) {
            SYSCALL_LOG("sys_sleep(%p, %p)\n", req, rem);

            if (!req) {
                SYSCALL_RET(-EFAULT);
            }

            // Copy timespec from userspace.
            struct NSys::Clock::timespec kreq;
            if (NMem::UserCopy::copyfrom(&kreq, req, sizeof(struct NSys::Clock::timespec)) < 0) {
                SYSCALL_RET(-EFAULT);
            }

            // Validate timespec.
            if (kreq.tv_sec < 0 || kreq.tv_nsec < 0 || kreq.tv_nsec >= NSys::Clock::NSEC_PER_SEC) {
                SYSCALL_RET(-EINVAL);
            }

            // Convert to milliseconds, rounding up.
            uint64_t ms = (uint64_t)kreq.tv_sec * NSys::Clock::MSEC_PER_SEC;
            uint64_t ns_to_ms = (kreq.tv_nsec + 999999) / 1000000; // Round up nanoseconds to milliseconds.
            ms += ns_to_ms;

            // Record start time if we need to compute remaining time.
            struct NSys::Clock::timespec start_time;
            if (rem) {
                NSys::Clock::Clock *clock = NSys::Clock::getclock(NSys::Clock::CLOCK_MONOTONIC);
                if (clock && clock->gettime(&start_time) < 0) {
                    SYSCALL_RET(-EFAULT);
                }
            }

            // Perform sleep.
            int ret = NSched::sleep(ms);

            // If interrupted and rem is provided, calculate remaining time.
            if (ret == -EINTR && rem) {
                struct NSys::Clock::timespec end_time;
                NSys::Clock::Clock *clock = NSys::Clock::getclock(NSys::Clock::CLOCK_MONOTONIC);
                if (clock && clock->gettime(&end_time) == 0) {
                    // Calculate elapsed time in nanoseconds.
                    uint64_t elapsed_ns = ((uint64_t)end_time.tv_sec * NSys::Clock::NSEC_PER_SEC + (uint64_t)end_time.tv_nsec) -
                                        ((uint64_t)start_time.tv_sec * NSys::Clock::NSEC_PER_SEC + (uint64_t)start_time.tv_nsec);

                    // Calculate requested time in nanoseconds.
                    uint64_t requested_ns = (uint64_t)kreq.tv_sec * NSys::Clock::NSEC_PER_SEC + (uint64_t)kreq.tv_nsec;

                    // Calculate remaining time.
                    uint64_t remaining_ns = (elapsed_ns < requested_ns) ? (requested_ns - elapsed_ns) : 0;

                    struct NSys::Clock::timespec krem;
                    krem.tv_sec = remaining_ns / NSys::Clock::NSEC_PER_SEC;
                    krem.tv_nsec = remaining_ns % NSys::Clock::NSEC_PER_SEC;

                    if (NMem::UserCopy::copyto(rem, &krem, sizeof(struct NSys::Clock::timespec)) < 0) {
                        // If we can't copy the remaining time, we still return -EINTR.
                        // POSIX allows this behavior.
                    }
                }
            }

            SYSCALL_RET(ret);
        }
    }
}