#include <dev/input/input.hpp>
#include <lib/errno.hpp>
#include <sys/clock.hpp>

namespace NDev {
    namespace Input {

        NLib::DoubleList<Device *> devices = NLib::DoubleList<Device *>();
        NLib::DoubleList<struct eventhandler *> handlers = NLib::DoubleList<struct eventhandler *>();
        NArch::IRQSpinlock devlock;

        enum event::disposition Device::getdispose(uint16_t type, uint16_t *pcode, int32_t *pvalue) {
            int32_t value = *pvalue;
            uint16_t code = *pcode;
            enum event::disposition disposition = event::disposition::IGNORE;

            switch (type) {
                case event::type::SYN: {
                    if (code == sync::REPORT) {
                        disposition = event::disposition::FLUSH;
                    }
                    break;
                }

                case event::type::KEY: {
                    if (this->keybit.test(code)) {
                        disposition = event::disposition::BUFFER;
                    }
                    break;
                }
            }

            *pvalue = value; // Override with any changes.
            *pcode = code; // Override with any changes.

            return disposition;
        }

        void Device::sendtohandler(struct event ev) {
            devlock.acquire();

            NLib::DoubleList<struct eventhandler *>::Iterator it = this->handlers.begin();

            while (it.valid()) {
                (*it.get())->event(ev.tmstmp, ev.type, ev.code, ev.value);
                it.next();
            }

            devlock.release();
        }

        void Device::handle(uint16_t type, uint16_t code, int32_t value) {
            // XXX: We can add event timestamps for entropy to cryptographic random seed!

            enum event::disposition disposition = this->getdispose(type, &code, &value);
            if (disposition == event::disposition::IGNORE) {
                return;
            }

            struct NSys::Clock::timespec ts;
            NSys::Clock::Clock *clk = NSys::Clock::getclock(NSys::Clock::CLOCK_MONOTONIC);
            clk->gettime(&ts);

            if (disposition == event::disposition::DIRECT) {
                struct event ev {
                    .tmstmp = ts.tv_sec * 1000000000ull + ts.tv_nsec,
                    .type = type,
                    .code = code,
                    .value = value
                };
                this->sendtohandler(ev);
            } else if (disposition == event::disposition::BUFFER) {
                struct event ev {
                    .tmstmp = ts.tv_sec * 1000000000ull + ts.tv_nsec,
                    .type = type,
                    .code = code,
                    .value = value
                };

                this->packet.push(ev);
            } else if (disposition == event::disposition::FLUSH) {
                for (size_t i = 0; i < this->packet.getsize(); i++) {
                    this->sendtohandler(this->packet[i]);
                }
                this->packet.clear();
                this->packet.reserve(64);
            }
        }

        void Device::doevent(uint16_t type, uint16_t code, int32_t value) {
            if (this->evsupported & type) { // If we actually support generating this event type, pass it through.

                this->lock.acquire();

                this->handle(type, code, value);
                this->lock.release();
            }
        }

        static bool attachhandler(Device *dev, struct eventhandler *handler) {
            if (dev->evsupported & handler->evsubscription) { // We found a device that supports at least *one* of the events.

                dev->handlers.push(handler);
                if (handler->connect) {
                    return handler->connect(dev, dev->evsupported & handler->evsubscription);
                }
                return true;
            }
            return false;
        }

        int registerdevice(Device *dev) {
            devlock.acquire();

            devices.push(dev); // Register device, so handlers can find it later, if needed.

            dev->evsupported |= event::type::SYN; // All devices should accept basic synchronisation events.

            NLib::DoubleList<struct eventhandler *>::Iterator it = handlers.begin();

            while (it.valid()) {
                attachhandler(dev, *it.get()); // Attempt to connect device to handler now.
                it.next();
            }

            devlock.release();
            return 0;
        }

        int registerhandler(struct eventhandler *handler) {
            devlock.acquire();

            NLib::DoubleList<Device *>::Iterator it = devices.begin();

            size_t count = 0;
            while (it.valid()) {

                if (attachhandler(*it.get(), handler)) { // Attempt to add.
                    count++;
                }

                it.next();
            }

            handlers.push(handler);

            devlock.release();
            return count > 0 ? 0 : -ENODEV; // ENODEV is non-fatal, the device may be added later.
        }
    }
}
