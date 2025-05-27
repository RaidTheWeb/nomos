#include <arch/x86_64/arch.hpp>
#include <arch/x86_64/io.hpp>
#include <arch/x86_64/serial.hpp>
#include <lib/assert.hpp>
#include <util/kprint.hpp>

namespace NArch {
    SerialPort serial[8] = { };
    bool serialenabled = false;
    bool serialchecked = false;

    void serial_init(void) {
        serial[0].init(SerialPort::COM1);
    }

    void SerialPort::init(enum port port) {
        this->port = port;

        // Disable interrupts -> So that we can do a full reset.
        outb(this->port + INTEN, 0x00);

        // Enable DLAB mask to let us define baud rate.
        outb(this->port + LINECTL, 0 | LINECTL_DLAB);

        // 38400 baud. (Divisor of 3)
        outb(this->port + LSBAUD, 3);
        outb(this->port + MSBAUD, 0);

        outb(this->port + LINECTL,
            0 | // Reset -> Disables DLAB mask.
            LINECTL_DATA0 | LINECTL_DATA1 // 8-bits.
            // No parity bit set.
            // Stop bit defaults to 1.
        );

        outb(this->port + FIFOCTL,
            0 |
            FIFO_FIFOEN | // Enable FIFO.
            FIFO_CLRTRANS | FIFO_CLRRCV | // Clear FIFO.
            FIFO_TRIGGER7 | FIFO_TRIGGER6 // 14 byte threshold before data interrupt.
        );

        outb(this->port + MODEMCTL,
            0 |
            MODEMCTL_OUT2 | // Enable IRQ.
            MODEMCTL_DTR | MODEMCTL_RTS | // Mark that we're ready to transceive.
            MODEMCTL_LOOP // Enable loopback for test.
        );

        // Send test byte.
        outb(this->port + WRITE, 0xae);

        // Test for test byte.
        assert(inb(this->port + READ) == 0xae, "UART loopback test failed.\n");

        // Disable loopback.
        outb(this->port + MODEMCTL,
            0 |
            MODEMCTL_OUT2 |
            MODEMCTL_DTR | MODEMCTL_RTS
        );
        this->initialised = true;
        NUtil::printf("[serial]: Serial initialised.\n");
        for (size_t i = 0; i < this->backbufferidx; i++) {
            // Dump backbuffer.
            this->write(this->backbuffer[i]);
        }
        NUtil::printf("[serial]: Pre-initialisation backbuffer restored.\n");
    }

    bool SerialPort::poll(void) {
        return inb(this->port + LINESTAT) & 0x01;
    }

    uint8_t SerialPort::read(void) {
        while (!this->poll());

        return inb(this->port + READ);
    }

    bool SerialPort::writeable(void) {
        return inb(this->port + LINESTAT) & LINESTAT_THRE;
    }

    void SerialPort::write(uint8_t data) {
        if (!serialenabled && serialchecked) {
            return;
        }

        if (!this->initialised) {
            this->backbuffer[this->backbufferidx++] = data;
            return;
        }

        while (!this->writeable());

        outb(this->port + WRITE, data);
    }
}
