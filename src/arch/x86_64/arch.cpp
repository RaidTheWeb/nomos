#include <arch/limine/arch.hpp>
#include <arch/x86_64/arch.hpp>
#include <arch/x86_64/gdt.hpp>
#include <arch/x86_64/interrupts.hpp>
#include <arch/x86_64/serial.hpp>
#include <util/kprint.hpp>

namespace NArch {
    void init(void) {
        NUtil::printf("[arch]: x86_64 init()\n");
        NArch::serial_init();

        NLimine::init();

        GDT gdt = GDT();
        gdt.setup();
        gdt.reload();

        InterruptTable table = InterruptTable();
        table.setup();
        table.reload();


    }
}
