


extern "C" void kernel_main(void) {
    for (;;) {
        asm ("hlt");
    }
}
