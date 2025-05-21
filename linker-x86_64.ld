OUTPUT_FORMAT(elf64-x86-64)

ENTRY(kernel_main)

/* Define program headers for Limine's MMU permissions. */
PHDRS
{
    text PT_LOAD;
    rodata PT_LOAD;
    data PT_LOAD;
}

SECTIONS
{
    . = 0xffffffff80000000; /* Start at the upper region. */

    text_start = .;
    .text : {
        *(.text .text.*)
    } :text
    . = ALIGN(CONSTANT(MAXPAGESIZE));
    text_end = .;

    rodata_start = .;
    .rodata : {
        *(.rodata .rodata.*)
    } :rodata

    .init_array : {
        __init_array = .;
        KEEP(*(SORT_BY_INIT_PRIORITY(.init_array.*) SORT_BY_INIT_PRIORITY(.ctors.*)))
        KEEP(*(.init_array .ctors))
        __init_array_end = .;
    } :rodata

    . = ALIGN(CONSTANT(MAXPAGESIZE));
    rodata_end = .;

    data_start = .;
    .data : {
        *(.data .data.*)
    } :data

    .bss : {
        *(.bss .bss.*)
        *(COMMON)
    } :data
    . = ALIGN(CONSTANT(MAXPAGESIZE));
    data_end = .;

    /DISCARD/ : {
        *(.eh_frame*)
        *(.note .note.*)
    }
}
