global gdt_flush
gdt_flush:
    lgdt [rdi]

    mov ax, 0x28
    ltr ax

    swapgs
    mov ax, 0
    mov gs, ax
    mov fs, ax
    swapgs
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov ss, ax

    push qword 0x8
    lea rax, [rel .reloadcs]
    push rax
    retfq

.reloadcs:
    ret
