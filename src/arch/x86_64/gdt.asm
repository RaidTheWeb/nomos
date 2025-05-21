global gdt_flush
gdt_flush:
    lgdt [rdi]
    push 0x08
    lea rax, [rel .reloadcs]
    push rax
    retfq

.reloadcs:
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax
    ret
