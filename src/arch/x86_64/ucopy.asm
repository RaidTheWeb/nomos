section .text

global __ucopyfrom
global __ucopyto
global __ustrlen
global __umemset

; Fault tolerant copy from user space to kernel space.
__ucopyfrom:
    test rdx, rdx ; Check for zero size.
    jz .copydone

    ; Set up for rep movsb.
    mov rcx, rdx ; size (count for rep).
    ; rsi and rdi are already set up as source and destination.
.Lfromfault: ; Point where a fault can occur.
    rep movsb
.copydone:
    xor rax, rax ; Return 0. Success!
    ret
.fromhandler: ; Fault handler jumps here on fault.
    mov rax, -14 ; -EFAULT
    ret

; Fault tolerant copy from kernel space to user space.
__ucopyto:
    test rdx, rdx ; Check for zero size.
    jz .copydone2
    mov rcx, rdx ; size (count for rep).
    ; rsi and rdi are already set up as source and destination.
.Ltofault: ; Point where a fault can occur.
    rep movsb
.copydone2:
    xor rax, rax ; Return 0. Success!
    ret
.tohandler: ; Fault handler jumps here on fault.
    mov rax, -14 ; -EFAULT
    ret

; Fault tolerant strlen for user space strings.
__ustrlen:
    xor rax, rax
    test rsi, rsi
    jz .strlendone
.strlenloop:
    test rsi, rsi
    jz .strlendone
.Lstrlenfault:
    mov cl, [rdi]
    test cl, cl
    jz .strlendone
    inc rdi
    inc rax
    dec rsi
    jmp .strlenloop
.strlendone:
    ret

.strlenhandler:
    mov rax, -14 ; -EFAULT
    ret

; Fault tolerant memset for user space memory.
__umemset:
    test rdx, rdx ; Check for zero size.
    jz .memsetdone

    ; Set up for rep stosb.
    mov rcx, rdx ; size (count for rep).
    ; rdi is already set up for destination.
    mov al, sil ; byte to set is in sil.
.Lmemsetfault: ; Point where a fault can occur.
    rep stosb
.memsetdone:
    xor rax, rax ; Return 0. Success!
    ret
.memsethandler: ; Fault handler jumps here on fault.
    mov rax, -14 ; -EFAULT
    ret

section .faulttable
    ; Fault table entries for user copy functions.
    dq __ucopyfrom.Lfromfault, __ucopyfrom.fromhandler
    dq __ucopyto.Ltofault, __ucopyto.tohandler
    dq __ustrlen.Lstrlenfault, __ustrlen.strlenhandler
    dq __umemset.Lmemsetfault, __umemset.memsethandler