section .text

global __ucopyfrom
global __ucopyto
global __ustrlen
global __umemset

; Fault tolerant copy from user space to kernel space.
__ucopyfrom:
    test rdx, rdx ; Check for zero size.
    jz .copydone
    mov rcx, rdx
.copyloop:
.Lfromfault: ; Point where a fault can occur.
    mov al, [rsi]
    mov [rdi], al
    inc rsi
    inc rdi
    dec rcx
    jnz .copyloop
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
    mov rcx, rdx
.copyloop2:
    mov al, [rsi]
.Ltofault: ; Point where a fault can occur.
    mov [rdi], al
    inc rsi
    inc rdi
    dec rcx
    jnz .copyloop2
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
    mov rcx, rdx
.memsetloop:
.Lmemsetfault: ; Point where a fault can occur.
    mov [rdi], sil
    inc rdi
    dec rcx
    jnz .memsetloop
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