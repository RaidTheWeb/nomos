; Context swap helper functions, these are mostly just the same as the isr.asm thunk helper.

global trampoline
trampoline:
    dq 0xffffffffff600000

section .trampoline.entry
global trampoline_entry
trampoline_entry:
    swapgs
    mov cr3, rax
    lfence
    mov rax, [rsp + 40]

    o64 iret

section .text

global ctx_swap
ctx_swap:
    cli ; Start by clearing interrupts, so we don't get disrupted.

    mov rsp, rdi ; Dump context into stack, so the iret we do will restore these interrupts.

    add rsp, 24 ; Skip segments + CR2 (like in isr.asm).

    ; Restore context, same as in isr.asm
    ; Start grabbing segments off the stack.
    ; Again, we must dump these into intermediary registers before putting them in the segments.
    pop rax
    mov es, rax

    pop rax
    mov ds, rax

    pop rax
    pop rbx
    pop rcx
    pop rdx
    pop r8
    pop r9
    pop r10
    pop r11
    pop r12
    pop r13
    pop r14
    pop r15

    pop rdi
    pop rsi

    ; Skip vector. This doesn't matter to state restoration, because it was put onto the stack within the handler, NOT the original state.
    add rsp, 8

    pop rbp ; Restore original RBP

    ; Skip error code. Ditto.
    add rsp, 8

    cmp qword [rsp + 8], 0x23 ; Are we within the user code segment?
    jne .ret ; We're context switching within the kernel. Remain with current GS.

    mov [gs:0x8], rsp ; Store RSP.
    mov rsp, [gs:0x18] ; Load user local stack.

    push rax
    mov rax, [gs:0x8] ; Restore old RSP, so we can copy over the context to the scratch stack.

    ; Push IRETQ frame to scratch stack.
    push qword [rax + 32] ; SS
    push qword [rax + 24] ; RSP
    push qword [rax + 16] ; RFLAGS
    push qword [rax + 8] ; CS
    push qword [rax] ; RIP

    ; Now we can use RAX again.
    ; Prepare for page table swap back, post-syscall.
    mov rax, [gs:0x0] ; Load current thread pointer.
    mov rax, [rax + 8] ; Load current process pointer.
    mov rax, [rax] ; Load address space pointer.
    mov rax, [rax + 8] ; Load physical PML4 of current thread into temp.

    jmp [trampoline]
.ret:
    o64 iret ; Go back to where we were before being interrupted.
