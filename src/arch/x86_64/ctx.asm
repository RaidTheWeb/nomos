; Context swap helper functions, these are mostly just the same as the isr.asm thunk helper.

global ctx_swap
ctx_swap:
    cli ; Start by clearing interrupts, so we don't get disrupted.

    mov rsp, rdi ; Dump context into stack, so the iret we do will restore these interrupts.

    add rsp, 24 ; Skip segments (like in isr.asm).

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

    o64 iret ; Go back to where we were before being interrupted.
