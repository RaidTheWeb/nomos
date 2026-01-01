%macro ISR_NOERROR 1
isr_%1:
    push qword 0 ; Dummy error. This interrupt won't add the error itself.

    push rbp ; Save

    mov rbp, %1 ; Put vector here for later.
    jmp isr_common
%endmacro

%macro ISR_ERROR 1
isr_%1:
    push rbp ; Save
    mov rbp, %1 ; Push vector.
    jmp isr_common ; Common handler.
%endmacro

extern isr_handle

; Define stub labels:

%assign i 0
%rep 256 ; Repeat for entirety of ISR table.

%if i <> 8 && i <> 10 && i <> 11 && i <> 12 && i <> 13 && i <> 14 && i <> 17 && i <> 21 && i <> 29 && i <> 30
    ISR_NOERROR i
%else
    ISR_ERROR i
%endif

%assign i i + 1
%endrep

; Generic Handler
isr_common:
    lfence
    test qword [rsp + 24], 0x3 ; Are we in the user code segment?
    jz .kentry ; Interrupt was triggered during kernel code, no need to swap GS.

    push rax

    swapgs
    lfence
    ; mov rax, [gs:0x18] ; Swap to kernel CR3.

    ; mov cr3, rax
    ; lfence

    pop rax

.kentry: ; Coming from kernel space.

    ; Push current context (save!).
    push rbp ; This contains the vector -> as we told it to in the ISR thunk.
    push rsi
    push rdi
    push r15
    push r14
    push r13
    push r12
    push r11
    push r10
    push r9
    push r8
    push rdx
    push rcx
    push rbx
    push rax

    ; Push segments, these needs to be put into intermediary registers first.
    mov rax, ds
    push rax

    mov rax, es
    push rax

    ; Push segments (THESE WILL NOT BE RESTORED)
    mov rax, fs
    push rax

    mov rax, gs
    push rax

    mov rdi, cr2
    push rdi

    mov rdi, 0x10 ; Kernel data segment.

    ; Update segments.
    mov ds, rdi ; Data segment.
    mov es, rdi ; Extra segment.

    mov rdi, rbp ; Move vector in here, so that it's the first argument.
    mov rsi, rsp ; Context is currently stored here in the stack. Second argument.

    cld
    mov rax, isr_handle
    call rax
    cli ; Clear interrupts after we return from the function call.

    add rsp, 24 ; Skip segments.

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

    test qword [rsp + 8], 0x3 ; Are we within the user code segment?
    jz .ret ; We're context switching within the kernel. Remain with current GS.

    push rax

    ; Now we can use RAX again.
    ; Prepare for page table swap back, post-syscall.
    mov rax, [gs:0x0] ; Load current thread pointer.
    mov rax, [rax + 8] ; Load current process pointer.
    mov rax, [rax] ; Load address space pointer.
    mov rax, [rax + 8] ; Load physical PML4 of current thread into temp.

    ; lfence
    ; mov cr3, rax
    swapgs
    lfence

    pop rax
.ret: ; If this is a kernel thread, we're already in the kernel CR3, no work.
    o64 iret ; Go back to where we were before being interrupted.

section .rodata
global isr_table ; Make sure we can access this from C++ files.
isr_table:
    %assign i 0
    %rep 256

    dq isr_%+ i ; Put ISR address into isr_table.

    %assign i i + 1
    %endrep
