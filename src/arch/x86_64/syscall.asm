
extern sys_exit
extern sys_prctl
extern sys_debug
extern sys_mmap
extern sys_munmap
extern sys_mprotect
extern sys_openat
extern sys_close
extern sys_read
extern sys_write
extern sys_seek

MAXSYSCALLS equ 256

section .rodata ; This can be in the normal rodata section, because we'll be using kernel maps by the time we want to use it.
syscall_table:
    dq sys_exit
    dq sys_prctl
    dq sys_debug
    dq sys_mmap
    dq sys_munmap
    dq sys_mprotect
    dq sys_openat
    dq sys_close
    dq sys_read
    dq sys_write
    dq sys_seek
    times (MAXSYSCALLS - ($ - syscall_table) / 8) dq 0 ; Pad with zeroes, from last system call to end of the table.


section .text
global syscall_entry
syscall_entry:
    swapgs ; Swap GS, because we need the kernel's view on the GS base.

    mov [gs:0x8], rax ; Save RAX into temp. Yay!

    mov rax, qword [gs:0x0] ; Current thread pointer is at offset 0.
    mov rax, qword [rax + 0] ; Load address of stack top into RAX. It's also at offset 0 in thread pointer, so we don't need anything else.
    xchg rsp, rax ; Swap RAX into RSP, so we're now using the kernel stack, and the user stack sits in the thread's stack top. It'll be swapped back when we exit the system call.

    ; RAX now contains the user stack, and RSP contains the kernel stack.

    push rax ; User RSP. Dump here, so that on exit, we can restore the user stack.
    push r11 ; RFLAGS (stored in r11).
    push rcx ; User RIP.

    mov rax, [gs:0x8] ; Restore original RAX (containing system call number).
    ; Save original register state, so we can use later.
    push rax ; System call number (for indexing into table). (96)

    push rdi ; (88)
    push rsi ; (80)
    push rdx ; (72)
    push r8 ; (64)
    push r9 ; (56)
    push r10 ; (48)
    push rbx ; (40)
    push rbp ; (32)
    push r12 ; (24)
    push r13 ; (16)
    push r14 ; (8)
    push r15 ; (0)

    ; Load kernel data. SYSCALL already loads kernel code for us, but we need to load kernel data ourselves.
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    ; GS has already been set by SWAPGS.

    mov rdi, [rsp + 96] ; RAX, system call number (96 offset in stack).
    cmp rdi, MAXSYSCALLS ; Test system call number against the number of system calls.
    jae .invalid ; If the system call number exceeds the number of system calls, we should return an ENOSYS error code.

    lea rbx, [syscall_table] ; Load table.
    mov rax, [rbx + rdi * 8] ; Load system call table + (call number * 8), that way we can get the RIP for the associated system call.
    test rax, rax ; Check for zero.
    jz .invalid ; If this system call entry has not been set, we jump to invalid handler.

    ; Set up arguments.
    mov rdi, [rsp + 88] ; Retrieve RDI. Argument 1.
    mov rsi, [rsp + 80] ; Retrieve RSI. Argument 2.
    mov rdx, [rsp + 72] ; Retrieve RDX. Argument 3.
    mov rcx, [rsp + 48] ; Retrieve R10 (in place of RCX, as RCX is clobbered by SYSCALL). Argument 4.
    mov r8, [rsp + 64] ; Retrieve R8. Argument 5.
    mov r9, [rsp + 56] ; Retrieve R9. Argument 6.

    call rax ; Call table entry.

    mov [rsp + 96], rax ; Store return value from function (RAX) into RAX's location on the stack. This is so that when we restore the original state later, we set RAX with the return value.
    jmp .done

.invalid:
    mov qword [rsp + 96], -38 ; -38 = -ENOSYS. Correct error number store.

.done:
    ; Restore original state.
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    pop r10
    pop r9
    pop r8
    pop rdx
    pop rsi
    pop rdi
    pop rax

    mov rcx, [rsp + 16] ; Grab user RSP.
    xchg rsp, rcx ; Swap back to user stack. RCX now contains the kernel stack

    ; Push frame for transition across to userspace.
    push qword [rcx + 16] ; System call stack (old state).
    push qword [rcx + 8] ; RFLAGS
    push qword [rcx] ; RIP

    swapgs ; Swap back to user GS.

    ; Pop frame off of user stack.
    pop rcx ; RIP
    pop r11 ; Restore RFLAGS.
    pop rsp ; Restore stack.

    o64 sysret ; Return to user mode.
