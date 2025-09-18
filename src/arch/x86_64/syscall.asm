
extern sched_savesysstate
extern signal_checkpending

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
extern sys_ioctl
extern sys_dup
extern sys_dup2
extern sys_gettid
extern sys_getpid
extern sys_getppid
extern sys_getpgid
extern sys_setpgid
extern sys_setsid
extern sys_fork

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
    dq sys_ioctl
    dq sys_dup
    dq sys_dup2
    dq sys_gettid
    dq sys_getpid
    dq sys_getppid
    dq sys_getpgid
    dq sys_setpgid
    dq sys_setsid
    dq sys_fork
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

    ; Build a context struct for pre-system call state.

    push qword 0x1b ; User SS (208)
    push rax ; User RSP. Dump here, so that on exit, we can restore the user stack. (200)
    push r11 ; RFLAGS (stored in r11). (192)
    push qword 0x23 ; User CS (184)
    push rcx ; User RIP. (176)
    push qword 0 ; Zero error. (168)

    push rbp ; (160)

    push qword 0 ; Zero IRQ. (152)

    push rsi ; (144)
    push rdi ; (136)
    push r15 ; (128)
    push r14 ; (120)
    push r13 ; (112)
    push r12 ; (104)
    push qword 0 ; R11 (clobbered) (96)
    push r10 ; (88)
    push r9 ; (80)
    push r8 ; (72)
    push rdx ; (64)
    push qword 0 ; RCX (clobbered) (56)
    push rbx ; (48)

    mov rax, [gs:0x8] ; Restore system call number.
    push rax ; (40)

    mov rax, ds
    push rax ; (32)

    mov rax, es
    push rax ; (24)

    mov rax, fs
    push rax ; (16)

    mov rax, gs
    push rax ; (8)

    mov rax, cr2
    push rax ; (0)

    mov ax, 0x10
    mov ds, ax
    mov es, ax

    mov rdi, rsp
    call sched_savesysstate ; Save context before syscall.

    sti
    mov rdi, [rsp + 40] ; RAX, system call number (40 offset in stack).
    cmp rdi, MAXSYSCALLS ; Test system call number against the number of system calls.
    jae .invalid ; If the system call number exceeds the number of system calls, we should return an ENOSYS error code.

    lea rbx, [syscall_table] ; Load table.
    mov rax, [rbx + rdi * 8] ; Load system call table + (call number * 8), that way we can get the RIP for the associated system call.
    test rax, rax ; Check for zero.
    jz .invalid ; If this system call entry has not been set, we jump to invalid handler.

    ; Set up arguments.
    mov rdi, [rsp + 136] ; Retrieve RDI. Argument 1.
    mov rsi, [rsp + 144] ; Retrieve RSI. Argument 2.
    mov rdx, [rsp + 64] ; Retrieve RDX. Argument 3.
    mov rcx, [rsp + 88] ; Retrieve R10 (in place of RCX, as RCX is clobbered by SYSCALL). Argument 4.
    mov r8, [rsp + 72] ; Retrieve R8. Argument 5.
    mov r9, [rsp + 80] ; Retrieve R9. Argument 6.

    call rax ; Call table entry.

    mov [rsp + 40], rax ; Store return value from function (RAX) into RAX's location on the stack. This is so that when we restore the original state later, we set RAX with the return value.
    jmp .done

.invalid:
    mov qword [rsp + 40], -38 ; -38 = -ENOSYS. Correct error number store.

.done:
    cli

    call signal_checkpending

    add rsp, 24 ; Skip segments (we only want ES onwards).

    pop rax
    mov es, rax

    pop rax
    mov ds, rax

    pop rax
    pop rbx
    add rsp, 8 ; Skip RCX
    pop rdx
    pop r8
    pop r9
    pop r10
    add rsp, 8 ; Skip R11
    pop r12
    pop r13
    pop r14
    pop r15

    pop rdi
    pop rsi

    add rsp, 8 ; Skip IRQ

    pop rbp

    add rsp, 8 ; Skip Error

    pop rcx
    add rsp, 8 ; Skip CS.
    pop r11
    pop rsp ; Restore user RSP. We're back!

    swapgs ; Swap back to user GS.
    lfence

    o64 sysret ; Return to user mode.
