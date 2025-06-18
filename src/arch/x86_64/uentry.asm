global uentry
uentry:

    mov rax, 0

    syscall

eep:
    pause
    jmp eep
    ret
