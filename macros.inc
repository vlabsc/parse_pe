macro pushall {
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
}


macro popall {
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
}


macro flushall {
    xor rax, rax
    xor rbx, rbx
    xor rcx, rcx
    xor rdx, rdx
}

macro debugr register
{
    invoke printf, " [ debug register: %d ] ", register
}

macro debugi value
{
    invoke printf, " [ debug integer: %d ] ", value
}

macro debugix value
{
    invoke printf, " [ debug integer: 0x%08x ] ", dword value
}

macro debuga addr
{
    invoke printf, " [ debug address: 0x%x ] ", addr
}

macro debugregsx
{
    pushall
    ;xor rax, rax
    ;mov eax, ebx
    invoke printf, "rax: %x, eax: %x, ax: %x ", rax, eax, word ax
    call print_newline
    flushall
    popall

    pushall
    xor rax, rax
    xor r9, r9
    mov eax, ebx
    invoke printf, "rbx: %x, ebx: %x, bx: %x ", rax, eax, word ax
    call print_newline
    flushall
    popall


    pushall
    xor rax, rax
    xor r9, r9
    mov eax, ecx
    invoke printf, "rcx: %x, ecx: %x, cx: %x ", rax, eax, word ax
    call print_newline
    flushall
    popall

    pushall
    xor rax, rax
    xor r9, r9
    mov eax, edx
    invoke printf, "rdx: %x, edx: %x, dx: %x ", rax, eax, word ax
    call print_newline
    flushall
    popall


    pushall
    xor rax, rax
    xor r9, r9
    mov eax, esi
    invoke printf, "rsi: %x, esi: %x, si: %x ", rsi, esi, si
    call print_newline
    flushall
    popall


    pushall
    xor rax, rax
    xor r9, r9
    mov eax, edi
    invoke printf, "rdi: %x, edi: %x, di: %x ", rdi, edi, di
    call print_newline
    flushall
    popall

    pushall
    flushall
    popall
}


macro debugregsi
{
    invoke printf, "rax: %llu, eax: %u, ax: %u, al: %x, ah: %x", rax, eax, ax, al, ah
    call print_newline
    invoke printf, "rbx: %llu, ebx: %u, bx: %u, bl: %x, bh: %x", rbx, ebx, bx, bl, bh
    call print_newline
    invoke printf, "rcx: %llu, ecx: %u, cx: %u, cl: %x, ch: %x", rcx, ecx, cx, cl, ch
    call print_newline
    invoke printf, "rdx: %llu, edx: %u, dx: %u, dl: %x, dh: %x", rdx, edx, dx, dl, dh
    call print_newline
}

macro debugbreak
{
    ;invoke printf, "breaking here"
    ;call print_newline
    int3
}