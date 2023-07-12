include 'V:\OneHalf\Programming\asm\FASM\libs\macros.inc'

section '.data' data readable writeable

    print_newlinestr db 13, 10, 0

    handle_getstd dd 1
    count dw 0
    dwLen dd 0

    struct COORD 
        X dw ?
        Y dw ?
    ends

    struct SMALL_RECT
        Left dw ?
        Top dw ?
        Right dw ?
        Bottom dw ?
    ends

    struct CONSOLE_SCREEN_BUFFER_INFO
        dwSize COORD ?
        dwCursorPosition COORD ?
        wAttributes dw ?
        srWindow SMALL_RECT ?
        dwMaximumWindowSize COORD ?
    ends

    csbi CONSOLE_SCREEN_BUFFER_INFO
    coord COORD 0, 0


section '.text' code readable executable

clrscr:
    xor eax, eax

    mov eax, -11
    invoke GetStdHandle, -11
    mov dword [handle_getstd], eax

    xor rdx, rdx
    xor rcx, rcx

    invoke GetConsoleScreenBufferInfo, dword [handle_getstd], addr csbi

    xor ecx, ecx
    xor edx, edx

    mov byte cl, byte [csbi.dwSize.X]
    mov byte dl, byte [csbi.dwSize.Y]

    imul ecx, edx
    mov dword [dwLen], ecx

    
    invoke FillConsoleOutputCharacter, dword [handle_getstd], 0x20, dword [dwLen], \
                                        dword [coord], addr count

    invoke SetConsoleCursorPosition, dword [handle_getstd], dword [coord]

    ret 

print_newline:
    invoke printf, print_newlinestr
    ret


proc printn, inputstring
    pushall
    mov dword [inputstring], ecx
    xor ecx, ecx
    mov ecx, dword [inputstring]
    invoke printf, ecx
    invoke printf, print_newlinestr
    flushall
    popall
    ret
endp


proc find_number_of_command_line_arguments, arg_address
    mov dword [arg_address], ecx
    local .total_spaces dd 0x0
    local .total_args dd 0x00

    pushall
; first lets find number of arguments
    xor ecx, ecx
    xor esi, esi
    mov esi, dword [arg_address]
find_number_of_arguments:
    cmp byte [esi], byte 0x0
    je find_number_of_arguments_out

    cmp byte [esi], byte 0x20   ; space
    jne no_spaces
        cmp byte [esi + 1], byte 0x20   ; space
        je no_spaces
        inc [.total_spaces]
    no_spaces:
    inc esi
    jmp find_number_of_arguments
find_number_of_arguments_out:

    flushall
    popall

    xor rax, rax
    mov eax, dword [.total_spaces]
    ret

endp



proc get_argument_strings_for_one_argument, arg_address, arg1_address, arg2_address
    mov dword [arg_address], ecx
    mov dword [arg1_address], edx
    mov dword [arg2_address], r8d

    local .total_spaces dd 0x0
    local .total_args dd 0x00
    local .len_arg1 dd 0x00
    local .len_arg2 dd 0x00

    pushall
; first lets find number of arguments
    xor ecx, ecx
    xor esi, esi
    mov esi, dword [arg_address]
get_argument_strings_for_1st_argument_find_number_of_arguments:
    cmp byte [esi], byte 0x0
    je get_argument_strings_for_1st_argument_find_number_of_arguments_out

    cmp byte [esi], byte 0x20   ; space
    je get_argument_strings_for_1st_argument_find_number_of_arguments_out

    inc esi
    inc [.len_arg1]
    jmp get_argument_strings_for_1st_argument_find_number_of_arguments
get_argument_strings_for_1st_argument_find_number_of_arguments_out:

    inc [.len_arg1]     ; last increment to add \0 at the end


get_argument_strings_for_2nd_argument_find_number_of_arguments:
    cmp byte [esi], byte 0x0
    je get_argument_strings_for_2nd_argument_find_number_of_arguments_out

    cmp byte [esi], byte 0x20 ; just ignore spaces
    je get_argument_strings_for_2nd_argument_find_number_of_arguments_out_ignore_spaces
    inc [.len_arg2]

    get_argument_strings_for_2nd_argument_find_number_of_arguments_out_ignore_spaces:

    inc esi
    jmp get_argument_strings_for_2nd_argument_find_number_of_arguments
get_argument_strings_for_2nd_argument_find_number_of_arguments_out:

    inc [.len_arg2]     ; last increment to add \0 at the end

    xor rax, rax
    xor rbx, rbx
    mov ebx, dword [arg1_address]
    invoke GlobalAlloc, 0x0040, [.len_arg1]     ; 0x0040 - GMEM_ZEROINIT
    mov [rbx], eax

    xor rax, rax
    xor rbx, rbx
    mov ebx, dword [arg2_address]
    invoke GlobalAlloc, 0x0040, [.len_arg2]     ; 0x0040 - GMEM_ZEROINIT
    mov [rbx], eax

    ;debugbreak

    pushall
; first lets find number of arguments
    xor ecx, ecx
    xor esi, esi
    mov esi, dword [arg_address]


    ;debugbreak

    xor rcx, rcx
    xor rdx, rdx
    mov ecx, [.len_arg1]
    dec ecx                 ;   [.len_arg1] includes \0 ..
    mov esi, dword [arg_address]
    mov edx, dword [arg1_address]
    mov edi, [edx]
    rep movsb

    xor rcx, rcx
    xor rdx, rdx
    mov ecx, [.len_arg2]
    dec ecx                 ;   [.len_arg2] includes \0 ..
    mov esi, dword [arg_address]
    add esi, [.len_arg1]
    mov edx, dword [arg2_address]
    mov edi, [edx]
    rep movsb


    flushall
    popall

    mov rax, 1
    ret

endp
