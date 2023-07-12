; ifh.asm - input file handling
; version 7 - optimization
; version 7 - pe64 implementation
; this code opens the input pe file and prepares



section '.data' data readable writeable

input_file_handle dd 0
input_file_size dd 0
input_file_size_read_by_readfile dd 0
input_file_buffer_address dd 0          ; address of the buffer
;input_file_max_size_allowed dd 5594304   ; 4194304 bytes = 4 mb
input_file_max_size_allowed dd 4194304   ; 4194304 bytes = 4 mb

is_32bit db 0x0
is_64bit db 0x0


ret_error_code dd 0
return_to_main_error_code dd 0




section '.text' code readable executable

proc open_file input_file_name

    mov dword [input_file_name], ecx

    pushall
    flushall

    invoke printf, "opening the file %s ... ", dword [input_file_name]

    ; ------------------------------------------------------------
    invoke CreateFileA, dword [input_file_name], GENERIC_READ, 0, NULL, OPEN_EXISTING, \
                        FILE_ATTRIBUTE_NORMAL, NULL
    cmp eax, -1
    jne .CreateFileA_noerror
    .CreateFileA_error:
        invoke GetLastError
        mov [ret_error_code], eax
        xor rcx, rcx
        xor rdx, rdx
        invoke printf, "Error in opening the file %s", dword [input_file_name]
        xor rcx, rcx
        xor rdx, rdx
        invoke printf, "Error code is %d ", [ret_error_code]
        jmp open_file_function_return_with_error
    .CreateFileA_noerror:
    mov [input_file_handle], eax
    xor rcx, rcx
    xor rdx, rdx
    invoke printf, "file %s opened successfully.", dword [input_file_name]
    call print_newline
    invoke printf, "finding the size of file %s ... ", dword [input_file_name]

    xor rax, rax
    invoke GetFileSize, [input_file_handle], NULL
    cmp eax, 0xFFFFFFFF
    jne .GetFileSize_noerror
    .GetFileSize_error:
        invoke GetLastError
        mov [ret_error_code], eax
        xor rcx, rcx
        xor rdx, rdx
        invoke printf, "Error in GetFileSize."
        xor rcx, rcx
        xor rdx, rdx
        invoke printf, "Error code is %d.", [ret_error_code]
        call print_newline
        jmp open_file_function_return_with_error
    .GetFileSize_noerror:
    mov [input_file_size], eax
    invoke printf, "file %s size is: %d bytes. ", \
                dword [input_file_name], [input_file_size]

    mov ebx, [input_file_max_size_allowed]
    mov eax, dword [input_file_size]
    cmp eax, ebx            ; eax holds the file size
    jle .filesizeok
    invoke printf, "file size is bigger than MAX bytes (%d bytes).", \
                    [input_file_max_size_allowed]
    jmp open_file_function_return

    .filesizeok:
    mov [input_file_size], eax
    invoke printf, "file size is %d bytes.", [input_file_size]
    call print_newline

    invoke printf, "allocating buffer for %u bytes ... ", [input_file_size]
    xor eax, eax
    mov eax, GMEM_FIXED
    or eax, GMEM_ZEROINIT
    invoke GlobalAlloc, eax, [input_file_size]

    cmp eax, NULL
    jne .GlobalAlloc_noerror
    .GlobalAlloc_error:
        invoke GetLastError
        mov [ret_error_code], eax
        xor rcx, rcx
        xor rdx, rdx
        invoke printf, "Error in GlobalAlloc."
        xor rcx, rcx
        xor rdx, rdx
        invoke printf, "Error code is %d.", [ret_error_code]
        call print_newline
        jmp open_file_function_return_with_error
    .GlobalAlloc_noerror:
    mov [input_file_buffer_address], eax
    invoke printf, "allocated buffer at address 0x%x. ", [input_file_buffer_address]
    call print_newline

    flushall

    invoke printf, "reading file (%s) and loading content into the address 0x%x ... ", dword [input_file_name], \
                        [input_file_buffer_address]
    invoke ReadFile, [input_file_handle], [input_file_buffer_address], \
                        [input_file_size], addr input_file_size_read_by_readfile, NULL

    
    cmp eax, 0
    jne .ReadFile_noerror
    .ReadFile_error:
        invoke GetLastError
        mov [ret_error_code], eax
        xor rcx, rcx
        xor rdx, rdx
        invoke printf, "Error in ReadFile."
        xor rcx, rcx
        xor rdx, rdx
        invoke printf, "Error code is %d. ", [ret_error_code]
        call print_newline
        jmp open_file_function_return_with_error
    .ReadFile_noerror:
    invoke printf, "ReadFile successfull ... "
    call print_newline
    invoke printf, "%d bytes loaded into address 0x%x.", [input_file_size_read_by_readfile], \
                                [input_file_buffer_address]
    
    
    fastcall find_is32bit, [input_file_buffer_address]
    cmp eax, 64
    je found_64_bit
find_is32bit_foun64bit:
    fastcall parse_pe, [input_file_buffer_address]
    ;invoke printf, "parsing the buffer at address 0x%x ... ", [input_file_buffer_address]
found_32_bit:
    invoke printf, "pe32 header parsed successfull ... "
    call print_newline
    jmp found_32_64_bit_comeout

found_64_bit:
    invoke printf, "pe32+ (64bit) found ... "
    call print_newline
    fastcall parse_pe64, [input_file_buffer_address]
    invoke printf, "pe64 header parsed successfull ... "
    call print_newline

found_32_64_bit_comeout:
    xor eax, eax

    jmp open_file_function_return_without_error


open_file_function_return_with_error:
    mov [return_to_main_error_code], dword 0x0
    jmp open_file_function_return

open_file_function_return_without_error:
    mov [return_to_main_error_code], dword 0x1

open_file_function_return:
    call print_newline
    call print_newline
    invoke printf, "closing the file %s and returning ... ", dword [input_file_name]
    invoke CloseHandle, [input_file_handle]
    invoke printf, "closed file %s.", dword [input_file_name]

    cmp [input_file_buffer_address], 0x0
    je global_free_out
    invoke GlobalFree, [input_file_buffer_address]
    global_free_out:

    ; ------------------------------------------------------------
    popall

    mov eax, dword [return_to_main_error_code]
    ret


endp


