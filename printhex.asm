; printhex.asm
; file in hex version 11

section '.data' data readable writeable
hexmaptable db '0123456789ABCDEF'
hexstring rb 48
db 0    ; end of string 
filterstring rb 16
db 0 
;print_newlinestr db 13, 10, 0

section '.text' code readable executable

proc print_hex hexprint_buffer_total_lines_to_display, \
                    hexprint_buffer_total_columns_to_display, \
                    hexprint_buffer_last_line_columns_to_display, \
                    inputfile_read_buffer_address
    
    local row_address_print rb 0x4

    mov dword [hexprint_buffer_total_lines_to_display], ecx
    mov dword [hexprint_buffer_total_columns_to_display], edx
    mov [hexprint_buffer_last_line_columns_to_display], r8
    mov [inputfile_read_buffer_address], r9

    xor eax, eax
    mov eax, dword [esp + 64]
    mov dword [row_address_print], eax

    pushall

    xor r14, r14
    mov esi, dword [inputfile_read_buffer_address]

    iteration_loop_each_rows_start:
        cmp dword [hexprint_buffer_total_lines_to_display], r14d
        je iteration_loop_each_rows_end

        mov edi, esi            ; mov esi, dword [inputfile_read_buffer_address]
        
        lea ebx, [hexmaptable]
        lea r15d, [hexstring]
        mov ecx, dword [hexprint_buffer_total_columns_to_display]         ; 16
        looop1:
            xor eax, eax

            mov al, byte [edi]
            and al, 0xf0
            shr al, 4
            xlatb
            mov [r15d], al
            inc r15d

            mov al, byte [edi]
            and al, 0xf
            xlatb
            mov [r15d], al
            inc r15d

            mov [r15d], byte 0x20

            inc edi
            inc r15d    
        loop looop1
        ; print the ASCII of the row - start 

        lea r15d, [filterstring]
        mov ecx, dword [hexprint_buffer_total_columns_to_display]     ; 16
        looop2:            
            cmp byte [esi], 0x20
            jge .check_ascii_readable_1
            jmp .ascii_not_normal_print
            .check_ascii_readable_1:
                cmp byte [esi], 0x7e
                jle .ascii_normal_print
                jmp .ascii_not_normal_print
            .ascii_normal_print:
                mov bl, byte [esi]
                mov [r15d], byte bl
                jmp .check_ascii_readable_1_out
            .ascii_not_normal_print:
                mov [r15d], byte 0x2e                ; 0x2e -> .
            .check_ascii_readable_1_out:
            inc r15d            ; [filterstring]
            inc esi             ; [inputfile_read_buffer_address]
        loop looop2
        
        ; print the ASCII of the row - end

        invoke printf, "%08x [ %s ] [ %s ]%s", dword [row_address_print], addr hexstring, addr filterstring, print_newlinestr
        ;at this point one row is over. hence calculation are made

        inc r14d            ; one row is over - hexprint_buffer_total_lines_to_display
        mov dword ecx, dword [hexprint_buffer_total_columns_to_display]
        add dword [row_address_print], dword ecx    
        
        jmp iteration_loop_each_rows_start
    iteration_loop_each_rows_end:


; -----------------------------------------------------------------------------------
    ; now let's iterate the last row

    cmp byte [hexprint_buffer_last_line_columns_to_display], 0x0
    je print_hex_return

    xor ecx, ecx
    mov ecx, 49
    lea r15d, [hexstring]

    looop3:
        mov [r15d], byte 0x0
        inc r15d
    loop looop3

    xor rcx, rcx
    mov edi, esi

    xor rcx, rcx
    xor rdx, rdx
    xor r15, r15

    invoke printf, "%08x [ ", dword [row_address_print]    
    .iteration_loop_last_row_start:
        xor r15d, r15d
        lea ebx, [hexmaptable]
        lea r15d, [hexstring]
        xor ecx, ecx
        mov cl, byte [hexprint_buffer_last_line_columns_to_display]

        looop4:
            mov al, byte [edi]
            and al, 0xf0
            shr al, 4

            xlatb
            mov [r15d], al

            inc r15d    

            mov al, byte [edi]
            and al, 0xf

            xlatb
            mov [r15d], al

            inc r15d    

            mov [r15d], byte 0x20

            inc edi
            inc r15d    
        loop looop4
        invoke printf, "%s ", addr hexstring

        xor ebx, ebx
        mov bl, byte [hexprint_buffer_total_columns_to_display]
        sub bl, byte [hexprint_buffer_last_line_columns_to_display]
        looop5:
            test ebx, ebx
            je looop5_comeout
            invoke printf, "   "
            dec ebx
            jmp looop5
        looop5_comeout:

        invoke printf, "] "


        ; print the ASCII of the last row - start 

        mov edi, esi
        xor r15, r15

        invoke printf, "[ "
        .iteration_loop_last_row_col_ascii_start:
            cmp r15b, byte [hexprint_buffer_total_columns_to_display]
            je .iteration_loop_last_row_ascii_end

            cmp r15b, byte [hexprint_buffer_last_line_columns_to_display]
            ; no jle because the col_index starts at 0
            jl .iteration_loop_last_last_row_col_1
            invoke printf, " "
            jmp .iteration_loop_last_last_row_col_2

            .iteration_loop_last_last_row_col_1:
                mov ecx, edi
                mov ecx, [ecx]
                fastcall print_ascii_character, ecx

            .iteration_loop_last_last_row_col_2:

            inc edi
            inc r15b    ; one column is over

            jmp .iteration_loop_last_row_col_ascii_start
        .iteration_loop_last_row_ascii_end:
        invoke printf, " ]"
        ; print the ASCII of the row - end


print_hex_return:

    popall
    ret
endp



proc print_ascii_character, char_to_print
    ; ascii - 0x20 to 0x7e looks readable

    pushall

    mov byte [char_to_print], byte cl
    cmp byte [char_to_print], 0x20
            jge .check_ascii_readable_1
            jmp .ascii_not_normal_print
            .check_ascii_readable_1:
                cmp byte [char_to_print], 0x7e
                jle .ascii_normal_print
                jmp .ascii_not_normal_print
            .ascii_normal_print:
                invoke printf, "%c", [char_to_print]
                jmp .check_ascii_readable_1_out
            .ascii_not_normal_print:
                invoke printf, "."
            .check_ascii_readable_1_out:

    popall
    ret
endp

