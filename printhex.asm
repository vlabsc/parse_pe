; printhex.asm
; version 7 - optimization
; version 7 - pe64 implementation

section '.text' code readable executable

proc print_hex hexprint_buffer_total_lines_to_display, \
                    hexprint_buffer_total_columns_to_display, \
                    hexprint_buffer_last_line_columns_to_display, \
                    inputfile_read_buffer_address, \
                    row_address_print_start_address

    local row_address_print rb 0x4
    
    ; r14d - row_index
    ; r15d - col_index
    ; esi - buffer_index_save
    ; edi - buffer_index


    mov dword [hexprint_buffer_total_lines_to_display], ecx
    mov dword [hexprint_buffer_total_columns_to_display], edx
    mov [hexprint_buffer_last_line_columns_to_display], r8
    mov [inputfile_read_buffer_address], r9
    ;debugbreak

    xor eax, eax
    mov eax, dword [esp + 64]
    mov dword [row_address_print], eax

    pushall
    ;mov dword [row_address_print], dword 0x00000000

    xor rsi, rsi
    xor rdi, rdi
    xor r14, r14
    xor r15, r15

    .iteration_loop_each_rows_start:
        ; save the position - start
        ; first time the hex values are printed
        ; then again for the same bytes we need to print ASCII
        ; so the buffer_index is savted into 'buffer_index_save' 
        ; to start specific to that row
        ; esi holds the original offset, edi is incremented for every cell display
        xor rcx, rcx
        mov esi, edi
        ; save the position - end

        ; check if row_index is less then hexprint_buffer_total_lines_to_display - start
        ; the total rows should be less than hexprint_buffer_total_lines_to_display
        ; hexprint_buffer_total_lines_to_display = file size / bytes to show per line
        ; the reminder would go into hexprint_buffer_last_line_columns_to_display
        xor ecx, ecx        
        cmp dword [hexprint_buffer_total_lines_to_display], r14d
        je .iteration_loop_each_rows_end
        ; check if row_index is less then hexprint_buffer_total_lines_to_display - end

        xor rdx, rdx
        xor rcx, rcx
        xor r15, r15

        invoke printf, "0x%08x [ ", dword [row_address_print]        
        .iteration_loop_cols_start:
            cmp r15b, byte [hexprint_buffer_total_columns_to_display]
            je .iteration_loop_cols_end

            xor edx, edx
            mov eax, edi
            add eax, dword [inputfile_read_buffer_address]
            mov dl, byte [eax]
            invoke printf, "%02x", dl

            invoke printf, " "  ; space between every hex
            inc edi
            inc r15b
            jmp .iteration_loop_cols_start
        .iteration_loop_cols_end:
        invoke printf, "] "

        ; print the ASCII of the row - start 

        ; restore the position
        ; first time the hex values are printed
        ; then again for the same bytes we need to print ASCII
        ; so the buffer_index is restored from 'buffer_index_save' 
        ; to start specific to that row
        ; esi holds the original offset, edi is incremented for every cell display
        xor ecx, ecx
        mov edi, esi        
        xor r15d, r15d

        invoke printf, "[ "
        .iteration_loop_cols_ascii_start:
            cmp r15b, byte [hexprint_buffer_total_columns_to_display]
            je .iteration_loop_cols_ascii_end
            
            mov ecx, edi
            add ecx, dword [inputfile_read_buffer_address]
            mov ecx, [ecx]
            fastcall print_ascii_character, ecx

            inc edi
            inc r15b
            jmp .iteration_loop_cols_ascii_start
        .iteration_loop_cols_ascii_end:
        invoke printf, " ] "
        ; print the ASCII of the row - end

        ;l at this point one row is over. hence calculation are made

        inc r14d            ; one row is over

        mov dword ecx, dword [hexprint_buffer_total_columns_to_display]
        add dword [row_address_print], dword ecx    
        
        call print_newline
        jmp .iteration_loop_each_rows_start
    .iteration_loop_each_rows_end:

    ; now let's iterate the last row

    cmp byte [hexprint_buffer_last_line_columns_to_display], 0x0
    je .print_hex_return

    ; save the position - start
    ; first time the hex values are printed
    ; then again for the same bytes we need to print ASCII
    ; so the buffer_index is savted into 'buffer_index_save' 
    ; to start specific to that row
    ; esi holds the original offset, edi is incremented for every cell display
    xor rcx, rcx
    mov esi, edi
    ; save the position - end

    xor rcx, rcx
    xor rdx, rdx
    xor r15, r15

    invoke printf, "0x%08x [ ", dword [row_address_print]
    ;invoke printf, "0x%08x ", dword [row_address_print]
    ;invoke printf, "[ "

    .iteration_loop_last_row_start:
        cmp r15b, byte [hexprint_buffer_total_columns_to_display]
        je .iteration_loop_last_row_end

        cmp r15b, byte [hexprint_buffer_last_line_columns_to_display]
        ; no jle because the col_index starts at 0
        jl .iteration_loop_last_row_col_1
        invoke printf, "  "
        jmp .iteration_loop_last_row_col_2

        .iteration_loop_last_row_col_1:
            xor edx, edx
            mov eax, edi

            add eax, dword [inputfile_read_buffer_address]
            mov dl, byte [eax]
            invoke printf, "%02x", dl

        .iteration_loop_last_row_col_2:

            inc r15b    ; one column is over
            inc edi

            invoke printf, " "
            jmp .iteration_loop_last_row_start
        .iteration_loop_last_row_end:
        invoke printf, "] "

        ; print the ASCII of the last row - start 

        ; restore the position
        ; first time the hex values are printed
        ; then again for the same bytes we need to print ASCII
        ; so the buffer_index is restored from 'buffer_index_save' 
        ; to start specific to that row
        ; esi holds the original offset, edi is incremented for every cell display
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

                add ecx, dword [inputfile_read_buffer_address]
                mov ecx, [ecx]
                fastcall print_ascii_character, ecx

            .iteration_loop_last_last_row_col_2:

            inc edi
            inc r15b    ; one column is over

            jmp .iteration_loop_last_row_col_ascii_start
        .iteration_loop_last_row_ascii_end:
        invoke printf, " ]"
        ; print the ASCII of the row - end


.print_hex_return:

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

