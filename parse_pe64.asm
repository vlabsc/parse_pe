; parse_pe64.asm - parse_pe from memory
; version 8 - populate more fields
; the pe parser .. after the file content is loaded into memory, pe format is parsed
; pe64 - yet to do import table


section '.data' data readable writeable

offset.pe64.dos_header.mz_signature equ 0x0     ; first offset
offset.pe64.dos_header.nt_header_location equ 0x3c     ; within dos heaader at 3c, address of PE
offset.pe64.nt_header.pe_signature dd 0x0000
offset.pe64.nt_header.file_header dd 0x0000
offset.pe64.nt_header.optional_header dd 0x0000
offset.pe64.section_header.start dd 0x0
offset.pe64.section_header.end dd 0x0

value.pe64.dos_header.mz_signature dw 0x0000
value.pe64.nt_header.pe_signature dd 0x0000


value.pe64.nt_header.file_header.machine dw 0x0000
value.pe64.nt_header.file_header.number_of_sections dw 0x0000
value.pe64.nt_header.file_header.time_date_stamp dd 0x0000
value.pe64.nt_header.file_header.pointer_to_symbol_table dd 0x0000
value.pe64.nt_header.file_header.number_of_symbols dd 0x0000
value.pe64.nt_header.file_header.size_of_optional_header dw 0x0000
value.pe64.nt_header.file_header.characteristics dw 0x0000


value.pe64.nt_header.optional_header.magic dw 0x0000
value.pe64.nt_header.optional_header.major db 0x0
value.pe64.nt_header.optional_header.minor db 0x0
value.pe64.nt_header.optional_header.size_of_code dd 0x00000000
value.pe64.nt_header.optional_header.size_of_initialized_data dd 0x00000000

value.pe64.nt_header.optional_header.size_of_uninitialized_data dd 0x00000000
value.pe64.nt_header.optional_header.address_of_entry_point dd 0x00000000
value.pe64.nt_header.optional_header.base_of_code dd 0x00000000
value.pe64.nt_header.optional_header.image_base dq 0x00000000
value.pe64.nt_header.optional_header.size_of_image dd 0x00000000
value.pe64.nt_header.optional_header.size_of_headers dd 0x00000000
value.pe64.nt_header.optional_header.checksum dd 0x00000000
value.pe64.nt_header.optional_header.size_of_stack_reserve dq 0x00000000
value.pe64.nt_header.optional_header.size_of_stack_commit dq 0x00000000
value.pe64.nt_header.optional_header.size_of_heap_reserve dq 0x00000000
value.pe64.nt_header.optional_header.size_of_heap_commit dq 0x00000000
value.pe64.nt_header.optional_header.loader_flags dd 0x00000000
value.pe64.nt_header.optional_header.number_of_rva_and_sizes dd 0x00000000

value.pe64.nt_header.optional_header.dd.export.rva dd 0x00000000
value.pe64.nt_header.optional_header.dd.export.size dd 0x00000000

value.pe64.nt_header.optional_header.dd.import.rva dd 0x00000000
value.pe64.nt_header.optional_header.dd.import.size dd 0x00000000

value.pe64.nt_header.optional_header.dd.resource.rva dd 0x00000000
value.pe64.nt_header.optional_header.dd.resource.size dd 0x00000000

value.pe64.nt_header.optional_header.dd.exception.rva dd 0x00000000
value.pe64.nt_header.optional_header.dd.exception.size dd 0x00000000

value.pe64.nt_header.optional_header.dd.certificate.rva dd 0x00000000
value.pe64.nt_header.optional_header.dd.certificate.size dd 0x00000000

value.pe64.nt_header.optional_header.dd.baserelocation.rva dd 0x00000000
value.pe64.nt_header.optional_header.dd.baserelocation.size dd 0x00000000

value.pe64.nt_header.optional_header.dd.debug.rva dd 0x00000000
value.pe64.nt_header.optional_header.dd.debug.size dd 0x00000000

value.pe64.nt_header.optional_header.dd.architecture.rva dd 0x00000000
value.pe64.nt_header.optional_header.dd.architecture.size dd 0x00000000

value.pe64.nt_header.optional_header.dd.globalptr.rva dd 0x00000000
value.pe64.nt_header.optional_header.dd.globalptr.size dd 0x00000000

value.pe64.nt_header.optional_header.dd.tls.rva dd 0x00000000
value.pe64.nt_header.optional_header.dd.tls.size dd 0x00000000

value.pe64.nt_header.optional_header.dd.loadconfig.rva dd 0x00000000
value.pe64.nt_header.optional_header.dd.loadconfig.size dd 0x00000000

value.pe64.nt_header.optional_header.dd.boundimport.rva dd 0x00000000
value.pe64.nt_header.optional_header.dd.boundimport.size dd 0x00000000

value.pe64.nt_header.optional_header.dd.iat.rva dd 0x00000000
value.pe64.nt_header.optional_header.dd.iat.size dd 0x00000000

value.pe64.nt_header.optional_header.dd.delayimport.rva dd 0x00000000
value.pe64.nt_header.optional_header.dd.delayimport.size dd 0x00000000

value.pe64.nt_header.optional_header.dd.clrruntime.rva dd 0x00000000
value.pe64.nt_header.optional_header.dd.clrruntime.size dd 0x00000000

value.pe64.nt_header.optional_header.dd.reserved.rva dd 0x00000000
value.pe64.nt_header.optional_header.dd.reserved.size dd 0x00000000

value.pe64.section_header.name rb 0x8
value.pe64.section_header.virtual_size dd 0x0
value.pe64.section_header.virtual_rva dd 0x0
value.pe64.section_header.virtual_size_of_raw_data dd 0x0
value.pe64.section_header.virtual_pointer_to_raw_data dd 0x0
value.pe64.section_header.virtual_pointer_to_relocations dd 0x0
value.pe64.section_header.virtual_pointer_to_line_numbers dd 0x0
value.pe64.section_header.virtual_number_of_relocations dw 0x0
value.pe64.section_header.virtual_number_of_line_numbers dw 0x0
value.pe64.section_header.virtual_characteristics dd 0x0



section '.text' code readable executable

proc parse_pe64 input_file_buffer_address
    pushall

    mov dword [input_file_buffer_address], ecx
    call print_newline
    call print_newline
    invoke printf, "+---------------------------------------------------------------------------------------+"
    call print_newline
    invoke printf, "parsing for pe64 format at address 0x%x ... ", [input_file_buffer_address]

; ------------------------------------------------------------------------
    call print_newline
    invoke printf, "verifying MZ signature at offset: 0x%x ... ", offset.dos_header.mz_signature
    xor edi, edi
    xor ebx, ebx
    xor rdx, rdx
    xor esi, esi

    ; load the start of the file buffer into esi
    mov esi, dword [input_file_buffer_address]
    mov bx, word [esi + offset.dos_header.mz_signature]
    mov [value.pe64.dos_header.mz_signature], bx
    cmp bx, word 0x5a4d
    je pe64_verify_mz_noerror
        invoke printf, "found 0x%x ... [ failed ] ", word bx
        jmp pe64_parse_pe_return_with_error
    pe64_verify_mz_noerror:
    invoke printf, "found 0x%x ... [ ok ] ", word bx

; ------------------------------------------------------------------------
    call print_newline
    invoke printf, "finding offset to NT header ... "

    ; load the start of the file buffer into esi
    xor esi, esi
    mov esi, dword [input_file_buffer_address]
    ; offset.dos_header.nt_header_location equ 0x3c     
    ; within dos heaader at 3c, address of PE
    xor ebx, ebx
    mov ebx, [esi + offset.dos_header.nt_header_location]
    mov [offset.pe64.nt_header.pe_signature], ebx    

    invoke printf, "offset to NT header is 0x%hhhx ... [ ok ] ", \
                    dword [offset.pe64.nt_header.pe_signature]
    call print_newline
    invoke printf, "finding PE signature at offset 0x%hhhx ... ", \
                    [offset.pe64.nt_header.pe_signature]

    xor esi, esi
    xor edi, edi
    mov esi, dword [input_file_buffer_address]
    mov edi, [offset.pe64.nt_header.pe_signature]
    mov edx, [esi + edi]
    mov [value.pe64.nt_header.pe_signature], edx
    
    cmp dx, word 0x4550
    je pe64_verify_pe_signature_no_error
        invoke printf, "found 0x%x ... [ failed ] ", word dx
        jmp pe64_parse_pe_return_with_error
    pe64_verify_pe_signature_no_error:
    invoke printf, "found 0x%x ... [ ok ] ... ", word dx

; ------------------------------------------------------------------------
    xor edx, edx
    xor eax, eax

    mov esi, dword [input_file_buffer_address]
    mov edi, [offset.pe64.nt_header.pe_signature]

    mov edx, [esi + edi]
    mov eax, [esi + edi]
    shr eax, 8
    invoke printf, "char (%c%c) ... [ ok ] ", dx, ax
    call print_newline

    add edi, 0x4     ; PE\0\0 occupies 4 bytes
    invoke printf, "probing nt header at offset 0x%hhhx ... ", edi

; ------------------------------------------------------------------------
; lets probe the coff file header fields
    call print_newline
    invoke printf, "verifying PE machine architecture ... "

    call print_newline
    invoke printf, "    -> machine: "

    xor esi, esi
    xor edi, edi
    xor ebx, ebx
    xor edx, edx
    
    mov esi, dword [input_file_buffer_address]
    mov edi, [offset.pe64.nt_header.pe_signature]
    
    add edi, 0x4    ; PE\0\0 occupies 4 bytes

    mov [offset.pe64.nt_header.file_header], edi

    mov bx, word [esi + edi]
    mov [value.pe64.nt_header.file_header.machine], word bx
    cmp bx, word 0x014c         ; 32bit
    je pe64_verify_machine_noerror
    cmp bx, word 0x8664         ; 64bit
    je pe64_verify_machine_noerror
        invoke printf, "0x%04x ... [ failed ] ", word [value.pe64.nt_header.file_header.machine]
        jmp pe64_parse_pe_return_with_error
    pe64_verify_machine_noerror:
    invoke printf, "0x%x ... [ ok ] ", word [value.pe64.nt_header.file_header.machine]
    call print_newline

    xor esi, esi
    xor edi, edi

    mov esi, dword [input_file_buffer_address]
    mov edi, [offset.pe64.nt_header.pe_signature]
    
    add edi, 0x4    ; PE\0\0 occupies 4 bytes
    add edi, 0x2     ; + machine takes 2 bytes
    xor edx, edx
    mov dx, word [esi + edi]    
    mov [value.pe64.nt_header.file_header.number_of_sections], word dx
    xor edx, edx

    add edi, 0x2     ; + number of sections takes 2 bytes
    xor edx, edx
    mov edx, [esi + edi]

    mov dword [value.pe64.nt_header.file_header.time_date_stamp], dword edx

    add edi, 0x4     ; + time date stamp takes 4 bytes
    xor edx, edx
    mov edx, [esi + edi]

    mov dword [value.pe64.nt_header.file_header.pointer_to_symbol_table], edx
    xor edx, edx

    add edi, 0x4     ; + pointer to symbol table takes 4 bytes
    xor edx, edx
    mov edx, [esi + edi]

    mov dword [value.pe64.nt_header.file_header.number_of_symbols], dword edx
    xor edx, edx

    add edi, 0x4     ; + number of symbols table takes 4 bytes
    xor edx, edx
    mov dx, word [esi + edi]

    mov word [value.pe64.nt_header.file_header.size_of_optional_header], word dx
    xor edx, edx

    add edi, 0x2     ; + size of optional header takes 2 bytes
    xor edx, edx
    mov dx, word [esi + edi]

    mov word [value.pe64.nt_header.file_header.characteristics], word dx
    xor edx, edx

    add edi, 0x2     ; + characteristics takes 2 bytes
    mov [offset.pe64.nt_header.optional_header], edi

; lets probe the coff file header fields - end
; ------------------------------------------------------------------------
; lets probe the optional file header fields - start
    invoke printf, "offset to nt_header.optional_header at 0x%x ... probing ... ", \
                    word [offset.pe64.nt_header.optional_header]

    xor edx, edx
    xor esi, esi
    xor edi, edi
    mov esi, dword [input_file_buffer_address]
    mov edi, [offset.pe64.nt_header.optional_header]
    xor edx, edx
    mov dx, word [esi + edi]
    mov [value.pe64.nt_header.optional_header.magic], word dx

    ; compare if this 32bit or 64bit 
    ; 0x10b pe32
    ; 0x20b pe32+

    mov [is_64bit], 0x1

    add edi, 0x4        ; magic + major + minor
    xor edx, edx
    mov edx, dword [esi + edi]
    mov [value.pe64.nt_header.optional_header.size_of_code], dword edx

    add edi, 0x4        ; magic + major + minor + size of code
    xor edx, edx
    mov edx, dword [esi + edi]
    mov [value.pe64.nt_header.optional_header.size_of_initialized_data], dword edx

    add edi, 0x4        ; magic + major + minor + size of code + size of initialized data
    xor edx, edx
    mov edx, dword [esi + edi]
    mov [value.pe64.nt_header.optional_header.size_of_uninitialized_data], dword edx

    add edi, 0x4        ; magic + major + minor + size of code + size of initialized data + size of un-initialized data
    xor edx, edx
    mov edx, dword [esi + edi]
    mov [value.pe64.nt_header.optional_header.address_of_entry_point], dword edx

    add edi, 0x4        ; ... + address_of_entry_point
    xor edx, edx
    mov edx, dword [esi + edi]
    mov [value.pe64.nt_header.optional_header.base_of_code], dword edx

    add edi, 0x4        
    xor rdx, rdx
    mov rdx, qword [esi + edi]
    mov [value.pe64.nt_header.optional_header.image_base], qword rdx

    add edi, 0x20       
    xor edx, edx
    mov edx, dword [esi + edi]
    mov [value.pe64.nt_header.optional_header.size_of_image], dword edx
    
    add edi, 0x4        
    xor edx, edx
    mov edx, dword [esi + edi]
    mov [value.pe64.nt_header.optional_header.size_of_headers], dword edx
    
    add edi, 0x4        
    xor edx, edx
    mov edx, dword [esi + edi]
    mov [value.pe64.nt_header.optional_header.checksum], dword edx

    mov esi, dword [input_file_buffer_address]
    add edi, 0x8        
    xor edx, edx
    ;mov edx, dword [esi + edi]
    mov rdx, qword [esi + edi]
    mov [value.pe64.nt_header.optional_header.size_of_stack_reserve], qword rdx

    mov esi, dword [input_file_buffer_address]
    add edi, 0x8        
    xor edx, edx
    ;mov edx, dword [esi + edi]
    mov rdx, qword [esi + edi]
    mov [value.pe64.nt_header.optional_header.size_of_stack_commit], qword rdx

    mov esi, dword [input_file_buffer_address]
    add edi, 0x8        
    xor edx, edx
    ;mov edx, dword [esi + edi]
    mov rdx, qword [esi + edi]    
    mov [value.pe64.nt_header.optional_header.size_of_heap_reserve], qword rdx

    mov esi, dword [input_file_buffer_address]
    add edi, 0x8        
    xor edx, edx
    ;mov edx, dword [esi + edi]
    mov rdx, qword [esi + edi]    
    mov [value.pe64.nt_header.optional_header.size_of_heap_commit], qword rdx

    mov esi, dword [input_file_buffer_address]
    add edi, 0x8        
    xor edx, edx
    mov edx, dword [esi + edi]
    mov [value.pe64.nt_header.optional_header.loader_flags], dword edx

    mov esi, dword [input_file_buffer_address]
    add edi, 0x4        
    xor edx, edx
    mov edx, dword [esi + edi]
    mov [value.pe64.nt_header.optional_header.number_of_rva_and_sizes], dword edx

    invoke printf, "probing optional_header completed ... "
    call print_newline
; -----------------------------------------------------------------
; probing data directories 

    xor rsi, rsi
    mov esi, dword [input_file_buffer_address]
    add edi, 0x4        ; ... + address_of_entry_point + base_of_code
    add esi, edi
    lea edi, [value.pe64.nt_header.optional_header.dd.export.rva]
    mov ecx, 0x80   ; 128 bytes - 16 data directories
    rep movsb


    invoke printf, "probing pe64 header completed ... "
    call print_newline
    invoke printf, "+---------------------------------------------------------------------------------------+"
    call print_newline


; -----------------------------------------------------------------
    ;jmp pe64_parse_pe_return_without_error
pe64_parse_pe_return_without_error:
    flushall
    call print_parsed_pe64

    flushall
    mov eax, 0x1
    jmp pe64_parse_pe_proc_return

pe64_parse_pe_return_as_64bit_found:
    call print_newline
    invoke printf, "found 64bit (pe+) returning ... "
    call print_newline
    invoke printf, "+---------------------------------------------------------------------------------------+"
    call print_newline

pe64_parse_pe_return_with_error:
    flushall

pe64_parse_pe_proc_return:
    popall
    ret
endp






proc print_parsed_pe64
    pushall
    ;invoke printf, "+---------------------------------------------------------------------------------------+"
    ;call print_newline
    invoke printf, "printing the parsed pe64 ... "
    call print_newline

    call print_newline
    xor r8, r8
    mov r8w, word [value.pe64.dos_header.mz_signature]
    invoke printf, "MZ signature at offset: 0x%x is 0x%04x ... ", \
        offset.pe64.dos_header.mz_signature, r8w
    
    call print_newline
    invoke printf, "offset to NT header is 0x%hhhx ... ", \
                        dword [offset.pe64.nt_header.pe_signature]

    call print_newline
    invoke printf, "PE signature at offset 0x%hhhx ... ", [offset.pe64.nt_header.pe_signature]

    xor r8, r8
    mov r8d, dword [value.pe64.nt_header.pe_signature]
    invoke printf, "0x%x ... ", r8d
    call print_newline

    invoke printf, "offset to file header "
    xor r8, r8
    mov r8d, dword [offset.pe64.nt_header.file_header]
    invoke printf, "0x%x ... ", r8d
    call print_newline    

; -----------------------------------------------------------------
;   printing coff file header starts
    invoke printf, "verifying PE machine architecture ... ", edi
    call print_newline
    invoke printf, "    -> machine: "
    
    xor rdx, rdx
    mov dx, word [value.pe64.nt_header.file_header.machine]
    invoke printf, "0x%x ...", dx
    call print_newline

    xor rdx, rdx
    mov dx, word [value.pe64.nt_header.file_header.number_of_sections]
    invoke printf, "    -> number of sections: 0x%04x ", dx
    call print_newline

    xor rdx, rdx
    mov edx, dword [value.pe64.nt_header.file_header.time_date_stamp]
    invoke printf, "    -> time date stamp: 0x%x ", edx
    call print_newline

    xor rdx, rdx
    mov edx, dword [value.pe64.nt_header.file_header.pointer_to_symbol_table]
    invoke printf, "    -> pointer to symbol table: 0x%x ", edx
    call print_newline

    xor rdx, rdx
    mov edx, dword [value.pe64.nt_header.file_header.number_of_symbols]
    invoke printf, "    -> number of symbols: 0x%x ", edx
    call print_newline

    xor rdx, rdx
    mov dx, word [value.pe64.nt_header.file_header.size_of_optional_header]
    invoke printf, "    -> size of optional header: 0x%x ", dx
    call print_newline

    xor rdx, rdx
    mov dx, word [value.pe64.nt_header.file_header.characteristics]
    invoke printf, "    -> characteristics: 0x%x ", dx
    call print_newline
    invoke printf, "+---------------------------------------------------------------------------------------+"
    call print_newline


;   printing coff file header ends
; -----------------------------------------------------------------
;    printing optional header - starts
    
    xor rdx, rdx
    mov dx, word [offset.pe64.nt_header.optional_header]
    invoke printf, "offset to nt_header.optional_header at 0x%x ", dx
    call print_newline

    xor rdx, rdx
    mov dx, word [value.pe64.nt_header.optional_header.magic]
    invoke printf, "    -> magic: 0x%04x ", dx
    call print_newline

    xor rdx, rdx
    mov edx, dword [value.pe64.nt_header.optional_header.size_of_code]
    invoke printf, "    -> size of code: 0x%08x ", edx
    call print_newline

    xor rdx, rdx
    mov edx, dword [value.pe64.nt_header.optional_header.size_of_initialized_data]
    invoke printf, "    -> size of initialized data: 0x%08x ", edx
    call print_newline

    xor rdx, rdx
    mov edx, dword [value.pe64.nt_header.optional_header.size_of_uninitialized_data]
    invoke printf, "    -> size of un-initialized data: 0x%08x ", edx
    call print_newline

    xor rdx, rdx
    mov edx, dword [value.pe64.nt_header.optional_header.address_of_entry_point]
    invoke printf, "    -> address of entry point: 0x%08x ", edx
    call print_newline

    xor rdx, rdx
    mov edx, dword [value.pe64.nt_header.optional_header.base_of_code]
    invoke printf, "    -> base of code: 0x%08x ", edx
    call print_newline

    ;xor rdx, rdx
    ;mov edx, dword [value.pe64.nt_header.optional_header.base_of_data]
    ;invoke printf, "    -> base of data: 0x%08x ", edx
    ;call print_newline

    xor rdx, rdx
    mov rdx, qword [value.pe64.nt_header.optional_header.image_base]
    invoke printf, "    -> image base: 0x%016llx ", rdx
    call print_newline

    xor rdx, rdx
    mov edx, dword [value.pe64.nt_header.optional_header.size_of_image]
    invoke printf, "    -> size of image: 0x%08x ", edx
    call print_newline

    xor rdx, rdx
    mov edx, dword [value.pe64.nt_header.optional_header.size_of_headers]
    invoke printf, "    -> size of headers: 0x%08x ", edx
    call print_newline

    xor rdx, rdx
    mov edx, [value.pe64.nt_header.optional_header.checksum]
    invoke printf, "    -> checksum: 0x%08x ", edx
    call print_newline

    xor rdx, rdx
    mov rdx, qword [value.pe64.nt_header.optional_header.size_of_stack_reserve]
    invoke printf, "    -> size of stack reserve: 0x%016x ", rdx
    call print_newline

    xor rdx, rdx
    mov rdx, qword [value.pe64.nt_header.optional_header.size_of_stack_commit]
    invoke printf, "    -> size of stack commit: 0x%016x ", rdx
    call print_newline

    xor rdx, rdx
    mov rdx, qword [value.pe64.nt_header.optional_header.size_of_heap_reserve]
    invoke printf, "    -> size of heap reserve: 0x%016x ", rdx
    call print_newline

    xor rdx, rdx
    mov rdx, qword [value.pe64.nt_header.optional_header.size_of_heap_commit]
    invoke printf, "    -> size of heap commit: 0x%016x ", rdx
    call print_newline

    xor rdx, rdx
    mov edx, dword [value.pe64.nt_header.optional_header.loader_flags]
    invoke printf, "    -> loader flags: 0x%08x ", edx
    call print_newline

    xor rdx, rdx
    mov edx, dword [value.pe64.nt_header.optional_header.number_of_rva_and_sizes]
    invoke printf, "    -> number of rva and sizes: 0x%08x ", edx
    call print_newline
    invoke printf, "+---------------------------------------------------------------------------------------+"
    call print_newline

;    printing optional header - ends
; -----------------------------------------------------------------

; -----------------------------------------------------------------
; probing and printing data directories - start
    invoke printf, "printing data directories... "
    call print_newline

    invoke printf, " export table                   - "
    invoke printf, "0x%08x (rva) - ", [value.pe64.nt_header.optional_header.dd.export.rva]
    invoke printf, "0x%08x (size). ", [value.pe64.nt_header.optional_header.dd.export.size]
    call print_newline
    invoke printf, " import table                   - "
    invoke printf, "0x%08x (rva) - ", [value.pe64.nt_header.optional_header.dd.import.rva]
    invoke printf, "0x%08x (size). ", [value.pe64.nt_header.optional_header.dd.import.size]
    call print_newline
    invoke printf, " resource tabel                 - "
    invoke printf, "0x%08x (rva) - ", [value.pe64.nt_header.optional_header.dd.resource.rva]
    invoke printf, "0x%08x (size). ", [value.pe64.nt_header.optional_header.dd.resource.size]
    call print_newline
    invoke printf, " exception table                - "
    invoke printf, "0x%08x (rva) - ", [value.pe64.nt_header.optional_header.dd.exception.rva]
    invoke printf, "0x%08x (size). ", [value.pe64.nt_header.optional_header.dd.exception.size]
    call print_newline
    invoke printf, " certificate table              - "
    invoke printf, "0x%08x (rva) - ", [value.pe64.nt_header.optional_header.dd.certificate.rva]
    invoke printf, "0x%08x (size). ", [value.pe64.nt_header.optional_header.dd.certificate.size]
    call print_newline
    invoke printf, " base relocation table          - "
    invoke printf, "0x%08x (rva) - ", [value.pe64.nt_header.optional_header.dd.baserelocation.rva]
    invoke printf, "0x%08x (size). ", [value.pe64.nt_header.optional_header.dd.baserelocation.size]
    call print_newline
    invoke printf, " debug table                    - "
    invoke printf, "0x%08x (rva) - ", [value.pe64.nt_header.optional_header.dd.debug.rva]
    invoke printf, "0x%08x (size). ", [value.pe64.nt_header.optional_header.dd.debug.size]
    call print_newline
    invoke printf, " architecture table             - "
    invoke printf, "0x%08x (rva) - ", [value.pe64.nt_header.optional_header.dd.architecture.rva]
    invoke printf, "0x%08x (size). ", [value.pe64.nt_header.optional_header.dd.architecture.size]
    call print_newline
    invoke printf, " global ptr table               - "
    invoke printf, "0x%08x (rva) - ", [value.pe64.nt_header.optional_header.dd.globalptr.rva]
    invoke printf, "0x%08x (size). ", [value.pe64.nt_header.optional_header.dd.globalptr.size]
    call print_newline
    invoke printf, " tls table                      - "
    invoke printf, "0x%08x (rva) - ", [value.pe64.nt_header.optional_header.dd.tls.rva]
    invoke printf, "0x%08x (size). ", [value.pe64.nt_header.optional_header.dd.tls.size]
    call print_newline
    invoke printf, " load config table              - "
    invoke printf, "0x%08x (rva) - ", [value.pe64.nt_header.optional_header.dd.loadconfig.rva]
    invoke printf, "0x%08x (size). ", [value.pe64.nt_header.optional_header.dd.loadconfig.size]
    call print_newline
    invoke printf, " bound import table             - "
    invoke printf, "0x%08x (rva) - ", [value.pe64.nt_header.optional_header.dd.boundimport.rva]
    invoke printf, "0x%08x (size). ", [value.pe64.nt_header.optional_header.dd.boundimport.size]
    call print_newline
    invoke printf, " iat table                      - "
    invoke printf, "0x%08x (rva) - ", [value.pe64.nt_header.optional_header.dd.iat.rva]
    invoke printf, "0x%08x (size). ", [value.pe64.nt_header.optional_header.dd.iat.size]
    call print_newline
    invoke printf, " delay import descriptor table  - "
    invoke printf, "0x%08x (rva) - ", [value.pe64.nt_header.optional_header.dd.delayimport.rva]
    invoke printf, "0x%08x (size). ", [value.pe64.nt_header.optional_header.dd.delayimport.size]
    call print_newline
    invoke printf, " clr runtime header table       - "
    invoke printf, "0x%08x (rva) - ", [value.pe64.nt_header.optional_header.dd.clrruntime.rva]
    invoke printf, "0x%08x (size). ", [value.pe64.nt_header.optional_header.dd.clrruntime.size]
    call print_newline
    invoke printf, " reserved table                 - "
    invoke printf, "0x%08x (rva) - ", [value.pe64.nt_header.optional_header.dd.reserved.rva]
    invoke printf, "0x%08x (size). ", [value.pe64.nt_header.optional_header.dd.reserved.size]
    call print_newline

    invoke printf, "+---------------------------------------------------------------------------------------+"
    call print_newline

; probing and printing data directories - end
; -----------------------------------------------------------------
; probing and printing section headers - start
    invoke printf, "probing section headers ...  total of %hhx sections ... ", \ 
                    [value.pe64.nt_header.file_header.number_of_sections]
    call print_newline

    xor edi, edi
    mov esi, dword [input_file_buffer_address]
    mov edi, [offset.pe64.nt_header.optional_header]
    add di, word [value.pe64.nt_header.file_header.size_of_optional_header]
    mov [offset.pe64.section_header.start], edi

    invoke printf, "section header starts at 0x%hhx ... ", \ 
                    [offset.pe64.section_header.start]
    call print_newline

    mov [loop_index], 0x0
pe64_probe_section_headers_loop_start:
    mov ecx, [loop_index]
    cmp cx, [value.pe64.nt_header.file_header.number_of_sections]
    jge pe64_probe_section_headers_loop_out

    xor rdx, rdx    
    mov rdx, qword [esi + edi]
    mov qword [value.pe64.section_header.name], rdx
    invoke printf, "    -> ", [value.pe64.section_header.name]
    fastcall print_string_from_hex, value.pe64.section_header.name
    invoke printf, " (hex: 0x%llx)", [value.pe64.section_header.name]
    call print_newline
    
    add edi, 8
    xor rdx, rdx    
    mov edx, dword [esi + edi]
    mov dword [value.pe64.section_header.virtual_size], edx
    invoke printf, "    -> virtual size: 0x%x", [value.pe64.section_header.virtual_size]
    call print_newline

    add edi, 4
    xor rdx, rdx
    mov edx, dword [esi + edi]
    mov dword [value.pe64.section_header.virtual_rva], edx
    invoke printf, "    -> virtual rva: 0x%x", [value.pe64.section_header.virtual_rva]
    call print_newline

    add edi, 4
    xor rdx, rdx
    mov edx, dword [esi + edi]
    mov dword [value.pe64.section_header.virtual_size_of_raw_data], edx
    invoke printf, "    -> size of raw data: 0x%x", [value.pe64.section_header.virtual_size_of_raw_data]
    call print_newline

    add edi, 4
    xor rdx, rdx
    mov edx, dword [esi + edi]
    mov dword [value.pe64.section_header.virtual_pointer_to_raw_data], edx
    invoke printf, "    -> pointer to raw data: 0x%x", [value.pe64.section_header.virtual_pointer_to_raw_data]
    call print_newline

    add edi, 4
    xor rdx, rdx
    mov edx, dword [esi + edi]
    mov dword [value.pe64.section_header.virtual_pointer_to_relocations], edx
    invoke printf, "    -> pointer to relocations: 0x%x", [value.pe64.section_header.virtual_pointer_to_relocations]
    call print_newline

    add edi, 4
    xor rdx, rdx
    mov edx, dword [esi + edi]
    mov dword [value.pe64.section_header.virtual_pointer_to_line_numbers], edx
    invoke printf, "    -> pointer to line numbers: 0x%x", [value.pe64.section_header.virtual_pointer_to_line_numbers]
    call print_newline

    add edi, 4
    xor rdx, rdx
    mov dx, word [esi + edi]
    mov word [value.pe64.section_header.virtual_number_of_relocations], dx
    invoke printf, "    -> number of relocations: 0x%x", [value.pe64.section_header.virtual_number_of_relocations]
    call print_newline

    add edi, 2
    xor rdx, rdx
    mov dx, word [esi + edi]
    mov word [value.pe64.section_header.virtual_number_of_line_numbers], dx
    invoke printf, "    -> number of line numbers: 0x%x", [value.pe64.section_header.virtual_number_of_line_numbers]
    call print_newline

    add edi, 2
    xor rdx, rdx
    mov edx, dword [esi + edi]
    mov dword [value.pe64.section_header.virtual_characteristics], edx
    invoke printf, "    -> characteristics: 0x%x", [value.pe64.section_header.virtual_characteristics]

; section header characteristics print - start
    xor r15, r15
    mov r15d, dword [value.pe64.section_header.virtual_characteristics]

    invoke printf, " => [ "
pe64.characteristics_check_0:
    bt r15d, 29
    jnc pe64.characteristics_check_1
    invoke printf, " .executable. "

pe64.characteristics_check_1:
    bt r15d, 30
    jnc pe64.characteristics_check_2
    invoke printf, " .read. "

pe64.characteristics_check_2:
    bt r15d, 5
    jnc pe64.characteristics_check_3
    invoke printf, " .code. "

pe64.characteristics_check_3:
    bt r15d, 31
    jnc pe64.characteristics_check_4
    invoke printf, " .write. "

pe64.characteristics_check_4:
    bt r15d, 6
    jnc pe64.characteristics_comeout
    invoke printf, " .initialized data. "

pe64.characteristics_comeout:

; section header characteristics print - end

; now find out iat region
; iat is stored in 
;value.nt_header.optional_header.dd.import.rva dd 0x00000000
;value.nt_header.optional_header.dd.import.size dd 0x00000000
; aaa

    xor r15, r15
    mov r15d, edi
    sub r15d, 24
    
    xor rdx, rdx
    xor r8, r8

    mov ecx, dword [esi + r15d]  ; min
    sub r15d, 4      ; virtual size
    mov edx, ecx    ; min
    add edx, dword [esi + r15d]      ; rva size - max   
    ;aaa
    mov r8d, dword [value.pe64.nt_header.optional_header.dd.import.rva]    ; addr

    ; is_addr_within_range(min, max, addr)
    fastcall find_is_addr_within_range
    test eax, eax
    jz pe64.section_rva_iat_probe_comeout
    invoke printf, " .import section. "

pe64.section_rva_iat_probe_comeout:
    invoke printf, " ] "
    call print_newline

    add edi, 4
    inc [loop_index]
    call print_newline

    jmp pe64_probe_section_headers_loop_start
pe64_probe_section_headers_loop_out:

    mov [offset.pe64.section_header.end], edi
    invoke printf, "section header ends at 0x%hhx ... ", \ 
                    [offset.pe64.section_header.end]
    call print_newline

    invoke printf, "+---------------------------------------------------------------------------------------+"
    call print_newline
; probing and printing section headers - end
; -----------------------------------------------------------------
; probing and printing specific sections in hex - start


    invoke printf, "printing sections in hex format ...  total of %hhx sections ... ", \ 
                        [value.pe64.nt_header.file_header.number_of_sections]
    call print_newline

    xor edi, edi
    xor esi, esi
    mov esi, dword [input_file_buffer_address]
    mov edi, [offset.pe64.nt_header.optional_header]

    ; take us to the section headers
    add di, word [value.pe64.nt_header.file_header.size_of_optional_header]
    mov [loop_index], 0x0
pe64_probe_sections_hex_loop_start:
    mov ecx, [loop_index]
    cmp cx, [value.pe64.nt_header.file_header.number_of_sections]
    jge probe_sections_hex_loop_out

    xor rdx, rdx    
    mov rdx, qword [esi + edi]
    mov qword [value.pe64.section_header.name], rdx
    invoke printf, "    -> ", [value.pe64.section_header.name]
    fastcall print_string_from_hex, value.pe64.section_header.name

    add edi, 16             ; esi + 16 takes us to virtual_size_of_raw_data
    xor edx, edx
    mov edx, dword [esi + edi]
    mov dword [value.pe64.section_header.virtual_size_of_raw_data], edx
    invoke printf, "    -> size of raw data: 0x%x - ", [value.pe64.section_header.virtual_size_of_raw_data]

    add edi, 4      ; + virtual_size_of_raw_data
    xor rdx, rdx
    mov edx, dword [esi + edi]
    mov dword [value.pe64.section_header.virtual_pointer_to_raw_data], edx
    invoke printf, "pointer to raw data: 0x%x", [value.pe64.section_header.virtual_pointer_to_raw_data]
    call print_newline

    pushall    
    xor rdx, rdx
    xor r9, r9
    mov r9d, esi
    add r9d, dword [value.pe64.section_header.virtual_pointer_to_raw_data]   ; 4th arg

    fastcall print_hex, 3, 16, 16, r9, \
                dword [value.pe64.section_header.virtual_pointer_to_raw_data]
    call print_newline

    flushall
    popall
    
    add edi, 0x14             ; edi + 0x14 takes us to end of section headers
    inc [loop_index]
    call print_newline
    jmp pe64_probe_sections_hex_loop_start
pe64_probe_sections_hex_loop_out:


    invoke printf, "+---------------------------------------------------------------------------------------+"
    call print_newline

; probing and printing specific sections in hex - end
; -----------------------------------------------------------------




    ;jmp print_parsed_pe_return_without_error
pe64_print_parsed_pe_return_without_error:
    flushall
    mov eax, 0x1
    jmp pe64_print_parsed_pe_proc_return
        

pe64_print_parsed_pe_return_with_error:
    flushall

pe64_print_parsed_pe_proc_return:
    popall
    ret
endp

