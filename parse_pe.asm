; parse_pe.asm - parse_pe from memory
; version 8 - populate more fields
; the pe parser .. after the file content is loaded into memory, pe format is parsed

section '.data' data readable writeable

temps dd 0x00
loop_index dd 0x00

offset.dos_header.mz_signature equ 0x0     ; first offset
offset.dos_header.nt_header_location equ 0x3c     ; within dos heaader at 3c, address of PE
offset.nt_header.pe_signature dd 0x0000
offset.nt_header.file_header dd 0x0000
offset.nt_header.optional_header dd 0x0000
offset.section_header.start dd 0x0
offset.section_header.end dd 0x0

value.dos_header.mz_signature dw 0x0000
value.nt_header.pe_signature dd 0x0000

value.nt_header.file_header.machine dw 0x0000
value.nt_header.file_header.number_of_sections dw 0x0000
value.nt_header.file_header.time_date_stamp dd 0x0000
value.nt_header.file_header.pointer_to_symbol_table dd 0x0000
value.nt_header.file_header.number_of_symbols dd 0x0000
value.nt_header.file_header.size_of_optional_header dw 0x0000
value.nt_header.file_header.characteristics dw 0x0000


value.nt_header.optional_header.magic dw 0x0000
value.nt_header.optional_header.major db 0x0
value.nt_header.optional_header.minor db 0x0
value.nt_header.optional_header.size_of_code dd 0x00000000
value.nt_header.optional_header.size_of_initialized_data dd 0x00000000

value.nt_header.optional_header.size_of_uninitialized_data dd 0x00000000
value.nt_header.optional_header.address_of_entry_point dd 0x00000000
value.nt_header.optional_header.base_of_code dd 0x00000000
value.nt_header.optional_header.base_of_data dd 0x00000000
value.nt_header.optional_header.image_base dd 0x00000000
value.nt_header.optional_header.size_of_image dd 0x00000000
value.nt_header.optional_header.size_of_headers dd 0x00000000
value.nt_header.optional_header.checksum dd 0x00000000
value.nt_header.optional_header.size_of_stack_reserve dd 0x00000000
value.nt_header.optional_header.size_of_stack_commit dd 0x00000000
value.nt_header.optional_header.size_of_heap_reserve dd 0x00000000
value.nt_header.optional_header.size_of_heap_commit dd 0x00000000
value.nt_header.optional_header.loader_flags dd 0x00000000
value.nt_header.optional_header.number_of_rva_and_sizes dd 0x00000000   ; number of directories

value.nt_header.optional_header.dd.export.rva dd 0x00000000
value.nt_header.optional_header.dd.export.size dd 0x00000000

value.nt_header.optional_header.dd.import.rva dd 0x00000000
value.nt_header.optional_header.dd.import.size dd 0x00000000

value.nt_header.optional_header.dd.resource.rva dd 0x00000000
value.nt_header.optional_header.dd.resource.size dd 0x00000000

value.nt_header.optional_header.dd.exception.rva dd 0x00000000
value.nt_header.optional_header.dd.exception.size dd 0x00000000

value.nt_header.optional_header.dd.certificate.rva dd 0x00000000
value.nt_header.optional_header.dd.certificate.size dd 0x00000000

value.nt_header.optional_header.dd.baserelocation.rva dd 0x00000000
value.nt_header.optional_header.dd.baserelocation.size dd 0x00000000

value.nt_header.optional_header.dd.debug.rva dd 0x00000000
value.nt_header.optional_header.dd.debug.size dd 0x00000000

value.nt_header.optional_header.dd.architecture.rva dd 0x00000000
value.nt_header.optional_header.dd.architecture.size dd 0x00000000

value.nt_header.optional_header.dd.globalptr.rva dd 0x00000000
value.nt_header.optional_header.dd.globalptr.size dd 0x00000000

value.nt_header.optional_header.dd.tls.rva dd 0x00000000
value.nt_header.optional_header.dd.tls.size dd 0x00000000

value.nt_header.optional_header.dd.loadconfig.rva dd 0x00000000
value.nt_header.optional_header.dd.loadconfig.size dd 0x00000000

value.nt_header.optional_header.dd.boundimport.rva dd 0x00000000
value.nt_header.optional_header.dd.boundimport.size dd 0x00000000

value.nt_header.optional_header.dd.iat.rva dd 0x00000000
value.nt_header.optional_header.dd.iat.size dd 0x00000000

value.nt_header.optional_header.dd.delayimport.rva dd 0x00000000
value.nt_header.optional_header.dd.delayimport.size dd 0x00000000

value.nt_header.optional_header.dd.clrruntime.rva dd 0x00000000
value.nt_header.optional_header.dd.clrruntime.size dd 0x00000000

value.nt_header.optional_header.dd.reserved.rva dd 0x00000000
value.nt_header.optional_header.dd.reserved.size dd 0x00000000


value.import.section.rva dd 0x00000000
value.import.section.rva.size dd 0x00000000
value.import.section.raw dd 0x00000000
value.import.section.raw.size dd 0x00000000

value.import.directory.table.raw dd 0x00000000
value.import.directory.table.import.name.table.rva dd 0x00000000
value.import.directory.table.timestamp.rva dd 0x00000000
value.import.directory.table.forwarder.chain.rva dd 0x00000000
value.import.directory.table.name.rva dd 0x00000000
value.import.directory.table.import.address.table.rva dd 0x00000000



value.section_header.name rb 0x8
value.section_header.virtual_size dd 0x0
value.section_header.virtual_rva dd 0x0
value.section_header.virtual_size_of_raw_data dd 0x0
value.section_header.virtual_pointer_to_raw_data dd 0x0
value.section_header.virtual_pointer_to_relocations dd 0x0
value.section_header.virtual_pointer_to_line_numbers dd 0x0
value.section_header.virtual_number_of_relocations dw 0x0
value.section_header.virtual_number_of_line_numbers dw 0x0
value.section_header.virtual_characteristics dd 0x0

; data directory names table - used for printing
data_directory_names:
db "export                 ", 0
db "import                 ", 0
db "resource               ", 0
db "exception              " ,0
db "certificate            ",0
db "base relocation        ",0
db "debug                  ",0
db "architecture           ",0
db "global ptr             ",0
db "tls                    ",0
db "load config            ",0
db "bound import           ",0
db "iat                    ",0
db "delay import descriptor",0
db "clr runtime header     ",0
db "reserved               ",0


section '.text' code readable executable
proc parse_pe input_file_buffer_address
    pushall

    mov dword [input_file_buffer_address], ecx
    call print_newline
    call print_newline
    invoke printf, "+---------------------------------------------------------------------------------------+"
    call print_newline
    invoke printf, "parsing for pe format at address 0x%x ... ", [input_file_buffer_address]

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
    mov [value.dos_header.mz_signature], bx
    cmp bx, word 0x5a4d
    je verify_mz_noerror
        invoke printf, "found 0x%x ... [ failed ] ", word bx
        jmp parse_pe_return_with_error
    verify_mz_noerror:
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
    mov [offset.nt_header.pe_signature], ebx    

    invoke printf, "offset to NT header is 0x%hhhx ... [ ok ] ", \
                    dword [offset.nt_header.pe_signature]
    call print_newline
    invoke printf, "finding PE signature at offset 0x%hhhx ... ", \
                    [offset.nt_header.pe_signature]

    xor esi, esi
    xor edi, edi
    mov esi, dword [input_file_buffer_address]
    mov edi, [offset.nt_header.pe_signature]
    mov edx, [esi + edi]
    mov [value.nt_header.pe_signature], edx
    
    cmp dx, word 0x4550
    je verify_pe_signature_no_error
        invoke printf, "found 0x%x ... [ failed ] ", word dx
        jmp parse_pe_return_with_error
    verify_pe_signature_no_error:
    invoke printf, "found 0x%x ... [ ok ] ... ", word dx

; ------------------------------------------------------------------------
    xor edx, edx
    xor eax, eax

    mov esi, dword [input_file_buffer_address]
    mov edi, [offset.nt_header.pe_signature]

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
    mov edi, [offset.nt_header.pe_signature]
    
    add edi, 0x4    ; PE\0\0 occupies 4 bytes

    mov [offset.nt_header.file_header], edi

    mov bx, word [esi + edi]
    mov [value.nt_header.file_header.machine], word bx
    cmp bx, word 0x014c         ; 32bit
    je verify_machine_noerror
    cmp bx, word 0x8664         ; 64bit
    je verify_machine_noerror
        invoke printf, "0x%04x ... [ failed ] ", word [value.nt_header.file_header.machine]
        jmp parse_pe_return_with_error
    verify_machine_noerror:
    invoke printf, "0x%x ... [ ok ] ", word [value.nt_header.file_header.machine]
    call print_newline

    xor esi, esi
    xor edi, edi

    mov esi, dword [input_file_buffer_address]
    mov edi, [offset.nt_header.pe_signature]
    
    add edi, 0x4    ; PE\0\0 occupies 4 bytes
    add edi, 0x2     ; + machine takes 2 bytes
    xor edx, edx
    mov dx, word [esi + edi]    
    mov [value.nt_header.file_header.number_of_sections], word dx
    xor edx, edx

    add edi, 0x2     ; + number of sections takes 2 bytes
    xor edx, edx
    mov edx, [esi + edi]

    mov dword [value.nt_header.file_header.time_date_stamp], dword edx

    add edi, 0x4     ; + time date stamp takes 4 bytes
    xor edx, edx
    mov edx, [esi + edi]

    mov dword [value.nt_header.file_header.pointer_to_symbol_table], edx
    xor edx, edx

    add edi, 0x4     ; + pointer to symbol table takes 4 bytes
    xor edx, edx
    mov edx, [esi + edi]

    mov dword [value.nt_header.file_header.number_of_symbols], dword edx
    xor edx, edx

    add edi, 0x4     ; + number of symbols table takes 4 bytes
    xor edx, edx
    mov dx, word [esi + edi]

    mov word [value.nt_header.file_header.size_of_optional_header], word dx
    xor edx, edx

    add edi, 0x2     ; + size of optional header takes 2 bytes
    xor edx, edx
    mov dx, word [esi + edi]

    mov word [value.nt_header.file_header.characteristics], word dx
    xor edx, edx

    add edi, 0x2     ; + characteristics takes 2 bytes
    mov [offset.nt_header.optional_header], edi

; lets probe the coff file header fields - end
; ------------------------------------------------------------------------
; lets probe the optional file header fields - start
    invoke printf, "offset to nt_header.optional_header at 0x%x ... probing ... ", \
                    word [offset.nt_header.optional_header]

    xor edx, edx
    xor esi, esi
    xor edi, edi
    mov esi, dword [input_file_buffer_address]
    mov edi, [offset.nt_header.optional_header]
    xor edx, edx
    mov dx, word [esi + edi]
    mov [value.nt_header.optional_header.magic], word dx

    ; compare if this 32bit or 64bit 
    ; 0x10b pe32
    ; 0x20b pe32+

    cmp [value.nt_header.optional_header.magic], 0x20b
    je parse_pe_return_as_64bit_found
    mov [is_32bit], 0x1    
    
    ;je 

    add edi, 0x4        ; magic + major + minor
    xor edx, edx
    mov edx, dword [esi + edi]
    mov [value.nt_header.optional_header.size_of_code], dword edx

    add edi, 0x4        ; magic + major + minor + size of code
    xor edx, edx
    mov edx, dword [esi + edi]
    mov [value.nt_header.optional_header.size_of_initialized_data], dword edx

    add edi, 0x4        ; magic + major + minor + size of code + size of initialized data
    xor edx, edx
    mov edx, dword [esi + edi]
    mov [value.nt_header.optional_header.size_of_uninitialized_data], dword edx

    add edi, 0x4        ; magic + major + minor + size of code + size of initialized data + size of un-initialized data
    xor edx, edx
    mov edx, dword [esi + edi]
    mov [value.nt_header.optional_header.address_of_entry_point], dword edx

    add edi, 0x4        ; ... + address_of_entry_point
    xor edx, edx
    mov edx, dword [esi + edi]
    mov [value.nt_header.optional_header.base_of_code], dword edx

    add edi, 0x4        ; ... + address_of_entry_point + base_of_code
    xor edx, edx
    mov edx, dword [esi + edi]
    mov [value.nt_header.optional_header.base_of_data], dword edx

    add edi, 0x4        ; ... + address_of_entry_point + base_of_code
    xor edx, edx
    mov edx, dword [esi + edi]
    mov [value.nt_header.optional_header.image_base], dword edx

    add edi, 0x1c        ; ... + address_of_entry_point + base_of_code
    xor edx, edx
    mov edx, dword [esi + edi]
    mov [value.nt_header.optional_header.size_of_image], dword edx
    
    add edi, 0x4        ; ... + address_of_entry_point + base_of_code
    xor edx, edx
    mov edx, dword [esi + edi]
    mov [value.nt_header.optional_header.size_of_headers], dword edx
    
    add edi, 0x4        ; ... + address_of_entry_point + base_of_code
    xor edx, edx
    mov edx, dword [esi + edi]
    mov [value.nt_header.optional_header.checksum], dword edx

    mov esi, dword [input_file_buffer_address]
    add edi, 0x8        ; ... + address_of_entry_point + base_of_code
    xor edx, edx
    mov edx, dword [esi + edi]
    mov [value.nt_header.optional_header.size_of_stack_reserve], dword edx

    mov esi, dword [input_file_buffer_address]
    add edi, 0x4        ; ... + address_of_entry_point + base_of_code
    xor edx, edx
    mov edx, dword [esi + edi]
    mov [value.nt_header.optional_header.size_of_stack_commit], dword edx

    mov esi, dword [input_file_buffer_address]
    add edi, 0x4        ; ... + address_of_entry_point + base_of_code
    xor edx, edx
    mov edx, dword [esi + edi]
    mov [value.nt_header.optional_header.size_of_heap_reserve], dword edx

    mov esi, dword [input_file_buffer_address]
    add edi, 0x4        ; ... + address_of_entry_point + base_of_code
    xor edx, edx
    mov edx, dword [esi + edi]
    mov [value.nt_header.optional_header.size_of_heap_commit], dword edx

    mov esi, dword [input_file_buffer_address]
    add edi, 0x4        ; ... + address_of_entry_point + base_of_code
    xor edx, edx
    mov edx, dword [esi + edi]
    mov [value.nt_header.optional_header.loader_flags], dword edx

    mov esi, dword [input_file_buffer_address]
    add edi, 0x4        ; ... + address_of_entry_point + base_of_code
    xor edx, edx
    mov edx, dword [esi + edi]
    mov [value.nt_header.optional_header.number_of_rva_and_sizes], dword edx

    invoke printf, "probing optional_header completed ... "
    call print_newline
; -----------------------------------------------------------------
; probing data directories 

    xor rsi, rsi
    mov esi, dword [input_file_buffer_address]
    add edi, 0x4        ; ... + address_of_entry_point + base_of_code
    add esi, edi
    lea edi, [value.nt_header.optional_header.dd.export.rva]
    mov ecx, 0x80   ; 128 bytes - 16 data directories
    rep movsb

    invoke printf, "probing pe32 header completed ... "
    call print_newline
    invoke printf, "+---------------------------------------------------------------------------------------+"
    call print_newline

; -----------------------------------------------------------------
parse_pe_return_without_error:
    flushall
    call print_parsed_pe

    flushall
    mov eax, 0x1
    jmp parse_pe_proc_return

parse_pe_return_as_64bit_found:
    mov [is_64bit], 0x1
    call print_newline
    invoke printf, "found 64bit (pe+) returning ... "
    call print_newline
    invoke printf, "+---------------------------------------------------------------------------------------+"
    call print_newline

parse_pe_return_with_error:
    flushall

parse_pe_proc_return:
    popall   
    ret
endp










proc print_string_from_hex address_of_hex
    
    local loop_i db 0x00
    mov dword [address_of_hex], ecx
    pushall
    flushall
    mov ecx, 0
    xor esi, esi
    mov esi, dword [address_of_hex]

    iterate_every_hex:
        xor edx, edx

        mov dl, byte [esi]
        cmp edx, 0x0
        je iterate_every_hex_out

        invoke printf, "%c", byte [esi]

        inc esi
        jmp iterate_every_hex
    iterate_every_hex_out:

    popall
    ret
endp 




proc print_parsed_pe
    pushall
    invoke printf, "printing the parsed pe32 ... "
    call print_newline

    call print_newline
    xor r8, r8
    mov r8w, word [value.dos_header.mz_signature]
    invoke printf, "MZ signature at offset: 0x%x is 0x%04x ... ", \
        offset.dos_header.mz_signature, r8w
    
    call print_newline
    invoke printf, "offset to NT header is 0x%hhhx ... ", \
                        dword [offset.nt_header.pe_signature]

    call print_newline
    invoke printf, "PE signature at offset 0x%hhhx ... ", [offset.nt_header.pe_signature]

    xor r8, r8
    mov r8d, dword [value.nt_header.pe_signature]
    invoke printf, "0x%x ... ", r8d
    call print_newline

    invoke printf, "offset to file header "
    xor r8, r8
    mov r8d, dword [offset.nt_header.file_header]
    invoke printf, "0x%x ... ", r8d
    call print_newline    

; -----------------------------------------------------------------
;   printing coff file header starts
    invoke printf, "verifying PE machine architecture ... ", edi
    call print_newline
    invoke printf, "    -> machine: "
    
    xor rdx, rdx
    mov dx, word [value.nt_header.file_header.machine]
    invoke printf, "0x%x ...", dx
    call print_newline

    xor rdx, rdx
    mov dx, word [value.nt_header.file_header.number_of_sections]
    invoke printf, "    -> number of sections: 0x%04x ", dx
    call print_newline

    xor rdx, rdx
    mov edx, dword [value.nt_header.file_header.time_date_stamp]
    invoke printf, "    -> time date stamp: 0x%x ", edx
    call print_newline

    xor rdx, rdx
    mov edx, dword [value.nt_header.file_header.pointer_to_symbol_table]
    invoke printf, "    -> pointer to symbol table: 0x%x ", edx
    call print_newline

    xor rdx, rdx
    mov edx, dword [value.nt_header.file_header.number_of_symbols]
    invoke printf, "    -> number of symbols: 0x%x ", edx
    call print_newline

    xor rdx, rdx
    mov dx, word [value.nt_header.file_header.size_of_optional_header]
    invoke printf, "    -> size of optional header: 0x%x ", dx
    call print_newline

    xor rdx, rdx
    mov dx, word [value.nt_header.file_header.characteristics]
    invoke printf, "    -> characteristics: 0x%x ", dx
    call print_newline
    invoke printf, "+---------------------------------------------------------------------------------------+"
    call print_newline

;   printing coff file header ends
; -----------------------------------------------------------------
;    printing optional header - starts
    
    xor rdx, rdx
    mov dx, word [offset.nt_header.optional_header]
    invoke printf, "offset to nt_header.optional_header at 0x%x ", dx
    call print_newline

    xor rdx, rdx
    mov dx, word [value.nt_header.optional_header.magic]
    invoke printf, "    -> magic: 0x%04x ", dx
    call print_newline

    xor rdx, rdx
    mov edx, dword [value.nt_header.optional_header.size_of_code]
    invoke printf, "    -> size of code: 0x%08x ", edx
    call print_newline

    xor rdx, rdx
    mov edx, dword [value.nt_header.optional_header.size_of_initialized_data]
    invoke printf, "    -> size of initialized data: 0x%08x ", edx
    call print_newline

    xor rdx, rdx
    mov edx, dword [value.nt_header.optional_header.size_of_uninitialized_data]
    invoke printf, "    -> size of un-initialized data: 0x%08x ", edx
    call print_newline

    xor rdx, rdx
    mov edx, dword [value.nt_header.optional_header.address_of_entry_point]
    invoke printf, "    -> address of entry point: 0x%08x ", edx
    call print_newline

    xor rdx, rdx
    mov edx, dword [value.nt_header.optional_header.base_of_code]
    invoke printf, "    -> base of code: 0x%08x ", edx
    call print_newline

    xor rdx, rdx
    mov edx, dword [value.nt_header.optional_header.base_of_data]
    invoke printf, "    -> base of data: 0x%08x ", edx
    call print_newline

    xor rdx, rdx
    mov edx, [value.nt_header.optional_header.image_base]
    invoke printf, "    -> image base: 0x%08x ", edx
    call print_newline

    xor rdx, rdx
    mov edx, dword [value.nt_header.optional_header.size_of_image]
    invoke printf, "    -> size of image: 0x%08x ", edx
    call print_newline

    xor rdx, rdx
    mov edx, dword [value.nt_header.optional_header.size_of_headers]
    invoke printf, "    -> size of headers: 0x%08x ", edx
    call print_newline

    xor rdx, rdx
    mov edx, [value.nt_header.optional_header.checksum]
    invoke printf, "    -> checksum: 0x%08x ", edx
    call print_newline

    xor rdx, rdx
    mov edx, dword [value.nt_header.optional_header.size_of_stack_reserve]
    invoke printf, "    -> size of stack reserve: 0x%08x ", edx
    call print_newline

    xor rdx, rdx
    mov edx, dword [value.nt_header.optional_header.size_of_stack_commit]
    invoke printf, "    -> size of stack commit: 0x%08x ", edx
    call print_newline

    xor rdx, rdx
    mov edx, dword [value.nt_header.optional_header.size_of_heap_reserve]
    invoke printf, "    -> size of heap reserve: 0x%08x ", edx
    call print_newline

    xor rdx, rdx
    mov edx, dword [value.nt_header.optional_header.size_of_heap_commit]
    invoke printf, "    -> size of heap commit: 0x%08x ", edx
    call print_newline

    xor rdx, rdx
    mov edx, dword [value.nt_header.optional_header.loader_flags]
    invoke printf, "    -> loader flags: 0x%08x ", edx
    call print_newline

    xor rdx, rdx
    mov edx, dword [value.nt_header.optional_header.number_of_rva_and_sizes]
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
    invoke printf, "0x%08x (rva) - ", [value.nt_header.optional_header.dd.export.rva]
    invoke printf, "0x%08x (size). ", [value.nt_header.optional_header.dd.export.size]
    call print_newline
    invoke printf, " import table                   - "
    invoke printf, "0x%08x (rva) - ", [value.nt_header.optional_header.dd.import.rva]
    invoke printf, "0x%08x (size). ", [value.nt_header.optional_header.dd.import.size]
    call print_newline
    invoke printf, " resource tabel                 - "
    invoke printf, "0x%08x (rva) - ", [value.nt_header.optional_header.dd.resource.rva]
    invoke printf, "0x%08x (size). ", [value.nt_header.optional_header.dd.resource.size]
    call print_newline
    invoke printf, " exception table                - "
    invoke printf, "0x%08x (rva) - ", [value.nt_header.optional_header.dd.exception.rva]
    invoke printf, "0x%08x (size). ", [value.nt_header.optional_header.dd.exception.size]
    call print_newline
    invoke printf, " certificate table              - "
    invoke printf, "0x%08x (rva) - ", [value.nt_header.optional_header.dd.certificate.rva]
    invoke printf, "0x%08x (size). ", [value.nt_header.optional_header.dd.certificate.size]
    call print_newline
    invoke printf, " base relocation table          - "
    invoke printf, "0x%08x (rva) - ", [value.nt_header.optional_header.dd.baserelocation.rva]
    invoke printf, "0x%08x (size). ", [value.nt_header.optional_header.dd.baserelocation.size]
    call print_newline
    invoke printf, " debug table                    - "
    invoke printf, "0x%08x (rva) - ", [value.nt_header.optional_header.dd.debug.rva]
    invoke printf, "0x%08x (size). ", [value.nt_header.optional_header.dd.debug.size]
    call print_newline
    invoke printf, " architecture table             - "
    invoke printf, "0x%08x (rva) - ", [value.nt_header.optional_header.dd.architecture.rva]
    invoke printf, "0x%08x (size). ", [value.nt_header.optional_header.dd.architecture.size]
    call print_newline
    invoke printf, " global ptr table               - "
    invoke printf, "0x%08x (rva) - ", [value.nt_header.optional_header.dd.globalptr.rva]
    invoke printf, "0x%08x (size). ", [value.nt_header.optional_header.dd.globalptr.size]
    call print_newline
    invoke printf, " tls table                      - "
    invoke printf, "0x%08x (rva) - ", [value.nt_header.optional_header.dd.tls.rva]
    invoke printf, "0x%08x (size). ", [value.nt_header.optional_header.dd.tls.size]
    call print_newline
    invoke printf, " load config table              - "
    invoke printf, "0x%08x (rva) - ", [value.nt_header.optional_header.dd.loadconfig.rva]
    invoke printf, "0x%08x (size). ", [value.nt_header.optional_header.dd.loadconfig.size]
    call print_newline
    invoke printf, " bound import table             - "
    invoke printf, "0x%08x (rva) - ", [value.nt_header.optional_header.dd.boundimport.rva]
    invoke printf, "0x%08x (size). ", [value.nt_header.optional_header.dd.boundimport.size]
    call print_newline
    invoke printf, " iat table                      - "
    invoke printf, "0x%08x (rva) - ", [value.nt_header.optional_header.dd.iat.rva]
    invoke printf, "0x%08x (size). ", [value.nt_header.optional_header.dd.iat.size]
    call print_newline
    invoke printf, " delay import descriptor table  - "
    invoke printf, "0x%08x (rva) - ", [value.nt_header.optional_header.dd.delayimport.rva]
    invoke printf, "0x%08x (size). ", [value.nt_header.optional_header.dd.delayimport.size]
    call print_newline
    invoke printf, " clr runtime header table       - "
    invoke printf, "0x%08x (rva) - ", [value.nt_header.optional_header.dd.clrruntime.rva]
    invoke printf, "0x%08x (size). ", [value.nt_header.optional_header.dd.clrruntime.size]
    call print_newline
    invoke printf, " reserved table                 - "
    invoke printf, "0x%08x (rva) - ", [value.nt_header.optional_header.dd.reserved.rva]
    invoke printf, "0x%08x (size). ", [value.nt_header.optional_header.dd.reserved.size]
    call print_newline

    invoke printf, "+---------------------------------------------------------------------------------------+"
    call print_newline

; probing and printing data directories - end
; -----------------------------------------------------------------
; probing and printing section headers - start
    invoke printf, "probing section headers ...  total of %hhx sections ... ", \ 
                    [value.nt_header.file_header.number_of_sections]
    call print_newline

    xor edi, edi
    mov esi, dword [input_file_buffer_address]
    mov edi, [offset.nt_header.optional_header]
    add di, word [value.nt_header.file_header.size_of_optional_header]
    mov [offset.section_header.start], edi

    invoke printf, "section header starts at 0x%hhx ... ", \ 
                    [offset.section_header.start]
    call print_newline
    
    mov [loop_index], 0x0
probe_section_headers_loop_start:
    mov ecx, [loop_index]
    cmp cx, [value.nt_header.file_header.number_of_sections]
    jge probe_section_headers_loop_out

    xor rdx, rdx    
    mov rdx, qword [esi + edi]
    mov qword [value.section_header.name], rdx
    invoke printf, "    -> ", [value.section_header.name]
    fastcall print_string_from_hex, value.section_header.name
    invoke printf, " (hex: 0x%llx)", [value.section_header.name]
    call print_newline
    
    add edi, 8
    xor rdx, rdx    
    mov edx, dword [esi + edi]
    mov dword [value.section_header.virtual_size], edx
    invoke printf, "    -> virtual size: 0x%x", [value.section_header.virtual_size]
    call print_newline

    add edi, 4
    xor rdx, rdx
    mov edx, dword [esi + edi]
    mov dword [value.section_header.virtual_rva], edx
    invoke printf, "    -> virtual rva: 0x%x", [value.section_header.virtual_rva]
    call print_newline

    add edi, 4
    xor rdx, rdx
    mov edx, dword [esi + edi]
    mov dword [value.section_header.virtual_size_of_raw_data], edx
    invoke printf, "    -> size of raw data: 0x%x", [value.section_header.virtual_size_of_raw_data]
    call print_newline

    add edi, 4
    xor rdx, rdx
    mov edx, dword [esi + edi]
    mov dword [value.section_header.virtual_pointer_to_raw_data], edx
    invoke printf, "    -> pointer to raw data: 0x%x", [value.section_header.virtual_pointer_to_raw_data]
    call print_newline

    add edi, 4
    xor rdx, rdx
    mov edx, dword [esi + edi]
    mov dword [value.section_header.virtual_pointer_to_relocations], edx
    invoke printf, "    -> pointer to relocations: 0x%x", [value.section_header.virtual_pointer_to_relocations]
    call print_newline

    add edi, 4
    xor rdx, rdx
    mov edx, dword [esi + edi]
    mov dword [value.section_header.virtual_pointer_to_line_numbers], edx
    invoke printf, "    -> pointer to line numbers: 0x%x", [value.section_header.virtual_pointer_to_line_numbers]
    call print_newline

    add edi, 4
    xor rdx, rdx
    mov dx, word [esi + edi]
    mov word [value.section_header.virtual_number_of_relocations], dx
    invoke printf, "    -> number of relocations: 0x%x", [value.section_header.virtual_number_of_relocations]
    call print_newline

    add edi, 2
    xor rdx, rdx
    mov dx, word [esi + edi]
    mov word [value.section_header.virtual_number_of_line_numbers], dx
    invoke printf, "    -> number of line numbers: 0x%x", [value.section_header.virtual_number_of_line_numbers]
    call print_newline

    add edi, 2
    xor rdx, rdx
    mov edx, dword [esi + edi]
    mov dword [value.section_header.virtual_characteristics], edx
    invoke printf, "    -> characteristics: 0x%x", [value.section_header.virtual_characteristics]

; section header characteristics print - start
    xor r15, r15
    mov r15d, dword [value.section_header.virtual_characteristics]

    invoke printf, " => [ "
characteristics_check_0:
    bt r15d, 29
    jnc characteristics_check_1
    invoke printf, " .executable. "

characteristics_check_1:
    bt r15d, 30
    jnc characteristics_check_2
    invoke printf, " .read. "

characteristics_check_2:
    bt r15d, 5
    jnc characteristics_check_3
    invoke printf, " .code. "

characteristics_check_3:
    bt r15d, 31
    jnc characteristics_check_4
    invoke printf, " .write. "

characteristics_check_4:
    bt r15d, 6
    jnc characteristics_comeout
    invoke printf, " .initialized data. "

characteristics_comeout:

; section header characteristics print - end

; now find out iat region
; iat is stored in 
;value.nt_header.optional_header.dd.import.rva dd 0x00000000
;value.nt_header.optional_header.dd.import.size dd 0x00000000

    xor r15, r15
    mov r15d, edi
    sub r15d, 24
    
    xor rdx, rdx
    xor r8, r8

    mov ecx, dword [esi + r15d]  ; min
    mov edx, ecx    ; min
    sub r15d, 4      ; virtual size
    add edx, dword [esi + r15d]      ; rva size - max   
    mov r8d, dword [value.nt_header.optional_header.dd.import.rva]    ; import addr

    ; is_addr_within_range(min, max, addr)
    fastcall find_is_addr_within_range
    test eax, eax
    jz section_rva_iat_probe_comeout
    invoke printf, " .import section. "
    
    mov ecx, dword [value.nt_header.optional_header.dd.import.rva]    ; import addr
    add r15d, 4      ; virtual size
    mov edx, dword [esi + r15d]  ; min
    mov r8d, dword [value.section_header.virtual_pointer_to_raw_data]
    ;get_pointer_to_raw_address rva, base_rva, base_raw
    fastcall get_pointer_to_raw_address
    mov [value.import.directory.table.raw], eax

    mov eax, dword [value.section_header.virtual_pointer_to_raw_data]
    mov [value.import.section.raw], eax
    
    mov eax, dword [value.section_header.virtual_size_of_raw_data]
    mov [value.import.section.raw.size], eax

    mov eax, dword [value.section_header.virtual_rva]
    mov [value.import.section.rva], eax

    mov dword [value.section_header.virtual_size], edx
    mov [value.import.section.raw.size], eax



section_rva_iat_probe_comeout:
    invoke printf, " ] "
    call print_newline

    add edi, 4
    inc [loop_index]
    call print_newline

    jmp probe_section_headers_loop_start
probe_section_headers_loop_out:

    mov [offset.section_header.end], edi
    invoke printf, "section header ends at 0x%hhx ... ", \ 
                    [offset.section_header.end]
    call print_newline

    invoke printf, "+---------------------------------------------------------------------------------------+"
    call print_newline

; probing and printing section headers - end
; -----------------------------------------------------------------
; probing and printing specific sections in hex - start


    invoke printf, "printing sections in hex format ...  total of %hhx sections ... ", \ 
                        [value.nt_header.file_header.number_of_sections]
    call print_newline

    xor edi, edi
    xor esi, esi
    mov esi, dword [input_file_buffer_address]
    mov edi, [offset.nt_header.optional_header]

    ; take us to the section headers
    add di, word [value.nt_header.file_header.size_of_optional_header]
    mov [loop_index], 0x0
probe_sections_hex_loop_start:
    mov ecx, [loop_index]
    cmp cx, [value.nt_header.file_header.number_of_sections]
    jge probe_sections_hex_loop_out

    xor rdx, rdx    
    mov rdx, qword [esi + edi]
    mov qword [value.section_header.name], rdx
    invoke printf, "    -> ", [value.section_header.name]
    fastcall print_string_from_hex, value.section_header.name

    add edi, 16             ; esi + 16 takes us to virtual_size_of_raw_data
    xor edx, edx
    mov edx, dword [esi + edi]
    mov dword [value.section_header.virtual_size_of_raw_data], edx
    invoke printf, "    -> size of raw data: 0x%x - ", [value.section_header.virtual_size_of_raw_data]

    add edi, 4      ; + virtual_size_of_raw_data
    xor rdx, rdx
    mov edx, dword [esi + edi]
    mov dword [value.section_header.virtual_pointer_to_raw_data], edx
    invoke printf, "pointer to raw data: 0x%x", [value.section_header.virtual_pointer_to_raw_data]
    call print_newline

    pushall    
    xor rdx, rdx
    xor r9, r9
    mov r9d, esi
    add r9d, dword [value.section_header.virtual_pointer_to_raw_data]   ; 4th arg

    fastcall print_hex, 3, 16, 16, r9, \
                dword [value.section_header.virtual_pointer_to_raw_data]
    call print_newline

    flushall
    popall
    
    add edi, 0x14             ; edi + 0x14 takes us to end of section headers
    inc [loop_index]
    call print_newline
    jmp probe_sections_hex_loop_start
probe_sections_hex_loop_out:


    invoke printf, "+---------------------------------------------------------------------------------------+"
    call print_newline

; probing and printing specific sections in hex - end
; -----------------------------------------------------------------
; probing and printing import table - start

;value.import.directory.table.rva dd 0x00000000

;value.import.directory.table.import.name.table.rva dd 0x00000000
;value.import.directory.table.timestamp.rva dd 0x00000000
;value.import.directory.table.forwarder.chain.rva dd 0x00000000
;value.import.directory.table.name.rva dd 0x00000000
;value.import.directory.table.import.address.table.rva dd 0x00000000

    invoke printf, "probing and printing import directory table %s", print_newlinestr

    mov esi, dword [input_file_buffer_address]
    add esi, [value.import.directory.table.raw]
    xor eax, eax    ; count number of 0, to mark last table entry
    invoke printf, "import directory table address: 0x%08x %s%s", \
                        [value.import.directory.table.raw], print_newlinestr, print_newlinestr

    import_directory_table_probe_print_loop_start:
        xor eax, eax        
        or eax, [esi]
        or eax, [esi+4]
        or eax, [esi+8]
        or eax, [esi+12]
        or eax, [esi+16]
        test eax, eax
        jz import_directory_table_probe_print_loop_comeout

        xor eax, eax
        mov eax, [esi]
        invoke printf, "import name table rva: %08x %s", eax, print_newlinestr

        xor eax, eax
        mov eax, [esi+4]
        invoke printf, "time date stamp: %08d %s", eax, print_newlinestr

        xor eax, eax
        mov eax, [esi+8]
        invoke printf, "forwarder chain: %08x %s", eax, print_newlinestr

        xor eax, eax
        mov eax, [esi+12]
        invoke printf, "name rva: %08x ", eax

        mov ecx, [esi+12]       ; name rva
        mov edx, [value.import.section.rva] ; base rva
        mov r8d, [value.import.section.raw] ; base_raw

        ;get_pointer_to_raw_address rva, base_rva, base_raw
        fastcall get_pointer_to_raw_address
        add eax, [input_file_buffer_address]
        invoke printf, "(%s)%s", eax, print_newlinestr

        xor eax, eax
        mov eax, [esi+16]   ; import address table
        invoke printf, "import address table rva: %08x %s%s", \
                            eax, print_newlinestr, print_newlinestr

        add esi, 20
        jmp import_directory_table_probe_print_loop_start
    import_directory_table_probe_print_loop_comeout:
    invoke printf, "+---------------------------------------------------------------------------------------+%s", print_newlinestr
; probing and printing import table - end
; -----------------------------------------------------------------

; probing and printing import name table - start
; -----------------------------------------------------------------
;value.import.directory.table.rva dd 0x00000000

;value.import.directory.table.import.name.table.rva dd 0x00000000
;value.import.directory.table.timestamp.rva dd 0x00000000
;value.import.directory.table.forwarder.chain.rva dd 0x00000000
;value.import.directory.table.name.rva dd 0x00000000
;value.import.directory.table.import.address.table.rva dd 0x00000000

    invoke printf, "probing and printing import name table %s", print_newlinestr

    mov esi, dword [input_file_buffer_address]
    add esi, [value.import.directory.table.raw]
    xor eax, eax    ; count number of 0, to mark last table entry
    invoke printf, "import directory table address: 0x%08x %s%s", \
                        [value.import.directory.table.raw], print_newlinestr, print_newlinestr

    import_name_table_probe_print_loop_start:
        xor eax, eax        
        or eax, [esi]
        or eax, [esi+4]
        or eax, [esi+8]
        or eax, [esi+12]
        or eax, [esi+16]
        test eax, eax
        jz import_name_table_probe_print_loop_comeout

        ;xor eax, eax
        ;mov eax, [esi]
        ;invoke printf, "import name table rva: %08x %s", eax, print_newlinestr

        mov ecx, [esi+12]       ; name rva
        mov edx, [value.import.section.rva] ; base rva
        mov r8d, [value.import.section.raw] ; base_raw

        ;get_pointer_to_raw_address rva, base_rva, base_raw
        fastcall get_pointer_to_raw_address
        add eax, [input_file_buffer_address]
        invoke printf, "apis imported from (%s)%s", eax, print_newlinestr

        ; aaa
        mov ecx, [esi]         ; import name table
        mov edx, [value.import.section.rva] ; base rva
        mov r8d, [value.import.section.raw] ; base_raw

        push rsi
        fastcall print_import_name_table
        pop rsi


        add esi, 20
        jmp import_name_table_probe_print_loop_start
    import_name_table_probe_print_loop_comeout:

    invoke printf, "probing and printing import name table completed %s", print_newlinestr
    invoke printf, "+---------------------------------------------------------------------------------------+%s", print_newlinestr
; probing and printing import name table - end
; -----------------------------------------------------------------

print_parsed_pe_return_without_error:
    flushall
    mov eax, 0x1
    jmp print_parsed_pe_proc_return
        

print_parsed_pe_return_with_error:
    flushall

print_parsed_pe_proc_return:
    popall
    ret
endp

; bbb
proc print_import_name_table rva, base_rva, base_raw
    mov dword [rva], ecx
    mov dword [base_rva], edx
    mov dword [base_raw], r8d

    sub ecx, edx
    add r8d, ecx
    mov esi, r8d
    add esi, [input_file_buffer_address]    ; first thunk of name table entry
    
    print_import_name_table_loop_start:
        cmp [esi], dword 0x0
        jz print_import_name_table_loop_comeout

        mov r13d, [esi]
        bt r13d, 31
        jc ordinal_bit_set
        ordinal_bit_not_set:
        mov edx, dword [base_rva]
        mov r8d, dword [base_raw]

        sub r13d, edx
        add r8d, r13d
        mov eax, r8d
        add eax, [input_file_buffer_address]    ; first thunk of name table entry

        mov r10w, word [eax]
        mov r12d, eax
        xor edx, edx
        invoke printf, "hint: %04x, ", r10w

        mov edx, r12d
        add edx, 2

        invoke printf, "name: %s%s", edx, print_newlinestr
        jmp ordinal_bit_set_comeout

        ordinal_bit_set:
        xor edx, edx
        invoke printf, "ordinal hint: %04x%s", r13d, print_newlinestr
        ordinal_bit_set_comeout:

        add esi, 4
        jmp print_import_name_table_loop_start
    print_import_name_table_loop_comeout:    
    ret
endp

proc get_pointer_to_raw_address rva, base_rva, base_raw
    mov dword [rva], ecx
    mov dword [base_rva], edx
    mov dword [base_raw], r8d

    sub ecx, edx
    add r8d, ecx
    mov eax, r8d

    ret
endp


proc find_is_addr_within_range address, min, max

    mov dword [min], ecx
    mov dword [max], edx
    mov dword [address], r8d

    cmp ecx, r8d
    jg is_addr_within_range_not_within_range

    cmp edx, r8d
    jl is_addr_within_range_not_within_range
    mov eax, 1
    jmp is_addr_within_range_comeout

is_addr_within_range_not_within_range:
    xor eax, eax

is_addr_within_range_comeout:
    ret
endp



proc find_is32bit input_file_buffer_address
    pushall

    mov dword [input_file_buffer_address], ecx

    xor ebx, ebx
    mov esi, dword [input_file_buffer_address]
    mov bx, word [esi + offset.dos_header.mz_signature]

    xor esi, esi
    mov esi, dword [input_file_buffer_address]

    ; offset.dos_header.nt_header_location equ 0x3c     
    ; within dos heaader at 3c, address of PE
    xor ebx, ebx
    mov ebx, [esi + offset.dos_header.nt_header_location]
    mov [offset.nt_header.pe_signature], ebx    

    xor esi, esi
    xor edi, edi
    mov esi, dword [input_file_buffer_address]
    mov edi, [offset.nt_header.pe_signature]
; ------------------------------------------------------------------------
    xor edx, edx
    xor eax, eax

    mov esi, dword [input_file_buffer_address]
    mov edi, [offset.nt_header.pe_signature]

    
    xor esi, esi
    xor edi, edi

    mov esi, dword [input_file_buffer_address]
    mov edi, [offset.nt_header.pe_signature]
    
    add edi, 0x4    ; PE\0\0 occupies 4 bytes
    add edi, 0x2     ; + machine takes 2 bytes
    add edi, 0x2     ; + number of sections takes 2 bytes
    add edi, 0x4     ; + time date stamp takes 4 bytes
    add edi, 0x4     ; + pointer to symbol table takes 4 bytes
    add edi, 0x4     ; + number of symbols table takes 4 bytes
    add edi, 0x2     ; + characteristics takes 2 bytes
    add edi, 0x2     ; + characteristics takes 2 bytes

; lets probe the coff file header fields - end
; ------------------------------------------------------------------------
; lets probe the optional file header fields - start

    xor edx, edx

    mov dx, word [esi + edi]
    mov [value.nt_header.optional_header.magic], word dx
    ; compare if this 32bit or 64bit 
    ; 0x10b pe32
    ; 0x20b pe32+

    cmp [value.nt_header.optional_header.magic], 0x20b
    je find_is32bit_return_as_64bit_found
    jmp find_is32bit_return_as_32bit_found

find_is32bit_return_as_64bit_found:
    flushall
    popall
    mov eax, 64
    jmp find_is32bit_return

find_is32bit_return_as_32bit_found:
    flushall
    popall
    mov eax, 32

find_is32bit_return:
    ret
endp