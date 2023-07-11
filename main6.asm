; main6.asm
; version 6 - print and parse as seperate logic 
; this is the main and entry code


format PE64 console
entry main

include 'WIN64AX.INC'

include 'libs.inc'
include 'macros.inc'


section '.data' data readable writeable

temp dd 0x77
;input_filename db "fih7.exe", 0
;input_filename db "out.exe", 0
;input_filename db "target.exe", 0
input_filename db "adobe.exe", 0

section '.text' code readable executable

main:

    pushall
    flushall

    xor eax, eax
    xor r9, r9
    xor r8, r8

    call clrscr
    invoke printf, "parse_pe (v6)- parse the pe header and print the fields."
    call print_newline


    fastcall open_file, input_filename
    cmp eax, 0
    jne .open_file_returned_without_error
    call print_newline
    invoke printf, "error reported."
    jmp .main_return

    .open_file_returned_without_error:
        call print_newline
        invoke printf, "no error reported."

.main_return:
    call print_newline
    invoke printf, "program ends."
    call print_newline
    popall
    ret

include 'ifh6.asm'   ; input file handling 
include 'parse_pe6.asm'
include 'printhex6.asm'



section '.idata' import data readable
    library msvcrt, 'msvcrt.dll',\
            kernel32, 'kernel32.dll'
        import msvcrt,\
            printf, 'printf'

        include 'C:\fasm\INCLUDE\API\KERNEL32.INC'
    
