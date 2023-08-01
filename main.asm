; main.asm
; version 8 - populate more fields
; this is the main and entry code


format PE64 console
entry main

include 'C:\fasm\INCLUDE\WIN64AX.INC'
include 'libs.inc'
include 'macros.inc'


section '.data' data readable writeable

temp dd 0x77
cmd_line_argument_pointer dd 0x00000000

cmd_line_arg1_address dd 1
cmd_line_arg2_address dd 1

;input_filename db "fih7.exe", 0
;input_filename db "out.exe", 0
;input_filename db "target.exe", 0
;input_filename db "adobe.exe", 0
inputfile_name_address dd 0x0

section '.text' code readable executable

main:

    pushall
    flushall
    invoke GetCommandLineA
    mov [cmd_line_argument_pointer], eax

    mov eax, [cmd_line_argument_pointer]
    fastcall find_number_of_command_line_arguments, eax

    cmp eax, 0x0
    je no_arguments_passed
    cmp eax, 0x1
    jg too_many_arguments_passed
    jmp correct_arguments_passed

no_arguments_passed:
    invoke printf, "no arguments passed ..."
    call print_newline
    fastcall print_help
    jmp main_return
too_many_arguments_passed:
    invoke printf, "too many arguments passed ..."
    call print_newline
    fastcall print_help
    jmp main_return

correct_arguments_passed:

    fastcall get_argument_strings_for_one_argument, [cmd_line_argument_pointer], \
                        cmd_line_arg1_address, cmd_line_arg2_address

    mov eax, [cmd_line_arg1_address]
    push rax
    mov eax, [cmd_line_arg2_address]
    push rax

    pop rax
    pop rax

    xor rax, rax
    mov eax, [cmd_line_arg2_address]
    mov [inputfile_name_address], eax

    xor eax, eax
    xor r9, r9
    xor r8, r8

    call clrscr
    invoke printf, "parse_pe (v8)- parse the pe header and print the fields."
    call print_newline


    ;fastcall open_file, input_filename
    fastcall open_file, [inputfile_name_address]
    cmp eax, 0
    jne .open_file_returned_without_error
    call print_newline
    invoke printf, "error reported."
    jmp main_return

    .open_file_returned_without_error:
        call print_newline
        invoke printf, "no error reported."


main_return:
    call print_newline
    invoke printf, "program ends."
    call print_newline
    popall
    ret


proc print_help
    pushall
    fastcall printn, "parse_pe v8. parse pe file and print pe header."
    fastcall printn, "command execution"
    fastcall printn, "parse_pe.exe <input_pefile_name>"
    fastcall printn, "example"
    fastcall printn, "parse_pe.exe parse_pe.exe"
    fastcall printn, "parse_pe.exe calc.exe"
    flushall
    popall
    ret
endp


include 'ifh.asm'   ; input file handling 
include 'parse_pe.asm'
include 'parse_pe64.asm'
include 'printhex.asm'



section '.idata' import data readable
    library msvcrt, 'msvcrt.dll',\
            kernel32, 'kernel32.dll'
        import msvcrt,\
            printf, 'printf'

        include 'C:\fasm\INCLUDE\API\KERNEL32.INC'
