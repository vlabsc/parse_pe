# parse_pe
parse_pe - parses pe header and prints it - simple - written in FASM (https://flatassembler.net/)

assembly process:
eiether execute run.bat or this command
" fasm main6.asm parse_pe.exe "

FASM (flat assember download) -> https://flatassembler.net/download.php

its a simple and fast pe32 header parser. prints the important values of pe32 header.

Yet to do:

more error checking

import table and other API printing



![image](https://github.com/vlabsc/parse_pe/assets/5446466/854dd05a-680d-47f3-8689-533857430e7b)
first parses the input pe32 file

![image](https://github.com/vlabsc/parse_pe/assets/5446466/246235a6-a3a6-47cc-b7f5-2e69e07f8980)
prints the dos header, nt header signature, coff file header and optional header

![image](https://github.com/vlabsc/parse_pe/assets/5446466/0fec4cbb-9bcc-47a3-8f16-ad48d1b47f26)
walks through the data directories, and prints section headers

![image](https://github.com/vlabsc/parse_pe/assets/5446466/a291f560-6bb3-4aac-8c2d-b75fd3412ce8)
prints the first 24 bytes of each section in hex



