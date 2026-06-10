#include "CipherAPI.h"
#include <cstring>
#include <fstream>
#include <vector>

// Заглушка для поблочной обработки (8 байт)
void process_block(const unsigned char* in_block, const char* key, unsigned char* out_block, bool is_encrypt) {
    // Для демонстрации структуры используем простой XOR, совместимый с 8-байтовыми блоками.
    for (int i = 0; i < 8; ++i) {
        out_block[i] = in_block[i] ^ key[i % 8]; 
    }
}

EXPORT_API void encrypt_text(const char* input, const char* key, char* output) {
    size_t len = strlen(input);
    size_t padded_len = ((len + 7) / 8) * 8;
    
    for (size_t i = 0; i < padded_len; i += 8) {
        unsigned char in_block[8] = {0};
        unsigned char out_block[8] = {0};
        
        for (size_t j = 0; j < 8; ++j) {
            if (i + j < len) in_block[j] = input[i + j];
        }
        process_block(in_block, key, out_block, true);
        memcpy(output + i, out_block, 8);
    }
    output[padded_len] = '\0';
}

// Функции decrypt_text, decrypt_file реализуются аналогично поблочно.
EXPORT_API bool encrypt_file(const char* in_path, const char* out_path, const char* key) {
    std::ifstream in(in_path, std::ios::binary);
    std::ofstream out(out_path, std::ios::binary);
    if (!in.is_open() || !out.is_open()) return false;

    unsigned char buffer[8] = {0};
    unsigned char out_buffer[8] = {0};
    
    while (in.read((char*)buffer, 8) || in.gcount() > 0) {
        process_block(buffer, key, out_buffer, true);
        out.write((char*)out_buffer, 8);
        memset(buffer, 0, 8);
    }
    return true;
}

EXPORT_API void generate_key(char* output_key) {
    const char* default_des_key = "DESKEY56";
    strcpy(output_key, default_des_key);
}