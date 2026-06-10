#include "CipherAPI.h"
#include <cstring>
#include <fstream>
#include <stdexcept>
#include <cstdlib>
#include <ctime>

EXPORT_API void encrypt_text(const char* input, const char* key, char* output) {
    size_t text_len = strlen(input);
    size_t key_len = strlen(key);
    if (key_len == 0) return;

    for (size_t i = 0; i < text_len; ++i) {
        output[i] = (char)((unsigned char)input[i] + (unsigned char)key[i % key_len]);
    }
    output[text_len] = '\0';
}

EXPORT_API void decrypt_text(const char* input, const char* key, char* output) {
    size_t text_len = strlen(input);
    size_t key_len = strlen(key);
    if (key_len == 0) return;

    for (size_t i = 0; i < text_len; ++i) {
        output[i] = (char)((unsigned char)input[i] - (unsigned char)key[i % key_len]);
    }
    output[text_len] = '\0';
}

EXPORT_API bool encrypt_file(const char* in_path, const char* out_path, const char* key) {
    std::ifstream in(in_path, std::ios::binary);
    std::ofstream out(out_path, std::ios::binary);
    if (!in.is_open() || !out.is_open()) return false;

    size_t key_len = strlen(key);
    size_t i = 0;
    char ch;
    while (in.get(ch)) {
        char encrypted = (char)((unsigned char)ch + (unsigned char)key[i % key_len]);
        out.put(encrypted);
        i++;
    }
    return true;
}

EXPORT_API bool decrypt_file(const char* in_path, const char* out_path, const char* key) {
    std::ifstream in(in_path, std::ios::binary);
    std::ofstream out(out_path, std::ios::binary);
    if (!in.is_open() || !out.is_open()) return false;

    size_t key_len = strlen(key);
    size_t i = 0;
    char ch;
    while (in.get(ch)) {
        char decrypted = (char)((unsigned char)ch - (unsigned char)key[i % key_len]);
        out.put(decrypted);
        i++;
    }
    return true;
}

EXPORT_API void generate_key(char* output_key) {
    srand((unsigned)time(NULL));
    int length = 8 + rand() % 8; // Ключ от 8 до 15 символов
    for (int i = 0; i < length; ++i) {
        output_key[i] = 'A' + (rand() % 26);
    }
    output_key[length] = '\0';
}