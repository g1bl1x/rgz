#include "CipherAPI.h"
#include <cstring>
#include <fstream>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <cstdlib>
#include <ctime>

// Вспомогательные функции для hex-преобразований
static std::string bytes_to_hex(const unsigned char* data, size_t len) {
    std::stringstream ss;
    for (size_t i = 0; i < len; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    }
    return ss.str();
}

static std::vector<unsigned char> hex_to_bytes(const std::string& hex) {
    std::vector<unsigned char> bytes;
    if (hex.length() % 2 != 0) return bytes;  // некорректная hex-строка
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byte_str = hex.substr(i, 2);
        char* endptr;
        long val = strtol(byte_str.c_str(), &endptr, 16);
        if (*endptr != 0) break;             // неверный символ
        bytes.push_back((unsigned char)val);
    }
    return bytes;
}

// Алгоритм Виженера над байтами (сдвиг по модулю 256)
static void vigenere_crypt(const unsigned char* input, size_t len, const char* key, unsigned char* output, bool encrypt) {
    size_t key_len = strlen(key);
    if (key_len == 0) {
        memcpy(output, input, len);
        return;
    }
    for (size_t i = 0; i < len; ++i) {
        int k = (unsigned char)key[i % key_len];
        if (encrypt) {
            output[i] = (input[i] + k) % 256;
        } else {
            output[i] = (input[i] - k + 256) % 256;
        }
    }
}

// Экспортируемые функции (текст через hex)
EXPORT_API void encrypt_text(const char* input_hex, const char* key, char* output_hex) {
    std::vector<unsigned char> plain = hex_to_bytes(input_hex);
    size_t len = plain.size();
    std::vector<unsigned char> cipher(len);
    vigenere_crypt(plain.data(), len, key, cipher.data(), true);
    std::string hex_result = bytes_to_hex(cipher.data(), len);
    strcpy(output_hex, hex_result.c_str());
}

EXPORT_API void decrypt_text(const char* input_hex, const char* key, char* output_hex) {
    std::vector<unsigned char> cipher = hex_to_bytes(input_hex);
    size_t len = cipher.size();
    std::vector<unsigned char> plain(len);
    vigenere_crypt(cipher.data(), len, key, plain.data(), false);
    std::string hex_result = bytes_to_hex(plain.data(), len);
    strcpy(output_hex, hex_result.c_str());
}


// Файловые операции (работают с бинарными данными)
EXPORT_API bool encrypt_file(const char* in_path, const char* out_path, const char* key) {
    std::ifstream in(in_path, std::ios::binary);
    std::ofstream out(out_path, std::ios::binary);
    if (!in.is_open() || !out.is_open()) return false;

    const size_t BUFFER_SIZE = 4096;
    unsigned char buffer[BUFFER_SIZE];
    unsigned char output[BUFFER_SIZE];
    size_t key_len = strlen(key);
    if (key_len == 0) return false;

    while (in.good()) {
        in.read(reinterpret_cast<char*>(buffer), BUFFER_SIZE);
        size_t bytes_read = in.gcount();
        if (bytes_read == 0) break;

        for (size_t i = 0; i < bytes_read; ++i) {
            int k = (unsigned char)key[i % key_len];
            output[i] = (buffer[i] + k) % 256;
        }
        out.write(reinterpret_cast<char*>(output), bytes_read);
    }
    return true;
}

EXPORT_API bool decrypt_file(const char* in_path, const char* out_path, const char* key) {
    std::ifstream in(in_path, std::ios::binary);
    std::ofstream out(out_path, std::ios::binary);
    if (!in.is_open() || !out.is_open()) return false;

    const size_t BUFFER_SIZE = 4096;
    unsigned char buffer[BUFFER_SIZE];
    unsigned char output[BUFFER_SIZE];
    size_t key_len = strlen(key);
    if (key_len == 0) return false;

    while (in.good()) {
        in.read(reinterpret_cast<char*>(buffer), BUFFER_SIZE);
        size_t bytes_read = in.gcount();
        if (bytes_read == 0) break;

        for (size_t i = 0; i < bytes_read; ++i) {
            int k = (unsigned char)key[i % key_len];
            output[i] = (buffer[i] - k + 256) % 256;
        }
        out.write(reinterpret_cast<char*>(output), bytes_read);
    }
    return true;
}

// Генерация ключа (случайная строка из латинских букв длиной 8–15)
EXPORT_API void generate_key(char* output_key) {
    std::srand(static_cast<unsigned>(std::time(nullptr)));
    int length = 8 + std::rand() % 8;
    for (int i = 0; i < length; ++i) {
        output_key[i] = 'A' + (std::rand() % 26);
    }
    output_key[length] = '\0';
}