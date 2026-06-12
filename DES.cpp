#include "CipherAPI.h"
#include <cstring>
#include <fstream>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <cctype>

// Вспомогательные функции для hex-преобразований внутри библиотеки
static std::string bytes_to_hex(const unsigned char* data, size_t len) {
    std::stringstream ss;
    for (size_t i = 0; i < len; ++i)
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    return ss.str();
}

static std::vector<unsigned char> hex_to_bytes(const std::string& hex) {
    std::vector<unsigned char> bytes;
    if (hex.length() % 2 != 0) return bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byte_str = hex.substr(i, 2);
        char* end;
        long val = strtol(byte_str.c_str(), &end, 16);
        if (*end != 0) break;
        bytes.push_back((unsigned char)val);
    }
    return bytes;
}

// Поблочная обработка (8 байт) – исходный XOR
static void process_block(const unsigned char* in_block, const char* key, unsigned char* out_block) {
    for (int i = 0; i < 8; ++i)
        out_block[i] = in_block[i] ^ key[i % 8];
}

// Экспортируемые функции
EXPORT_API void encrypt_text(const char* input_hex, const char* key, char* output_hex) {
    std::vector<unsigned char> plain = hex_to_bytes(input_hex);
    size_t len = plain.size();
    if (len == 0) {
        output_hex[0] = '\0';
        return;
    }

    size_t padded_len = ((len + 7) / 8) * 8;
    std::vector<unsigned char> cipher(padded_len, 0);
    for (size_t i = 0; i < len; ++i) cipher[i] = plain[i];

    // Шифрование
    for (size_t i = 0; i < padded_len; i += 8) {
        unsigned char out_block[8];
        process_block(&cipher[i], key, out_block);
        memcpy(&cipher[i], out_block, 8);
    }

    // Результат в hex
    std::string hex_result = bytes_to_hex(cipher.data(), padded_len);
    strcpy(output_hex, hex_result.c_str());
}

EXPORT_API void decrypt_text(const char* input_hex, const char* key, char* output_hex) {
    std::vector<unsigned char> cipher = hex_to_bytes(input_hex);
    size_t len = cipher.size();
    if (len == 0 || len % 8 != 0) {
        output_hex[0] = '\0';
        return;
    }

    // Расшифрование (XOR симметричен)
    for (size_t i = 0; i < len; i += 8) {
        unsigned char out_block[8];
        process_block(&cipher[i], key, out_block);
        memcpy(&cipher[i], out_block, 8);
    }

    std::string hex_result = bytes_to_hex(cipher.data(), len);
    strcpy(output_hex, hex_result.c_str());
}

EXPORT_API bool encrypt_file(const char* in_path, const char* out_path, const char* key) {
    std::ifstream in(in_path, std::ios::binary);
    std::ofstream out(out_path, std::ios::binary);
    if (!in.is_open() || !out.is_open()) return false;

    unsigned char buffer[8];
    while (in.read((char*)buffer, 8) || in.gcount() > 0) {
        size_t bytes_read = in.gcount();
        if (bytes_read == 0) break;
        // Если последний блок неполный, дополняем нулями
        for (size_t i = bytes_read; i < 8; ++i) buffer[i] = 0;
        unsigned char out_block[8];
        process_block(buffer, key, out_block);
        out.write((char*)out_block, 8);
    }
    return true;
}

EXPORT_API bool decrypt_file(const char* in_path, const char* out_path, const char* key) {
    // Для XOR шифрование и дешифрование одинаковы
    return encrypt_file(in_path, out_path, key);
}

EXPORT_API void generate_key(char* output_key) {
    const char* default_des_key = "DESKEY56";
    strcpy(output_key, default_des_key);
}