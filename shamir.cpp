#include "CipherAPI.h"
#include <cstring>
#include <fstream>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <random>
#include <algorithm>
#include <cmath>

// ----------------------------------------------------------------------
// Вспомогательные функции
// ----------------------------------------------------------------------
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
        char* endptr;
        long val = strtol(byte_str.c_str(), &endptr, 16);
        if (*endptr != 0) break;
        bytes.push_back((unsigned char)val);
    }
    return bytes;
}

// Быстрое возведение в степень по модулю
static long long mod_pow(long long base, long long exp, long long mod) {
    long long result = 1;
    base = base % mod;
    while (exp > 0) {
        if (exp & 1)
            result = (result * base) % mod;
        base = (base * base) % mod;
        exp >>= 1;
    }
    return result;
}

// Проверка числа на простоту (упрощённая)
static bool is_prime(long long n) {
    if (n <= 1) return false;
    if (n <= 3) return true;
    if (n % 2 == 0 || n % 3 == 0) return false;
    for (long long i = 5; i * i <= n; i += 6) {
        if (n % i == 0 || n % (i + 2) == 0)
            return false;
    }
    return true;
}

// Генерация случайного простого числа
static long long generate_prime() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<long long> dist(100000, 500000);
    
    for (int attempt = 0; attempt < 100; ++attempt) {
        long long candidate = dist(gen);
        if (is_prime(candidate))
            return candidate;
    }
    return 100003; // простое по умолчанию
}

// НОД для проверки взаимной простоты
static long long gcd(long long a, long long b) {
    while (b != 0) {
        long long t = b;
        b = a % b;
        a = t;
    }
    return a;
}

// Генерация случайного числа, взаимно простого с (p-1)
static long long generate_exponent(long long phi) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<long long> dist(2, phi - 1);
    
    for (int attempt = 0; attempt < 100; ++attempt) {
        long long candidate = dist(gen);
        if (gcd(candidate, phi) == 1)
            return candidate;
    }
    return 65537;
}

// Нахождение обратного элемента по модулю
static long long mod_inverse(long long a, long long m) {
    long long m0 = m, t, q;
    long long x0 = 0, x1 = 1;
    
    if (m == 1) return 0;
    
    while (a > 1) {
        q = a / m;
        t = m;
        m = a % m;
        a = t;
        t = x0;
        x0 = x1 - q * x0;
        x1 = t;
    }
    
    if (x1 < 0) x1 += m0;
    return x1;
}

// Преобразование текста в число (для шифрования)
static std::vector<long long> text_to_blocks(const std::string& text, size_t block_size = 2) {
    std::vector<long long> blocks;
    for (size_t i = 0; i < text.length(); i += block_size) {
        long long block = 0;
        for (size_t j = 0; j < block_size && i + j < text.length(); ++j) {
            block = (block << 8) | (unsigned char)text[i + j];
        }
        blocks.push_back(block);
    }
    return blocks;
}

// Преобразование чисел обратно в текст
static std::string blocks_to_text(const std::vector<long long>& blocks) {
    std::string result;
    for (long long block : blocks) {
        if (block == 0) {
            result += '\0';
            continue;
        }
        std::string block_str;
        long long temp = block;
        while (temp > 0) {
            block_str.insert(0, 1, (char)(temp & 0xFF));
            temp >>= 8;
        }
        result += block_str;
    }
    return result;
}

// ----------------------------------------------------------------------
// Экспортируемые функции (hex-интерфейс)
// ----------------------------------------------------------------------

EXPORT_API void encrypt_text(const char* input_hex, const char* key, char* output_hex) {
    std::string key_str(key);
    std::string public_key_str, prime_str;
    
    size_t colon_pos = key_str.find(':');
    if (colon_pos != std::string::npos) {
        public_key_str = key_str.substr(0, colon_pos);
        prime_str = key_str.substr(colon_pos + 1);
    } else {
        public_key_str = key_str;
        prime_str = "100003";
    }
    
    long long public_key_num = std::stoll(public_key_str);
    long long prime_num = std::stoll(prime_str);
    
    // Преобразуем входную hex-строку в текст
    std::vector<unsigned char> input_bytes = hex_to_bytes(input_hex);
    std::string input_text(input_bytes.begin(), input_bytes.end());
    
    // Разбиваем текст на блоки и шифруем
    std::vector<long long> blocks = text_to_blocks(input_text);
    std::vector<long long> encrypted_blocks;
    
    for (long long block : blocks) {
        long long encrypted = mod_pow(block, public_key_num, prime_num);
        encrypted_blocks.push_back(encrypted);
    }
    
    // Преобразуем зашифрованные блоки в строку
    std::string encrypted_text;
    for (size_t i = 0; i < encrypted_blocks.size(); ++i) {
        if (i > 0) encrypted_text += " ";
        encrypted_text += std::to_string(encrypted_blocks[i]);
    }
    
    // Возвращаем как hex
    std::string hex_result = bytes_to_hex((unsigned char*)encrypted_text.c_str(), encrypted_text.length());
    strcpy(output_hex, hex_result.c_str());
}

EXPORT_API void decrypt_text(const char* input_hex, const char* key, char* output_hex) {
    std::string key_str(key);
    std::string private_key_str, prime_str;
    
    size_t colon_pos = key_str.find(':');
    if (colon_pos != std::string::npos) {
        private_key_str = key_str.substr(0, colon_pos);
        prime_str = key_str.substr(colon_pos + 1);
    } else {
        private_key_str = key_str;
        prime_str = "100003";
    }
    
    long long private_key_num = std::stoll(private_key_str);
    long long prime_num = std::stoll(prime_str);
    
    // Преобразуем входную hex-строку в строку с числами
    std::vector<unsigned char> input_bytes = hex_to_bytes(input_hex);
    std::string input_str(input_bytes.begin(), input_bytes.end());
    
    // Парсим блоки
    std::vector<long long> encrypted_blocks;
    std::stringstream ss(input_str);
    long long block;
    while (ss >> block) {
        encrypted_blocks.push_back(block);
    }
    
    // Расшифровываем блоки
    std::vector<long long> decrypted_blocks;
    for (long long encrypted_block : encrypted_blocks) {
        long long decrypted = mod_pow(encrypted_block, private_key_num, prime_num);
        decrypted_blocks.push_back(decrypted);
    }
    
    // Преобразуем обратно в текст
    std::string decrypted_text = blocks_to_text(decrypted_blocks);
    
    // Возвращаем как hex
    std::string hex_result = bytes_to_hex((unsigned char*)decrypted_text.c_str(), decrypted_text.length());
    strcpy(output_hex, hex_result.c_str());
}

// ----------------------------------------------------------------------
// Файловые операции для Шамира
// ----------------------------------------------------------------------
static bool process_file_shamir(const char* in_path, const char* out_path, const char* key) {
    std::ifstream in(in_path, std::ios::binary);
    std::ofstream out(out_path, std::ios::binary);
    
    if (!in.is_open() || !out.is_open()) {
        return false;
    }
    
    std::string key_str(key);
    std::string exponent_str, prime_str;
    size_t colon_pos = key_str.find(':');
    if (colon_pos != std::string::npos) {
        exponent_str = key_str.substr(0, colon_pos);
        prime_str = key_str.substr(colon_pos + 1);
    } else {
        exponent_str = key_str;
        prime_str = "100003";
    }
    
    long long exponent = std::stoll(exponent_str);
    long long prime = std::stoll(prime_str);
    
    // Читаем файл блоками по 2 байта
    unsigned char buffer[2];
    while (in.read((char*)buffer, 2) || in.gcount() > 0) {
        size_t bytes_read = in.gcount();
        if (bytes_read == 0) break;
        
        long long block = 0;
        for (size_t i = 0; i < bytes_read; ++i) {
            block = (block << 8) | buffer[i];
        }
        
        long long processed = mod_pow(block, exponent, prime);
        
        // Записываем результат
        unsigned char out_buffer[2];
        out_buffer[0] = (processed >> 8) & 0xFF;
        out_buffer[1] = processed & 0xFF;
        out.write((char*)out_buffer, 2);
    }
    
    return true;
}

EXPORT_API bool encrypt_file(const char* in_path, const char* out_path, const char* key) {
    try {
        return process_file_shamir(in_path, out_path, key);
    } catch (...) {
        return false;
    }
}

EXPORT_API bool decrypt_file(const char* in_path, const char* out_path, const char* key) {
    try {
        return process_file_shamir(in_path, out_path, key);
    } catch (...) {
        return false;
    }
}

EXPORT_API void generate_key(char* output_key) {
    // Генерируем пару ключей
    long long prime = generate_prime();
    long long phi = prime - 1;
    long long c = generate_exponent(phi);
    long long d = mod_inverse(c, phi);
    
    // Формат: "public_key:private_key:prime"
    std::string key_pair = std::to_string(c) + ":" + std::to_string(d) + ":" + std::to_string(prime);
    strcpy(output_key, key_pair.c_str());
}