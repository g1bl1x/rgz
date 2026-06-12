#include "cipher_api.h"
#include <cstring>
#include <vector>

static const AlgorithmInfo INFO = {
    "Classic DES",
    8,       // key_size (64 bits, including parity bits)
    8,       // block_size
    false    // uses_iv (ECB mode)
};

EXPORT_API const AlgorithmInfo* get_algorithm_info(void) {
    return &INFO;
}

EXPORT_API size_t get_output_size(size_t input_size, int operation_type) {
    if (operation_type == 1) { // encrypt
        size_t padding = 8 - (input_size % 8);
        if (padding == 0) padding = 8;
        return input_size + padding;
    } else { // decrypt
        return input_size;
    }
}

// Таблицы перестановок DES
static const uint8_t IP[64] = {
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9,  1, 59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7
};

static const uint8_t FP[64] = {
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41,  9, 49, 17, 57, 25
};

static const uint8_t E[48] = {
    32,  1,  2,  3,  4,  5,  4,  5,  6,  7,  8,  9,
     8,  9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32,  1
};

static const uint8_t P[32] = {
    16,  7, 20, 21, 29, 12, 28, 17,  1, 15, 23, 26,  5, 18, 31, 10,
     2,  8, 24, 14, 32, 27,  3,  9, 19, 13, 30,  6, 22, 11,  4, 25
};

static const uint8_t PC1[56] = {
    57, 49, 41, 33, 25, 17,  9,  1, 58, 50, 42, 34, 26, 18,
    10,  2, 59, 51, 43, 35, 27, 19, 11,  3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,  7, 62, 54, 46, 38, 30, 22,
    14,  6, 61, 53, 45, 37, 29, 21, 13,  5, 28, 20, 12,  4
};

static const uint8_t PC2[48] = {
    14, 17, 11, 24,  1,  5,  3, 28, 15,  6, 21, 10,
    23, 19, 12,  4, 26,  8, 16,  7, 27, 20, 13,  2,
    41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
};

static const uint8_t SHIFTS[16] = {
    1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
};

static const uint8_t SBOX[8][64] = {
    {14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,
      0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
      4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,
     15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13},
    {15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,
      3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,
      0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15,
     13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9},
    {10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
     13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
     13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
      1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12},
    { 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,
     13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,
     10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
      3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14},
    { 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9,
     14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,
      4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
     11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3},
    {12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
     10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
      9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
      4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13},
    { 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
     13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
      1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
      6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12},
    {13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
      1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
      7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
      2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11}
};

// Вспомогательные функции для работы с битами
static inline bool get_bit(uint64_t data, int pos) {
    return (data >> (64 - pos)) & 1;
}

static inline void set_bit(uint64_t& data, int pos, bool val) {
    if (val) data |= (1ULL << (64 - pos));
    else data &= ~(1ULL << (64 - pos));
}

static inline uint64_t permute(uint64_t input, const uint8_t* table, int size) {
    uint64_t output = 0;
    for (int i = 0; i < size; ++i) {
        if (get_bit(input, table[i])) {
            output |= (1ULL << (size - 1 - i));
        }
    }
    return output;
}

static inline uint64_t rotl28(uint64_t val, int shifts) {
    uint32_t v = val & 0xFFFFFFF;
    return ((v << shifts) | (v >> (28 - shifts))) & 0xFFFFFFF;
}

static void generate_keys(uint64_t key, uint64_t subkeys[16]) {
    uint64_t pc1 = permute(key, PC1, 56);
    uint64_t C = (pc1 >> 28) & 0xFFFFFFF;
    uint64_t D = pc1 & 0xFFFFFFF;

    for (int i = 0; i < 16; ++i) {
        C = rotl28(C, SHIFTS[i]);
        D = rotl28(D, SHIFTS[i]);
        uint64_t CD = (C << 28) | D;
        subkeys[i] = permute(CD << 8, PC2, 48);
    }
}

static uint64_t f_func(uint64_t R, uint64_t K) {
    uint64_t expandedR = permute(R << 32, E, 48);
    uint64_t xor_res = expandedR ^ K;
    uint32_t sbox_out = 0;
    
    for (int i = 0; i < 8; ++i) {
        uint8_t block = (xor_res >> (42 - i * 6)) & 0x3F;
        int row = ((block & 0x20) >> 4) | (block & 0x01);
        int col = (block & 0x1E) >> 1;
        uint8_t val = SBOX[i][row * 16 + col];
        sbox_out |= (val << (28 - i * 4));
    }
    return permute(static_cast<uint64_t>(sbox_out) << 32, P, 32);
}

static uint64_t des_block(uint64_t block, const uint64_t subkeys[16], bool decrypt) {
    block = permute(block, IP, 64);
    uint64_t L = (block >> 32) & 0xFFFFFFFF;
    uint64_t R = block & 0xFFFFFFFF;

    for (int i = 0; i < 16; ++i) {
        uint64_t K = decrypt ? subkeys[15 - i] : subkeys[i];
        uint64_t nextL = R;
        uint64_t nextR = L ^ f_func(R, K);
        L = nextL;
        R = nextR;
    }
    
    uint64_t pre_output = (R << 32) | L;
    return permute(pre_output, FP, 64);
}

static uint64_t bytes_to_u64(const uint8_t* b) {
    uint64_t val = 0;
    for(int i = 0; i < 8; ++i) val = (val << 8) | b[i];
    return val;
}

static void u64_to_bytes(uint64_t val, uint8_t* b) {
    for(int i = 7; i >= 0; --i) {
        b[i] = val & 0xFF;
        val >>= 8;
    }
}

// PKCS#7 паддинг для поддержки произвольных длин файлов
static void add_pkcs7_padding(std::vector<uint8_t>& data, size_t block_size) {
    size_t padding = block_size - (data.size() % block_size);
    if (padding == 0) padding = block_size;
    for (size_t i = 0; i < padding; ++i) {
        data.push_back(static_cast<uint8_t>(padding));
    }
}

static bool remove_pkcs7_padding(std::vector<uint8_t>& data) {
    if (data.empty()) return false;
    uint8_t padding = data.back();
    if (padding == 0 || padding > 8) return false;
    for (size_t i = data.size() - padding; i < data.size(); ++i) {
        if (data[i] != padding) return false;
    }
    data.resize(data.size() - padding);
    return true;
}

EXPORT_API int encrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    if (key.size != INFO.key_size) return CRYPTO_ERR_KEY_SIZE;
    
    uint64_t u64_key = bytes_to_u64(key.data);
    uint64_t subkeys[16];
    generate_keys(u64_key, subkeys);
    
    std::vector<uint8_t> plain(input.data, input.data + input.size);
    add_pkcs7_padding(plain, 8);
    
    if (output->size < plain.size()) return CRYPTO_ERR_ALLOC;
    
    for (size_t i = 0; i < plain.size(); i += 8) {
        uint64_t block = bytes_to_u64(&plain[i]);
        uint64_t encrypted = des_block(block, subkeys, false);
        u64_to_bytes(encrypted, &output->data[i]);
    }
    output->size = plain.size();
    return CRYPTO_SUCCESS;
}

EXPORT_API int decrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    if (key.size != INFO.key_size) return CRYPTO_ERR_KEY_SIZE;
    if (input.size % 8 != 0) return CRYPTO_ERR_DECRYPT;
    if (output->size < input.size) return CRYPTO_ERR_ALLOC;
    
    uint64_t u64_key = bytes_to_u64(key.data);
    uint64_t subkeys[16];
    generate_keys(u64_key, subkeys);
    
    std::vector<uint8_t> decrypted(input.size);
    for (size_t i = 0; i < input.size; i += 8) {
        uint64_t block = bytes_to_u64(&input.data[i]);
        uint64_t dec_block = des_block(block, subkeys, true);
        u64_to_bytes(dec_block, &decrypted[i]);
    }
    
    if (!remove_pkcs7_padding(decrypted)) {
        return CRYPTO_ERR_DECRYPT;
    }
    
    memcpy(output->data, decrypted.data(), decrypted.size());
    output->size = decrypted.size();
    return CRYPTO_SUCCESS;
}

EXPORT_API int encrypt_test(ConstBuffer key, ConstBuffer /*iv*/,
                            ConstBuffer input, MutBuffer* output) {
    return encrypt(key, input, output);
}