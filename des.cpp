#include "cipher_api.h"
#include <cstring>
#include <vector>
#include <cstdint>


static const AlgorithmInfo INFO = {
    "Simplified DES",
    2,      
    1,      
    false    
};

EXPORT_API const AlgorithmInfo* get_algorithm_info(void) {
    return &INFO;
}

EXPORT_API size_t get_output_size(size_t input_size, int /*operation_type*/) {
    return input_size;
}

// Таблицы перестановок SDES
static const int IP[] = {1, 5, 2, 0, 3, 7, 4, 6};
static const int IP_inv[] = {3, 0, 2, 4, 6, 1, 7, 5};
static const int EP[] = {3, 0, 1, 2, 1, 2, 3, 0};
static const int P4[] = {1, 3, 2, 0};

static const uint8_t SBOX0[4][4] = {
    {1, 0, 3, 2}, {3, 2, 1, 0}, {0, 2, 1, 3}, {3, 1, 3, 2}
};
static const uint8_t SBOX1[4][4] = {
    {0, 1, 2, 3}, {2, 0, 1, 3}, {3, 0, 1, 0}, {2, 1, 0, 3}
};

// Универсальная функция перестановки бит для S-DES
static inline uint16_t permute_bits(uint16_t input, const int* table, int table_size, int input_size) {
    uint16_t output = 0;
    for (int i = 0; i < table_size; ++i) {
        int bit_pos = input_size - 1 - table[i];
        int bit = (input >> bit_pos) & 1;
        output = (output << 1) | bit;
    }
    return output;
}

static inline uint16_t left_shift_5(uint16_t val, int shifts) {
    return ((val << shifts) | (val >> (5 - shifts))) & 0x1F;
}

// Генерация раундовых ключей K1 и K2 из 10-битного мастер-ключа
static void generate_sdes_keys(uint16_t master_key, uint8_t& k1, uint8_t& k2) {
    static const int P10[] = {2, 4, 1, 6, 3, 9, 0, 8, 7, 5};
    static const int P8[] = {5, 2, 6, 3, 7, 4, 9, 8};

    uint16_t p10_key = permute_bits(master_key, P10, 10, 10);
    uint16_t left = (p10_key >> 5) & 0x1F;
    uint16_t right = p10_key & 0x1F;

    // Раундовый ключ 1 (LS-1 + P8)
    left = left_shift_5(left, 1);
    right = left_shift_5(right, 1);
    k1 = (uint8_t)permute_bits((left << 5) | right, P8, 8, 10);

    // Раундовый ключ 2 (LS-2 + P8)
    left = left_shift_5(left, 2);
    right = left_shift_5(right, 2);
    k2 = (uint8_t)permute_bits((left << 5) | right, P8, 8, 10);
}

// Функция Фейстеля f(R, K)
static uint8_t f_func(uint8_t R, uint8_t K) {
    uint8_t expanded = (uint8_t)permute_bits(R, EP, 8, 4);
    uint8_t xor_res = expanded ^ K;

    // SBOX0
    uint8_t left_chunk = (xor_res >> 4) & 0x0F;
    int row0 = (((left_chunk >> 3) & 1) << 1) | (left_chunk & 1);
    int col0 = (left_chunk >> 1) & 0x03;
    uint8_t s0_out = SBOX0[row0][col0];

    // SBOX1
    uint8_t right_chunk = xor_res & 0x0F;
    int row1 = (((right_chunk >> 3) & 1) << 1) | (right_chunk & 1);
    int col1 = (right_chunk >> 1) & 0x03;
    uint8_t s1_out = SBOX1[row1][col1];

    uint8_t combined = (s0_out << 2) | s1_out;
    return (uint8_t)permute_bits(combined, P4, 4, 4);
}

// Шифрование/дешифрование одного 8-битного блока
static uint8_t sdes_block(uint8_t block, uint8_t k1, uint8_t k2, bool decrypt) {
    uint8_t perm = (uint8_t)permute_bits(block, IP, 8, 8);
    uint8_t L0 = (perm >> 4) & 0x0F;
    uint8_t R0 = perm & 0x0F;

    uint8_t keyA = decrypt ? k2 : k1;
    uint8_t keyB = decrypt ? k1 : k2;

    uint8_t L1 = L0 ^ f_func(R0, keyA);
    uint8_t R1 = R0;

    uint8_t L1_sw = R1;
    uint8_t R1_sw = L1;

    uint8_t L2 = L1_sw ^ f_func(R1_sw, keyB);
    uint8_t R2 = R1_sw;

    uint8_t combined = (L2 << 4) | R2;
    return (uint8_t)permute_bits(combined, IP_inv, 8, 8);
}

EXPORT_API int encrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    if (key.size != INFO.key_size) return CRYPTO_ERR_KEY_SIZE;
    if (output->size < input.size) return CRYPTO_ERR_ALLOC;

    uint16_t master_key = ((uint16_t)key.data[0] << 8) | key.data[1];
    master_key &= 0x03FF; 

    uint8_t k1, k2;
    generate_sdes_keys(master_key, k1, k2);

    for (size_t i = 0; i < input.size; ++i) {
        output->data[i] = sdes_block(input.data[i], k1, k2, false);
    }
    output->size = input.size;
    return CRYPTO_SUCCESS;
}

EXPORT_API int decrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    if (key.size != INFO.key_size) return CRYPTO_ERR_KEY_SIZE;
    if (output->size < input.size) return CRYPTO_ERR_ALLOC;

    uint16_t master_key = ((uint16_t)key.data[0] << 8) | key.data[1];
    master_key &= 0x03FF;

    uint8_t k1, k2;
    generate_sdes_keys(master_key, k1, k2);

    for (size_t i = 0; i < input.size; ++i) {
        output->data[i] = sdes_block(input.data[i], k1, k2, true);
    }
    output->size = input.size;
    return CRYPTO_SUCCESS;
}

EXPORT_API int encrypt_test(ConstBuffer key, ConstBuffer /*iv*/,
                            ConstBuffer input, MutBuffer* output) {
    return encrypt(key, input, output);
}