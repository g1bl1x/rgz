#include "cipher_api.h"
#include <cstring>
#include <vector>

static const AlgorithmInfo INFO = {
    "DES-like XOR Cipher",
    8,       // key_size (64 bits)
    8,       // block_size
    false    // uses_iv
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

static void xor_block(const uint8_t* input, const uint8_t* key, uint8_t* output, size_t size) {
    for (size_t i = 0; i < size; ++i) {
        output[i] = input[i] ^ key[i % 8];
    }
}

// PKCS#7 паддинг
static void add_pkcs7_padding(std::vector<uint8_t>& data, size_t block_size) {
    size_t padding = block_size - (data.size() % block_size);
    if (padding == 0) padding = block_size;
    for (size_t i = 0; i < padding; ++i) {
        data.push_back(static_cast<uint8_t>(padding));
    }
}

// Удаление PKCS#7 паддинга
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
    
    // Копируем входные данные и добавляем паддинг
    std::vector<uint8_t> plain(input.data, input.data + input.size);
    add_pkcs7_padding(plain, 8);
    
    if (output->size < plain.size()) return CRYPTO_ERR_ALLOC;
    
    // Шифрование поблочно
    for (size_t i = 0; i < plain.size(); i += 8) {
        xor_block(&plain[i], key.data, &output->data[i], 8);
    }
    output->size = plain.size();
    return CRYPTO_SUCCESS;
}

EXPORT_API int decrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    if (key.size != INFO.key_size) return CRYPTO_ERR_KEY_SIZE;
    if (input.size % 8 != 0) return CRYPTO_ERR_DECRYPT;
    if (output->size < input.size) return CRYPTO_ERR_ALLOC;
    
    // Расшифрование поблочно
    std::vector<uint8_t> decrypted(input.size);
    for (size_t i = 0; i < input.size; i += 8) {
        xor_block(&input.data[i], key.data, &decrypted[i], 8);
    }
    
    // Удаление паддинга
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