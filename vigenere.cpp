#include "cipher_api.h"
#include <cstring>
#include <cstdlib>
#include <ctime>

static const AlgorithmInfo INFO = {
    "Vigenere Cipher",
    32,      
    1,       
    false    // uses_iv
};

EXPORT_API const AlgorithmInfo* get_algorithm_info(void) {
    return &INFO;
}

EXPORT_API size_t get_output_size(size_t input_size, int /*operation_type*/) {
    return input_size; 
}

EXPORT_API int encrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    if (key.size != INFO.key_size) return CRYPTO_ERR_KEY_SIZE;
    if (output->size < input.size) return CRYPTO_ERR_ALLOC;
    
    for (size_t i = 0; i < input.size; ++i) {
        output->data[i] = input.data[i] ^ key.data[i % key.size];
    }
    output->size = input.size;
    return CRYPTO_SUCCESS;
}

EXPORT_API int decrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    // XOR симметричен
    return encrypt(key, input, output);
}

EXPORT_API int encrypt_test(ConstBuffer key, ConstBuffer /*iv*/,
                            ConstBuffer input, MutBuffer* output) {
    return encrypt(key, input, output);
}