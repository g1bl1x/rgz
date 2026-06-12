#include "cipher_api.h"
#include <cstring>

static const AlgorithmInfo INFO = {
    "Shamir Cipher",
    16,
    1,       
    false
};

static long long mod_pow(long long base, long long exp, long long mod) {
    long long result = 1;
    base = base % mod;
    while (exp > 0) {
        if (exp & 1) result = (result * base) % mod;
        base = (base * base) % mod;
        exp >>= 1;
    }
    return result;
}

static long long find_prime(void) {
    return 257;  
}

static long long get_exponent_from_key(ConstBuffer key) {
    long long exp = 0;
    for (size_t i = 0; i < key.size && i < 8; ++i) {
        exp = (exp << 8) | key.data[i];
    }
    long long prime = find_prime();
    exp = exp % (prime - 1);
    if (exp < 2) exp = 65537;
    return exp;
}

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

EXPORT_API const AlgorithmInfo* get_algorithm_info(void) {
    return &INFO;
}

EXPORT_API size_t get_output_size(size_t input_size, int /*operation_type*/) {
    return input_size; 
}

EXPORT_API int encrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    if (key.size != INFO.key_size) return CRYPTO_ERR_KEY_SIZE;
    if (output->size < input.size) return CRYPTO_ERR_ALLOC;
    
    long long prime = find_prime();
    long long exp = get_exponent_from_key(key);
    
    for (size_t i = 0; i < input.size; ++i) {
        long long encrypted = mod_pow(input.data[i], exp, prime);
        output->data[i] = encrypted & 0xFF;
    }
    output->size = input.size;
    return CRYPTO_SUCCESS;
}

EXPORT_API int decrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    if (key.size != INFO.key_size) return CRYPTO_ERR_KEY_SIZE;
    if (output->size < input.size) return CRYPTO_ERR_ALLOC;
    
    long long prime = find_prime();
    long long exp = get_exponent_from_key(key);
    long long d = mod_inverse(exp, prime - 1);
    
    for (size_t i = 0; i < input.size; ++i) {
        long long decrypted = mod_pow(input.data[i], d, prime);
        output->data[i] = decrypted & 0xFF;
    }
    output->size = input.size;
    return CRYPTO_SUCCESS;
}

EXPORT_API int encrypt_test(ConstBuffer key, ConstBuffer /*iv*/,
                            ConstBuffer input, MutBuffer* output) {
    return encrypt(key, input, output);
}