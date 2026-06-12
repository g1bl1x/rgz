#ifndef SHAMIR_H
#define SHAMIR_H

#include "CipherAPI.h"
#include <string>

// Дополнительные функции для шифра Шамира
EXPORT_API void generate_shamir_keys(char* public_key, char* private_key, const char* prime);
EXPORT_API void shamir_encrypt(const char* input_hex, const char* public_key, const char* prime, char* output_hex);
EXPORT_API void shamir_decrypt(const char* input_hex, const char* private_key, const char* prime, char* output_hex);

#endif // SHAMIR_H