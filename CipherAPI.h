#ifndef CIPHER_API_H
#define CIPHER_API_H

#include <string>

// Макросы для экспорта функций в динамическую библиотеку
#if defined(_WIN32) || defined(_WIN64)
    #define EXPORT_API extern "C" __declspec(dllexport)
#else
    #define EXPORT_API extern "C"
#endif

// Унифицированный интерфейс алгоритмов
EXPORT_API void encrypt_text(const char* input, const char* key, char* output);
EXPORT_API void decrypt_text(const char* input, const char* key, char* output);
EXPORT_API bool encrypt_file(const char* in_path, const char* out_path, const char* key);
EXPORT_API bool decrypt_file(const char* in_path, const char* out_path, const char* key);
EXPORT_API void generate_key(char* output_key);

// Типы указателей на функции для динамической загрузки в main.cpp
typedef void (*TextFunc)(const char*, const char*, char*);
typedef bool (*FileFunc)(const char*, const char*, const char*);
typedef void (*KeyGenFunc)(char*);

#endif // CIPHER_API_H