#ifndef CIPHER_API_H
#define CIPHER_API_H

#include <cstddef>
#include <cstdint>

#ifdef _WIN32
    #define EXPORT_API extern "C" __declspec(dllexport)
#else
    #define EXPORT_API extern "C"
#endif

// Структуры для безопасной передачи данных
struct ConstBuffer {
    const uint8_t* data;
    size_t size;
};

struct MutBuffer {
    uint8_t* data;
    size_t size;
};

// Информация об алгоритме
struct AlgorithmInfo {
    const char* algorithm_name;
    size_t key_size;           // размер ключа в байтах
    size_t block_size;         // размер блока (0 для поточных)
    bool uses_iv;              // использует ли вектор инициализации
};

// Обязательные экспортируемые функции
EXPORT_API const AlgorithmInfo* get_algorithm_info(void);
EXPORT_API size_t get_output_size(size_t input_size, int operation_type);
EXPORT_API int encrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output);
EXPORT_API int decrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output);

// Опциональная функция для тестирования (с фиксированным IV)
EXPORT_API int encrypt_test(ConstBuffer key, ConstBuffer iv, 
                            ConstBuffer input, MutBuffer* output);

// Коды ошибок
#define CRYPTO_SUCCESS         0
#define CRYPTO_ERR_KEY_SIZE    -1
#define CRYPTO_ERR_INVALID_IV  -2
#define CRYPTO_ERR_ALLOC       -3
#define CRYPTO_ERR_ENCRYPT     -4
#define CRYPTO_ERR_DECRYPT     -5

#endif // CIPHER_API_H