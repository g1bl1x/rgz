#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <cstring>
#include <getopt.h>
#include <dlfcn.h>
#include <random>
#include <memory>
#include <algorithm>

#include "cipher_api.h"

#ifdef _WIN32
    #include <windows.h>
    #define LIB_HANDLE HMODULE
    #define LOAD_LIB(path) LoadLibraryA(path)
    #define GET_FUNC GetProcAddress
    #define CLOSE_LIB FreeLibrary
#else
    #define LIB_HANDLE void*
    #define LOAD_LIB(path) dlopen(path, RTLD_LAZY)
    #define GET_FUNC dlsym
    #define CLOSE_LIB dlclose
#endif

// Соответствие алгоритмов именам библиотек
struct AlgorithmEntry {
    const char* name;
    const char* lib_name_linux;
    const char* lib_name_windows;
};

static const AlgorithmEntry algorithms[] = {
    {"vigenere", "libvigenere.so", "vigenere.dll"},
    {"des",      "libdes.so",      "des.dll"},
    {"shamir",   "libshamir.so",   "shamir.dll"},
    {nullptr, nullptr, nullptr}
};

// Глобальные опции командной строки
struct Options {
    bool help = false;
    std::string algorithm;
    std::string mode;           // "encrypt", "decrypt", "generate-key"
    std::string key_path;       // --key <file>
    bool generate_key = false;  // --generate-key
    std::string save_key_path;  // --save-key <file>
    bool write_key = false;     // --write-key
    std::string input_path;     // --input <file>
    std::string output_path;    // --output <file>
};

static void print_help(const char* prog_name) {
    std::cout << "Usage: " << prog_name << " [OPTIONS]\n\n"
              << "Encryption/Decryption tool with pluggable crypto algorithms.\n\n"
              << "Options:\n"
              << "  -h, --help                  Show this help message\n"
              << "  -a, --algorithm ALGO        Select algorithm (vigenere, des, shamir)\n"
              << "  -m, --mode MODE             Mode: encrypt, decrypt, generate-key\n"
              << "  -k, --key FILE              Read key from FILE\n"
              << "  -g, --generate-key          Generate new key\n"
              << "  -s, --save-key FILE         Save generated key to FILE\n"
              << "  -w, --write-key             Write key to stdout\n"
              << "  -i, --input FILE            Read input from FILE (default: stdin)\n"
              << "  -o, --output FILE           Write output to FILE (default: stdout)\n\n"
              << "Examples:\n"
              << "  " << prog_name << " --help\n"
              << "  " << prog_name << " -a vigenere -m generate-key -s key.bin\n"
              << "  " << prog_name << " -a des -m encrypt -k key.bin -i data.txt -o data.enc\n"
              << "  " << prog_name << " -a shamir -m decrypt -k key.bin -i data.enc\n"
              << "  cat data.txt | " << prog_name << " -a vigenere -m encrypt -g -w\n";
}

static Options parse_args(int argc, char* argv[]) {
    Options opts;
    
    static struct option long_options[] = {
        {"help",         no_argument,       0, 'h'},
        {"algorithm",    required_argument, 0, 'a'},
        {"mode",         required_argument, 0, 'm'},
        {"key",          required_argument, 0, 'k'},
        {"generate-key", no_argument,       0, 'g'},
        {"save-key",     required_argument, 0, 's'},
        {"write-key",    no_argument,       0, 'w'},
        {"input",        required_argument, 0, 'i'},
        {"output",       required_argument, 0, 'o'},
        {0, 0, 0, 0}
    };
    
    int opt;
    while ((opt = getopt_long(argc, argv, "ha:m:k:gs:wi:o:", long_options, nullptr)) != -1) {
        switch (opt) {
            case 'h': opts.help = true; break;
            case 'a': opts.algorithm = optarg; break;
            case 'm': opts.mode = optarg; break;
            case 'k': opts.key_path = optarg; break;
            case 'g': opts.generate_key = true; break;
            case 's': opts.save_key_path = optarg; break;
            case 'w': opts.write_key = true; break;
            case 'i': opts.input_path = optarg; break;
            case 'o': opts.output_path = optarg; break;
            default: break;
        }
    }
    
    return opts;
}

// Чтение всего содержимого файла
static std::vector<uint8_t> read_file(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Cannot open file: " + path);
    }
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(file)),
                                  std::istreambuf_iterator<char>());
}

// Запись в файл
static void write_file(const std::string& path, const uint8_t* data, size_t size) {
    std::ofstream file(path, std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Cannot write to file: " + path);
    }
    file.write(reinterpret_cast<const char*>(data), size);
}

// Чтение из stdin
static std::vector<uint8_t> read_stdin() {
    std::vector<uint8_t> buffer;
    char ch;
    while (std::cin.get(ch)) {
        buffer.push_back(static_cast<uint8_t>(ch));
    }
    return buffer;
}

// Запись в stdout
static void write_stdout(const uint8_t* data, size_t size) {
    std::cout.write(reinterpret_cast<const char*>(data), size);
}

// Очистка чувствительных данных (защита от утечек)
static void secure_zero(void* ptr, size_t size) {
    volatile uint8_t* p = static_cast<volatile uint8_t*>(ptr);
    for (size_t i = 0; i < size; ++i) {
        p[i] = 0;
    }
}

// Генерация случайного ключа
static std::vector<uint8_t> generate_random_key(size_t key_size) {
    std::vector<uint8_t> key(key_size);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    for (size_t i = 0; i < key_size; ++i) {
        key[i] = static_cast<uint8_t>(dis(gen));
    }
    return key;
}

// Загрузка библиотеки и получение функций
struct CryptoLib {
    LIB_HANDLE handle;
    const AlgorithmInfo* (*get_info)();
    size_t (*get_output_size)(size_t, int);
    int (*encrypt)(ConstBuffer, ConstBuffer, MutBuffer*);
    int (*decrypt)(ConstBuffer, ConstBuffer, MutBuffer*);
    
    ~CryptoLib() {
        if (handle) CLOSE_LIB(handle);
    }
};

static CryptoLib load_library(const std::string& algo_name) {
    CryptoLib lib{};
    std::string lib_path;
    
    for (int i = 0; algorithms[i].name != nullptr; ++i) {
        if (algorithms[i].name == algo_name) {
#ifdef _WIN32
            lib_path = algorithms[i].lib_name_windows;
#else
            lib_path = algorithms[i].lib_name_linux;
#endif
            break;
        }
    }
    
    if (lib_path.empty()) {
        throw std::runtime_error("Unknown algorithm: " + algo_name);
    }
    
    lib.handle = LOAD_LIB(lib_path.c_str());
    if (!lib.handle) {
        throw std::runtime_error("Cannot load library: " + lib_path);
    }
    
    lib.get_info = reinterpret_cast<decltype(lib.get_info)>(GET_FUNC(lib.handle, "get_algorithm_info"));
    lib.get_output_size = reinterpret_cast<decltype(lib.get_output_size)>(GET_FUNC(lib.handle, "get_output_size"));
    lib.encrypt = reinterpret_cast<decltype(lib.encrypt)>(GET_FUNC(lib.handle, "encrypt"));
    lib.decrypt = reinterpret_cast<decltype(lib.decrypt)>(GET_FUNC(lib.handle, "decrypt"));
    
    if (!lib.get_info || !lib.get_output_size || !lib.encrypt || !lib.decrypt) {
        throw std::runtime_error("Library missing required functions");
    }
    
    return lib;
}

int main(int argc, char* argv[]) {
    try {
        Options opts = parse_args(argc, argv);
        
        // Режим справки
        if (opts.help || argc == 1) {
            print_help(argv[0]);
            return 0;
        }
        
        // Проверка обязательных параметров
        if (opts.algorithm.empty()) {
            std::cerr << "Error: --algorithm is required\n";
            print_help(argv[0]);
            return 1;
        }
        
        if (opts.mode.empty()) {
            std::cerr << "Error: --mode is required (encrypt, decrypt, generate-key)\n";
            return 1;
        }
        
        // Загрузка библиотеки
        CryptoLib lib = load_library(opts.algorithm);
        const AlgorithmInfo* info = lib.get_info();
        
        // Режим генерации ключа
        if (opts.mode == "generate-key") {
            if (!opts.generate_key) {
                std::cerr << "Error: --generate-key required for generate-key mode\n";
                return 1;
            }
            
            std::vector<uint8_t> key = generate_random_key(info->key_size);
            
            if (!opts.save_key_path.empty()) {
                write_file(opts.save_key_path, key.data(), key.size());
                std::cerr << "Key saved to: " << opts.save_key_path << "\n";
            }
            
            if (opts.write_key) {
                write_stdout(key.data(), key.size());
            }
            
            secure_zero(key.data(), key.size());
            return 0;
        }
        
        // Режим шифрования/дешифрования
        if (opts.mode != "encrypt" && opts.mode != "decrypt") {
            std::cerr << "Error: invalid mode. Use: encrypt, decrypt, generate-key\n";
            return 1;
        }
        
        // Загрузка ключа
        std::vector<uint8_t> key;
        if (!opts.key_path.empty()) {
            key = read_file(opts.key_path);
        } else if (opts.generate_key) {
            key = generate_random_key(info->key_size);
            if (opts.write_key) {
                write_stdout(key.data(), key.size());
                std::cerr << "\n[Key written to stdout]\n";
            }
            if (!opts.save_key_path.empty()) {
                write_file(opts.save_key_path, key.data(), key.size());
                std::cerr << "Key saved to: " << opts.save_key_path << "\n";
            }
        } else {
            std::cerr << "Error: --key or --generate-key required\n";
            return 1;
        }
        
        if (key.size() != info->key_size) {
            std::cerr << "Error: key size mismatch. Expected " << info->key_size 
                      << " bytes, got " << key.size() << "\n";
            return 1;
        }
        
        // Загрузка входных данных
        std::vector<uint8_t> input;
        if (!opts.input_path.empty()) {
            input = read_file(opts.input_path);
        } else {
            input = read_stdin();
        }
        
        // Вычисление размера выходного буфера
        int op_type = (opts.mode == "encrypt") ? 1 : 0;
        size_t out_size = lib.get_output_size(input.size(), op_type);
        std::vector<uint8_t> output(out_size);
        
        // Выполнение операции
        ConstBuffer key_buf{key.data(), key.size()};
        ConstBuffer input_buf{input.data(), input.size()};
        MutBuffer output_buf{output.data(), output.size()};
        
        int result;
        if (opts.mode == "encrypt") {
            result = lib.encrypt(key_buf, input_buf, &output_buf);
        } else {
            result = lib.decrypt(key_buf, input_buf, &output_buf);
        }
        
        if (result != CRYPTO_SUCCESS) {
            std::cerr << "Error: cryptographic operation failed with code " << result << "\n";
            return 1;
        }
        
        // Запись выходных данных
        if (!opts.output_path.empty()) {
            write_file(opts.output_path, output_buf.data, output_buf.size);
        } else {
            write_stdout(output_buf.data, output_buf.size);
        }
        
        // Очистка чувствительных данных
        secure_zero(key.data(), key.size());
        secure_zero(input.data(), input.size());
        secure_zero(output.data(), output.size());
        
        return 0;
        
    } catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << "\n";
        return 1;
    }
}