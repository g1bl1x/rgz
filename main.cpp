#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <cstring>
#include <getopt.h>
#include <random>
#include <memory>
#include <algorithm>
#include <stdexcept>

// Кроссплатформенный импорт заголовков для динамической загрузки
#if defined(_WIN32)
    #include <windows.h>
    #include <io.h>
    #include <fcntl.h>
    #define LIB_HANDLE HMODULE
    #define CLOSE_LIB(handle) FreeLibrary(handle)
#else
    #include <dlfcn.h>
    #define LIB_HANDLE void*
    #define CLOSE_LIB(handle) dlclose(handle)
#endif

#include "cipher_api.h"

// Соответствие алгоритмов именам библиотек для разных ОС
struct AlgorithmEntry {
    const char* name;
    const char* lib_name;
};

static const AlgorithmEntry algorithms[] = {
#if defined(_WIN32)
    {"vigenere", "vigenere.dll"},
    {"des",      "des.dll"},
    {"shamir",   "shamir.dll"},
#else
    {"vigenere", "libvigenere.so"},
    {"des",      "libdes.so"},
    {"shamir",   "libshamir.so"},
#endif
    {nullptr, nullptr}
};

struct Options {
    bool help = false;
    std::string algorithm;
    std::string mode;           // "encrypt", "decrypt", "generate-key"
    std::string key_path;       
    bool generate_key = false;  
    std::string save_key_path;  
    bool write_key = false;     
    std::string input_path;     
    std::string output_path;    
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
              << "  -o, --output FILE           Write output to FILE (default: stdout)\n";
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

static std::vector<uint8_t> read_file(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Cannot open file: " + path);
    }
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(file)),
                                  std::istreambuf_iterator<char>());
}

static void write_file(const std::string& path, const uint8_t* data, size_t size) {
    std::ofstream file(path, std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Cannot write to file: " + path);
    }
    file.write(reinterpret_cast<const char*>(data), size);
}

static std::vector<uint8_t> read_stdin() {
    std::vector<uint8_t> buffer;
    char ch;
    while (std::cin.get(ch)) {
        buffer.push_back(static_cast<uint8_t>(ch));
    }
    return buffer;
}

static void write_stdout(const uint8_t* data, size_t size) {
    std::cout.write(reinterpret_cast<const char*>(data), size);
}

static void secure_zero(void* ptr, size_t size) {
    volatile uint8_t* p = static_cast<volatile uint8_t*>(ptr);
    for (size_t i = 0; i < size; ++i) {
        p[i] = 0;
    }
}

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

// Обертка для работы с динамическими библиотеками
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
#if defined(_WIN32)
            lib_path = algorithms[i].lib_name; // Windows ищет в текущей папке автоматически
#else
            lib_path = "./" + std::string(algorithms[i].lib_name);
#endif
            break;
        }
    }
    
    if (lib_path.empty()) {
        throw std::runtime_error("Unknown algorithm: " + algo_name);
    }
    
#if defined(_WIN32)
    lib.handle = LoadLibraryA(lib_path.c_str());
    if (!lib.handle) {
        throw std::runtime_error("Cannot load library: " + lib_path + " (Error code: " + std::to_string(GetLastError()) + ")");
    }
    lib.get_info = reinterpret_cast<decltype(lib.get_info)>(GetProcAddress(lib.handle, "get_algorithm_info"));
    lib.get_output_size = reinterpret_cast<decltype(lib.get_output_size)>(GetProcAddress(lib.handle, "get_output_size"));
    lib.encrypt = reinterpret_cast<decltype(lib.encrypt)>(GetProcAddress(lib.handle, "encrypt"));
    lib.decrypt = reinterpret_cast<decltype(lib.decrypt)>(GetProcAddress(lib.handle, "decrypt"));
#else
    lib.handle = dlopen(lib_path.c_str(), RTLD_LAZY);
    if (!lib.handle) {
        throw std::runtime_error("Cannot load library: " + lib_path + " (" + dlerror() + ")");
    }
    lib.get_info = reinterpret_cast<decltype(lib.get_info)>(dlsym(lib.handle, "get_algorithm_info"));
    lib.get_output_size = reinterpret_cast<decltype(lib.get_output_size)>(dlsym(lib.handle, "get_output_size"));
    lib.encrypt = reinterpret_cast<decltype(lib.encrypt)>(dlsym(lib.handle, "encrypt"));
    lib.decrypt = reinterpret_cast<decltype(lib.decrypt)>(dlsym(lib.handle, "decrypt"));
#endif
    
    if (!lib.get_info || !lib.get_output_size || !lib.encrypt || !lib.decrypt) {
        throw std::runtime_error("Library missing required functions");
    }
    
    return lib;
}

int main(int argc, char* argv[]) {
    // Включаем бинарный режим для стандартных потоков на Windows
#if defined(_WIN32)
    _setmode(_fileno(stdin), _O_BINARY);
    _setmode(_fileno(stdout), _O_BINARY);
#endif

    try {
        Options opts = parse_args(argc, argv);
        
        if (opts.help || argc == 1) {
            print_help(argv[0]);
            return 0;
        }
        
        if (opts.algorithm.empty() || opts.mode.empty()) {
            std::cerr << "Error: --algorithm and --mode are required\n";
            return 1;
        }
        
        CryptoLib lib = load_library(opts.algorithm);
        const AlgorithmInfo* info = lib.get_info();
        
        if (opts.mode == "generate-key") {
            if (!opts.generate_key) {
                std::cerr << "Error: --generate-key required for this mode\n";
                return 1;
            }
            std::vector<uint8_t> key = generate_random_key(info->key_size);
            if (!opts.save_key_path.empty()) {
                write_file(opts.save_key_path, key.data(), key.size());
            }
            if (opts.write_key) {
                write_stdout(key.data(), key.size());
            }
            secure_zero(key.data(), key.size());
            return 0;
        }
        
        std::vector<uint8_t> key;
        if (!opts.key_path.empty()) {
            key = read_file(opts.key_path);
        } else if (opts.generate_key) {
            key = generate_random_key(info->key_size);
            if (opts.write_key) {
                write_stdout(key.data(), key.size());
            }
            if (!opts.save_key_path.empty()) {
                write_file(opts.save_key_path, key.data(), key.size());
            }
        } else {
            std::cerr << "Error: --key or --generate-key required\n";
            return 1;
        }
        
        if (key.size() != info->key_size) {
            std::cerr << "Error: key size mismatch.\n";
            return 1;
        }
        
        std::vector<uint8_t> input;
        if (!opts.input_path.empty()) {
            input = read_file(opts.input_path);
        } else {
            input = read_stdin();
        }
        
        int op_type = (opts.mode == "encrypt") ? 1 : 0;
        size_t out_size = lib.get_output_size(input.size(), op_type);
        std::vector<uint8_t> output(out_size);
        
        ConstBuffer key_buf{key.data(), key.size()};
        ConstBuffer input_buf{input.data(), input.size()};
        MutBuffer output_buf{output.data(), output.size()};
        
        int result = (opts.mode == "encrypt") ? 
            lib.encrypt(key_buf, input_buf, &output_buf) : 
            lib.decrypt(key_buf, input_buf, &output_buf);
        
        if (result != CRYPTO_SUCCESS) {
            std::cerr << "Error: crypto operation failed, code " << result << "\n";
            return 1;
        }
        
        if (!opts.output_path.empty()) {
            write_file(opts.output_path, output_buf.data, output_buf.size);
        } else {
            write_stdout(output_buf.data, output_buf.size);
        }
        
        secure_zero(key.data(), key.size());
        secure_zero(input.data(), input.size());
        secure_zero(output.data(), output.size());
        return 0;
        
    } catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << "\n";
        return 1;
    }
}