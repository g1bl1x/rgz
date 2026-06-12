#include "cipher_api.h"
#include <iostream>
#include <vector>
#include <cassert>
#include <dlfcn.h>
#include <cstring>

struct TestLib {
    void* handle;
    const AlgorithmInfo* (*get_info)();
    size_t (*get_output_size)(size_t, int);
    int (*encrypt)(ConstBuffer, ConstBuffer, MutBuffer*);
    int (*decrypt)(ConstBuffer, ConstBuffer, MutBuffer*);
};

static TestLib load_lib(const char* path) {
    TestLib lib{};
    std::string full_path = "./";
    full_path += path;
    
    lib.handle = dlopen(full_path.c_str(), RTLD_LAZY);
    if (!lib.handle) {
        std::cerr << "Failed to load " << full_path << ": " << dlerror() << std::endl;
        return lib;
    }
    
    lib.get_info = (decltype(lib.get_info))dlsym(lib.handle, "get_algorithm_info");
    lib.get_output_size = (decltype(lib.get_output_size))dlsym(lib.handle, "get_output_size");
    lib.encrypt = (decltype(lib.encrypt))dlsym(lib.handle, "encrypt");
    lib.decrypt = (decltype(lib.decrypt))dlsym(lib.handle, "decrypt");
    
    if (!lib.get_info || !lib.get_output_size || !lib.encrypt || !lib.decrypt) {
        std::cerr << "Library missing required functions" << std::endl;
        dlclose(lib.handle);
        lib.handle = nullptr;
    }
    
    return lib;
}

static bool test_algorithm(TestLib& lib, const std::vector<uint8_t>& key,
                           const std::vector<uint8_t>& plaintext) {
    const AlgorithmInfo* info = lib.get_info();
    if (key.size() != info->key_size) {
        std::cerr << "Key size mismatch for " << info->algorithm_name << std::endl;
        return false;
    }
    
    size_t out_size = lib.get_output_size(plaintext.size(), 1);
    std::vector<uint8_t> ciphertext(out_size);
    std::vector<uint8_t> decrypted(out_size);
    
    ConstBuffer key_buf{key.data(), key.size()};
    ConstBuffer plain_buf{plaintext.data(), plaintext.size()};
    MutBuffer cipher_buf{ciphertext.data(), ciphertext.size()};
    
    int err = lib.encrypt(key_buf, plain_buf, &cipher_buf);
    if (err != CRYPTO_SUCCESS) {
        std::cerr << "Encrypt failed for " << info->algorithm_name << ": " << err << std::endl;
        return false;
    }
    
    ConstBuffer cipher_buf_const{cipher_buf.data, cipher_buf.size};
    MutBuffer dec_buf{decrypted.data(), decrypted.size()};
    err = lib.decrypt(key_buf, cipher_buf_const, &dec_buf);
    if (err != CRYPTO_SUCCESS) {
        std::cerr << "Decrypt failed for " << info->algorithm_name << ": " << err << std::endl;
        return false;
    }
    
    // Сравнение
    if (plaintext.size() != dec_buf.size) {
        std::cerr << "Size mismatch for " << info->algorithm_name 
                  << ": expected " << plaintext.size() 
                  << ", got " << dec_buf.size << std::endl;
        return false;
    }
    
    for (size_t i = 0; i < plaintext.size(); ++i) {
        if (plaintext[i] != dec_buf.data[i]) {
            std::cerr << "Data mismatch at position " << i 
                      << ": expected " << (int)plaintext[i] 
                      << ", got " << (int)dec_buf.data[i] << std::endl;
            return false;
        }
    }
    
    std::cout << info->algorithm_name << ": PASSED\n";
    return true;
}

int main() {
    std::cout << "Running crypto tests...\n\n";
    
    std::vector<uint8_t> key32(32);
    std::vector<uint8_t> key8(8);
    std::vector<uint8_t> key16(16);
    std::vector<uint8_t> plaintext = {'H','e','l','l','o',' ','W','o','r','l','d','!',0};
    
    for (size_t i = 0; i < 32; ++i) key32[i] = i % 256;
    for (size_t i = 0; i < 8; ++i) key8[i] = i % 256;
    for (size_t i = 0; i < 16; ++i) key16[i] = i % 256;
    
    int passed = 0;
    int total = 0;
    
    TestLib vigenere = load_lib("libvigenere.so");
    if (vigenere.handle) {
        total++;
        if (test_algorithm(vigenere, key32, plaintext)) passed++;
        dlclose(vigenere.handle);
    } else {
        std::cerr << "SKIP: vigenere library not found\n";
    }
    
    TestLib des = load_lib("libdes.so");
    if (des.handle) {
        total++;
        if (test_algorithm(des, key8, plaintext)) passed++;
        dlclose(des.handle);
    } else {
        std::cerr << "SKIP: des library not found\n";
    }
    
    TestLib shamir = load_lib("libshamir.so");
    if (shamir.handle) {
        total++;
        if (test_algorithm(shamir, key16, plaintext)) passed++;
        dlclose(shamir.handle);
    } else {
        std::cerr << "SKIP: shamir library not found\n";
    }
    
    std::cout << "\n" << passed << "/" << total << " tests passed!\n";
    
    return (passed == total) ? 0 : 1;
}