#include <iostream>
#include <string>
#include <vector>
#include <stdexcept>
#include <clocale>
#include <cstring>
#include <filesystem>
#include <memory>
#include <algorithm>
#include <sstream>
#include <iomanip>

#if defined(_WIN32) || defined(_WIN64)
    #include <windows.h>
    typedef HMODULE LibHandle;
    #define LOAD_LIB(path) LoadLibraryA(path)
    #define GET_FUNC GetProcAddress
    #define CLOSE_LIB FreeLibrary
    const std::string LIB_EXT = ".dll";
#else
    #include <dlfcn.h>
    typedef void* LibHandle;
    #define LOAD_LIB(path) dlopen(path, RTLD_LAZY)
    #define GET_FUNC dlsym
    #define CLOSE_LIB dlclose
    const std::string LIB_EXT = ".so";
#endif

#include "CipherAPI.h" 

using namespace std;
namespace fs = filesystem;

// Структура для хранения информации о загруженной библиотеке
struct CryptoLib {
    string name;
    LibHandle handle;
    TextFunc encrypt_text;
    TextFunc decrypt_text;
    FileFunc encrypt_file;
    FileFunc decrypt_file;
    KeyGenFunc generate_key;

    CryptoLib() : handle(nullptr), encrypt_text(nullptr), decrypt_text(nullptr),
                  encrypt_file(nullptr), decrypt_file(nullptr), generate_key(nullptr) {}
};

string bytes_to_hex(const char* data, size_t len) {
    stringstream ss;
    for (size_t i = 0; i < len; ++i) {
        ss << hex << setw(2) << setfill('0') << (int)(unsigned char)data[i];
    }
    return ss.str();
}

// Преобразование hex-строки в байты
vector<unsigned char> hex_to_bytes(const string& hex) {
    vector<unsigned char> bytes;
    if (hex.length() % 2 != 0) {
        throw invalid_argument("Hex строка должна иметь чётную длину");
    }
    for (size_t i = 0; i < hex.length(); i += 2) {
        string byte_str = hex.substr(i, 2);
        char* endptr;
        long val = strtol(byte_str.c_str(), &endptr, 16);
        if (*endptr != 0) {
            throw invalid_argument("Неверный hex символ");
        }
        bytes.push_back((unsigned char)val);
    }
    return bytes;
}

// Удаление библиотеки при выходе из области видимости
void close_lib(CryptoLib& lib) {
    if (lib.handle) {
        CLOSE_LIB(lib.handle);
        lib.handle = nullptr;
    }
}

// Поиск библиотек в текущей папке
vector<string> find_libraries() {
    vector<string> paths;
    fs::path search_dir = "."; 
    if (!fs::exists(search_dir)) search_dir = ".";
    
    for (auto& entry : fs::directory_iterator(search_dir)) {
        if (entry.is_regular_file() && entry.path().extension() == LIB_EXT) {
            paths.push_back(entry.path().string());
        }
    }
    return paths;
}

// Загрузка конкретной библиотеки и получение указателей на функции
bool load_library(const string& path, CryptoLib& lib) {
    lib.handle = LOAD_LIB(path.c_str());
    if (!lib.handle) {
        cerr << "Не удалось загрузить " << path;
#if !defined(_WIN32)
        cerr << " (" << dlerror() << ")";
#endif
        cerr << endl;
        return false;
    }

    lib.encrypt_text = (TextFunc)GET_FUNC(lib.handle, "encrypt_text");
    lib.decrypt_text = (TextFunc)GET_FUNC(lib.handle, "decrypt_text");
    lib.encrypt_file = (FileFunc)GET_FUNC(lib.handle, "encrypt_file");
    lib.decrypt_file = (FileFunc)GET_FUNC(lib.handle, "decrypt_file");
    lib.generate_key = (KeyGenFunc)GET_FUNC(lib.handle, "generate_key");

    // Проверка наличия всех обязательных функций
    if (!lib.encrypt_text || !lib.decrypt_text || !lib.encrypt_file || !lib.decrypt_file || !lib.generate_key) {
        cerr << "Библиотека " << path << " не содержит всех необходимых функций!" << endl;
        CLOSE_LIB(lib.handle);
        lib.handle = nullptr;
        return false;
    }

    lib.name = fs::path(path).stem().string();
    return true;
}

// Создание директорий для пути (если их нет)
bool ensure_directories(const string& path) {
    fs::path p(path);
    fs::path parent = p.parent_path();
    if (!parent.empty() && !fs::exists(parent)) {
        return fs::create_directories(parent);
    }
    return true;
}

// Меню выбора алгоритма
int select_algorithm(const vector<CryptoLib>& libs) {
    if (libs.empty()) {
        cout << "Нет доступных библиотек. Поместите ." << LIB_EXT << " файлы в текущую папку.\n";
        return -1;
    }
    cout << "\nДоступные алгоритмы:\n";
    for (size_t i = 0; i < libs.size(); ++i) {
        cout << "  " << i+1 << ". " << libs[i].name << endl;
    }
    cout << "Выберите номер (0 - выход): ";
    int choice;
    cin >> choice;
    if (choice == 0) return -1;
    if (choice < 1 || choice > (int)libs.size()) {
        cout << "Неверный выбор.\n";
        return -2; // повтор
    }
    return choice-1;
}

// Шифрование/дешифрование текста
void text_operation(CryptoLib& lib) {
    cout << "\n--- Работа с текстом ---\n";
    cout << "1. Шифрование\n2. Дешифрование\nВыбор: ";
    int mode;
    cin >> mode;
    if (mode != 1 && mode != 2) {
        cout << "Неверный режим.\n";
        return;
    }
    cin.ignore();

    if (mode == 1) {
        // Шифрование
        cout << "Введите открытый текст: ";
        string plaintext;
        getline(cin, plaintext);
        cout << "Введите ключ: ";
        string key;
        getline(cin, key);

        // Преобразуем открытый текст в hex
        string plain_hex = bytes_to_hex(plaintext.c_str(), plaintext.length());
        char output[2048] = {0};
        lib.encrypt_text(plain_hex.c_str(), key.c_str(), output);
        cout << "Зашифрованный текст (hex): " << output << endl;
    } 
    else {
        // Дешифрование
        cout << "Введите зашифрованный текст (в hex): ";
        string hex_input;
        getline(cin, hex_input);
        cout << "Введите ключ: ";
        string key;
        getline(cin, key);

        char output[4096] = {0};
        lib.decrypt_text(hex_input.c_str(), key.c_str(), output);
        
        // Превращаем обратно в текст.
        vector<unsigned char> dec_bytes = hex_to_bytes(output);
        string dec_text(dec_bytes.begin(), dec_bytes.end());
        // Убираем возможные нулевые символы в конце
        while (!dec_text.empty() && dec_text.back() == '\0') dec_text.pop_back();
        cout << "Расшифрованный текст: " << dec_text << endl;
    }
}

// Шифрование/дешифрование файла
void file_operation(CryptoLib& lib) {
    cout << "\n--- Работа с файлом ---\n";
    cout << "1. Шифрование\n2. Дешифрование\nВыбор: ";
    int mode;
    cin >> mode;
    if (mode != 1 && mode != 2) {
        cout << "Неверный режим.\n";
        return;
    }

    cin.ignore();
    cout << "Входной файл: ";
    string in_path;
    getline(cin, in_path);
    cout << "Выходной файл (Enter - создать автоматически): ";
    string out_path;
    getline(cin, out_path);
    if (out_path.empty()) {
        // автоматическое имя: input.enc / input.dec
        fs::path p(in_path);
        string ext = (mode == 1) ? ".enc" : ".dec";
        out_path = p.string() + ext;
        cout << "Используется выходной файл: " << out_path << endl;
    }

    // Проверка существования входного файла
    if (!fs::exists(in_path)) {
        cerr << "Ошибка: входной файл не существует.\n";
        return;
    }

    // Создание директорий для выходного файла
    if (!ensure_directories(out_path)) {
        cerr << "Не удалось создать директории для " << out_path << endl;
        return;
    }

    cout << "Введите ключ: ";
    string key;
    getline(cin, key);

    bool success = false;
    try {
        if (mode == 1)
            success = lib.encrypt_file(in_path.c_str(), out_path.c_str(), key.c_str());
        else
            success = lib.decrypt_file(in_path.c_str(), out_path.c_str(), key.c_str());
    } catch (...) {
        cerr << "Исключение при обработке файла.\n";
        return;
    }

    if (success)
        cout << "Операция успешно завершена. Результат: " << out_path << endl;
    else
        cerr << "Ошибка: не удалось выполнить операцию (возможно, проблема с открытием файлов).\n";
}

// Генерация ключа
void generate_key(CryptoLib& lib) {
    char key[256] = {0};
    lib.generate_key(key);
    cout << "Сгенерированный ключ: " << key << endl;
}

int main() {
    setlocale(LC_ALL, "Russian");
#if defined(_WIN32)
    system("chcp 65001 > nul"); // UTF-8 для Windows
#endif

    cout << "=== Encryption Algorithm RGR ===\n";
    cout << "Программа для шифрования/дешифрования текста и файлов.\n";

    // Поиск и загрузка библиотек
    vector<string> lib_paths = find_libraries();
    if (lib_paths.empty()) {
        cerr << "Не найдено ни одной динамической библиотеки (" << LIB_EXT << ").\n";
        cerr << "Поместите скомпилированные библиотеки (vigenere" << LIB_EXT << ", des" << LIB_EXT << ") в текущую папку.\n";
        return 1;
    }

    vector<CryptoLib> libs;
    for (const auto& path : lib_paths) {
        CryptoLib lib;
        if (load_library(path, lib)) {
            libs.push_back(lib);
            cout << "Загружена библиотека: " << lib.name << endl;
        }
    }

    if (libs.empty()) {
        cerr << "Не удалось загрузить ни одной корректной библиотеки.\n";
        return 1;
    }

    int alg_idx = -1;
    while (alg_idx == -1) {
        alg_idx = select_algorithm(libs);
        if (alg_idx == -1) return 0;
        if (alg_idx == -2) alg_idx = -1;
    }

    CryptoLib& active_lib = libs[alg_idx];
    cout << "\nВыбран алгоритм: " << active_lib.name << endl;

    bool exit_flag = false;
    while (!exit_flag) {
        cout << "\n--- Главное меню ---\n";
        cout << "1. Шифрование/дешифрование текста\n";
        cout << "2. Шифрование/дешифрование файла\n";
        cout << "3. Сгенерировать ключ\n";
        cout << "0. Выход\n";
        cout << "Выбор: ";
        int choice;
        cin >> choice;
        cin.ignore(); // очистка буфера

        switch (choice) {
            case 1:
                text_operation(active_lib);
                break;
            case 2:
                file_operation(active_lib);
                break;
            case 3:
                generate_key(active_lib);
                break;
            case 0:
                exit_flag = true;
                break;
            default:
                cout << "Неверный выбор. Попробуйте снова.\n";
        }
    }

    // Выгрузка библиотек
    for (auto& lib : libs) {
        if (lib.handle) CLOSE_LIB(lib.handle);
    }
    cout << "Программа завершена.\n";
    return 0;
}