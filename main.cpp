#include <iostream>
#include <string>
#include <stdexcept>
#include <clocale>  // для setlocale

// Кроссплатформенная загрузка библиотек
#if defined(_WIN32) || defined(_WIN64)
    #include <windows.h>
    typedef HMODULE LibHandle;
    #define LOAD_LIB(path) LoadLibraryA(path)
    #define GET_FUNC GetProcAddress
    #define CLOSE_LIB FreeLibrary
    const char* VIGENERE_LIB = "vigenere.dll";
#else
    #include <dlfcn.h>
    typedef void* LibHandle;
    #define LOAD_LIB(path) dlopen(path, RTLD_LAZY)
    #define GET_FUNC dlsym
    #define CLOSE_LIB dlclose
    const char* VIGENERE_LIB = "./libvigenere.so";
#endif

using namespace std;

// Определения типов функций
typedef void (*TextFunc)(const char*, const char*, char*);
typedef void (*FileFunc)(const char*, const char*, const char*);
typedef void (*KeyGenFunc)(char*);

int main() {
    // Локализация интерфейса на русский язык
    setlocale(LC_ALL, "Russian");

    cout << "=== Encryption Algorithm RGR ===" << endl;
    
    LibHandle lib = LOAD_LIB(VIGENERE_LIB);
    if (!lib) {
        cerr << "Ошибка: Не удалось загрузить динамическую библиотеку!" << endl;
        return 1;
    }

    // Загрузка функций из библиотеки
    TextFunc encrypt_txt = (TextFunc)GET_FUNC(lib, "encrypt_text");
    FileFunc encrypt_fl = (FileFunc)GET_FUNC(lib, "encrypt_file");
    KeyGenFunc gen_key = (KeyGenFunc)GET_FUNC(lib, "generate_key");

    if (!encrypt_txt || !encrypt_fl || !gen_key) {
        cerr << "Ошибка: Функции не найдены в библиотеке!" << endl;
        CLOSE_LIB(lib);
        return 1;
    }

    try {
        int choice;
        cout << "Выберите действие:\n1. Шифровать текст\n2. Сгенерировать ключ\n> ";
        cin >> choice;

        if (choice == 1) {
            string text, key;
            cout << "Введите текст: ";
            cin >> text;
            cout << "Введите ключ: ";
            cin >> key;

            char output[1024] = {0};
            encrypt_txt(text.c_str(), key.c_str(), output);
            cout << "Результат: " << output << endl;
            
        } else if (choice == 2) {
            char new_key[256];
            gen_key(new_key);
            cout << "Сгенерированный ключ: " << new_key << endl;
        } else {
            throw invalid_argument("Неверный выбор меню.");
        }
    } 
    catch (const exception& e) {
        cerr << "Произошла ошибка: " << e.what() << endl;
    }

    CLOSE_LIB(lib);
    return 0;
}