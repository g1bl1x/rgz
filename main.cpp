#include <iostream>
#include <string>
#include <stdexcept>
#include <dlfcn.h>

using namespace std;

typedef void* LibHandle;
#define LOAD_LIB(path) dlopen(path, RTLD_LAZY)
#define GET_FUNC dlsym
#define CLOSE_LIB dlclose

// Путь к библиотеке в Linux
const char* VIGENERE_LIB = "./libvigenere.so";

// Подключаем наш заголовочный файл с типами указателей на функции
#include "CipherAPI.h"

int main() {
    // Локализация интерфейса
    setlocale(LC_ALL, "ru_RU.UTF-8");

    cout << "=== Encryption Algorithm RGR (Linux Version) ===" << endl;
    
    // Загрузка динамической библиотеки
    LibHandle lib = LOAD_LIB(VIGENERE_LIB);
    if (!lib) {
        cerr << "Ошибка: Не удалось загрузить динамическую библиотеку!" << endl;
        cerr << "Детали: " << dlerror() << endl; // dlerror() покажет точную причину в Linux
        return 1;
    }

    // Получение адресов функций
    TextFunc encrypt_txt = (TextFunc)GET_FUNC(lib, "encrypt_text");
    FileFunc encrypt_fl  = (FileFunc)GET_FUNC(lib, "encrypt_file");
    KeyGenFunc gen_key   = (KeyGenFunc)GET_FUNC(lib, "generate_key");

    if (!encrypt_txt || !encrypt_fl || !gen_key) {
        cerr << "Ошибка: Функции не найдены в библиотеке!" << endl;
        cerr << "Детали: " << dlerror() << endl;
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