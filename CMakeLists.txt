cmake_minimum_required(VERSION 3.10)
project(CryptoTool CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Werror")

# Главное приложение
add_executable(cryptum main.cpp)
target_link_libraries(cryptum dl)

# Библиотеки алгоритмов
add_library(vigenere SHARED vigenere.cpp)
add_library(des SHARED des.cpp)
add_library(shamir SHARED shamir.cpp)

# Тестирование
add_executable(test_crypto test_crypto.cpp)
target_link_libraries(test_crypto dl)

# Установка
install(TARGETS cryptum DESTINATION bin)
install(TARGETS vigenere des shamir DESTINATION lib)
