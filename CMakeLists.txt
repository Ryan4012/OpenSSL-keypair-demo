cmake_minimum_required(VERSION 3.16)
project(rsa_sign_demo)

find_package(OpenSSL REQUIRED)

add_executable(rsa_demo
    src/main.cpp
    src/crypto_utils.cpp
)

target_include_directories(rsa_demo PRIVATE src)
target_link_libraries(rsa_demo OpenSSL::Crypto)
