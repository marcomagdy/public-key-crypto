cmake_minimum_required(VERSION 3.20)
set(CMAKE_CXX_STANDARD 17)
project(sign-verify)

find_package(OpenSSL REQUIRED)
add_executable(sign sign.cpp)
target_link_libraries(sign OpenSSL::Crypto)

add_executable(verify verify.cpp)
target_link_libraries(verify OpenSSL::Crypto)

add_executable(encrypt encrypt.cpp)
target_link_libraries(encrypt OpenSSL::Crypto)

add_executable(decrypt decrypt.cpp)
target_link_libraries(decrypt OpenSSL::Crypto)
