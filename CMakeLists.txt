cmake_minimum_required(VERSION 3.18)

project(lithium)
add_library(lithium)
target_include_directories(lithium PRIVATE include/sodium)

target_sources(lithium
        PRIVATE
        src/crypto_aead/aegis256/aead_aegis256.c

        )