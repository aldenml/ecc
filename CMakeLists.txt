#
# Copyright (c) 2021, Alden Torres
#
# Licensed under the terms of the MIT license.
# Copy of the license at https://opensource.org/licenses/MIT
#

cmake_minimum_required(VERSION 3.16)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_VISIBILITY_PRESET hidden)

if(EMSCRIPTEN)
    set(BUILD_SHARED_LIBS OFF)
else()
    set(BUILD_SHARED_LIBS ON)
endif()

project(ecc LANGUAGES C)

# libsodium
include(ExternalProject)
if(EMSCRIPTEN)
    ExternalProject_Add(
        libsodium-external
        SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/libsodium
        CONFIGURE_COMMAND emconfigure ${CMAKE_CURRENT_SOURCE_DIR}/libsodium/configure
            "CFLAGS=-DSODIUM_STATIC=1 -Oz"
            --prefix=${CMAKE_CURRENT_SOURCE_DIR}/build/libsodium
            --disable-ssp
            --disable-asm
            --disable-pie
            --disable-shared
            --without-pthreads
        PREFIX ${CMAKE_CURRENT_SOURCE_DIR}/build/libsodium
        BUILD_COMMAND emmake make -j4
        BUILD_IN_SOURCE 1
    )
    ExternalProject_Add(
        blst-external
        SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/deps/blst
        CONFIGURE_COMMAND ""
        BUILD_COMMAND AR=emar ./build.sh CC=emcc -D__BLST_PORTABLE__
        BUILD_IN_SOURCE 1
        INSTALL_COMMAND ""
    )
else()
    ExternalProject_Add(
        libsodium-external
        SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/libsodium
        CONFIGURE_COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/libsodium/configure
            "CFLAGS=-DSODIUM_STATIC=1 -O2"
            --prefix=${CMAKE_CURRENT_SOURCE_DIR}/build/libsodium
            --disable-ssp
            --disable-asm
            --disable-shared
            --without-pthreads
        PREFIX ${CMAKE_CURRENT_SOURCE_DIR}/build/libsodium
        BUILD_COMMAND make -j4
        BUILD_IN_SOURCE 1
    )
    ExternalProject_Add(
        blst-external
        SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/deps/blst
        CONFIGURE_COMMAND ""
        BUILD_COMMAND ./build.sh -D__BLST_PORTABLE__
        BUILD_IN_SOURCE 1
        INSTALL_COMMAND ""
    )
endif()

file(MAKE_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/build/libsodium/include)

add_library(libsodium STATIC IMPORTED GLOBAL)
add_dependencies(libsodium libsodium-external)

set_target_properties(libsodium PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES ${CMAKE_CURRENT_SOURCE_DIR}/build/libsodium/include
    IMPORTED_LOCATION ${CMAKE_CURRENT_SOURCE_DIR}/build/libsodium/lib/libsodium.a
)

add_library(blst STATIC IMPORTED GLOBAL)
add_dependencies(blst blst-external)

set_target_properties(blst PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES ${CMAKE_CURRENT_SOURCE_DIR}/deps/blst/bindings
    IMPORTED_LOCATION ${CMAKE_CURRENT_SOURCE_DIR}/deps/blst/libblst.a
)

add_library(ecc
    src/export.h
    src/ecc.h src/ecc.c
    src/hash.h src/hash.c
    src/ed25519.h src/ed25519.c
    src/ristretto255.h src/ristretto255.c
    src/scalarmult.h src/scalarmult.c
    src/sign.h src/sign.c
    src/bls12_381.h src/bls12_381.c
)

target_compile_features(ecc PUBLIC c_std_11)
target_link_libraries(ecc PRIVATE libsodium blst)
target_compile_definitions(ecc PRIVATE ECC_ALL)

# oprf
add_library(oprf
    src/export.h
    src/ecc.h src/ecc.c
    src/hash.h src/hash.c
    src/ristretto255.h src/ristretto255.c
    src/scalarmult.h src/scalarmult.c
)

target_compile_features(oprf PUBLIC c_std_11)
target_link_libraries(oprf PRIVATE libsodium)
target_compile_definitions(oprf PRIVATE ECC_OPRF)
