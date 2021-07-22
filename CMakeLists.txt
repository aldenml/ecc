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
        SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/deps/libsodium
        CONFIGURE_COMMAND emconfigure ${CMAKE_CURRENT_SOURCE_DIR}/deps/libsodium/configure
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
        SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/deps/libsodium
        CONFIGURE_COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/deps/libsodium/configure
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

set(ecc_src_files
    src/export.h
    src/util.h src/util.c
    src/hash.h src/hash.c
    src/mac.h src/mac.c
    src/kdf.h src/kdf.c
    src/ed25519.h src/ed25519.c
    src/ristretto255.h src/ristretto255.c
    src/bls12_381.h src/bls12_381.c
    src/h2c.h src/h2c.c
    src/oprf.h src/oprf.c
    src/opaque.h src/opaque.c
    src/pre.h src/pre.c
    src/ecc.h
)

# ecc shared
add_library(ecc SHARED ${ecc_src_files})

target_compile_features(ecc PUBLIC c_std_11)
target_link_libraries(ecc PRIVATE libsodium blst)
target_compile_definitions(ecc PRIVATE ECC_ALL)
target_include_directories(ecc PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

# ecc static
add_library(ecc_static STATIC ${ecc_src_files})

target_compile_features(ecc_static PUBLIC c_std_11)
target_link_libraries(ecc_static PRIVATE libsodium blst)
target_include_directories(ecc_static PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

# oprf
add_library(oprf
    src/export.h
    src/util.h src/util.c
    src/hash.h src/hash.c
    src/ristretto255.h src/ristretto255.c
    src/h2c.h src/h2c.c
    src/oprf.h src/oprf.c
)

target_compile_features(oprf PUBLIC c_std_11)
target_link_libraries(oprf PRIVATE libsodium)
target_compile_definitions(oprf PRIVATE ECC_OPRF)

# opaque
add_library(opaque
    src/export.h
    src/util.h src/util.c
    src/hash.h src/hash.c
    src/mac.h src/mac.c
    src/kdf.h src/kdf.c
    src/ristretto255.h src/ristretto255.c
    src/h2c.h src/h2c.c
    src/oprf.h src/oprf.c
    src/opaque.h src/opaque.c
)

target_compile_features(opaque PUBLIC c_std_11)
target_link_libraries(opaque PRIVATE libsodium)
target_compile_definitions(opaque PRIVATE ECC_OPAQUE)

if(EMSCRIPTEN)
    target_compile_options(ecc PRIVATE -Oz)
    target_compile_options(oprf PRIVATE -Oz)
    target_compile_options(opaque PRIVATE -Oz)
endif()

# jvm
add_library(ecc-jvm
    jvm/jni.h
    jvm/libecc.c
)

target_compile_features(ecc-jvm PUBLIC c_std_11)
target_link_libraries(ecc-jvm PRIVATE ecc_static)

if(NOT DEFINED EMSCRIPTEN)
    include(cmake/FetchCmocka.cmake)

    # tests executables
    add_executable(test_util test/test_util.c)
    target_link_libraries(test_util PRIVATE ecc cmocka-static)
    add_executable(test_kdf test/test_kdf.c)
    target_link_libraries(test_kdf PRIVATE ecc cmocka-static)
    add_executable(test_bls12_381 test/test_bls12_381.c)
    target_link_libraries(test_bls12_381 PRIVATE ecc cmocka-static)
    add_executable(test_h2c test/test_h2c.c)
    target_link_libraries(test_h2c PRIVATE ecc cmocka-static)
    add_executable(test_oprf test/test_oprf.c)
    target_link_libraries(test_oprf PRIVATE ecc cmocka-static)
    add_executable(test_opaque test/test_opaque.c)
    target_link_libraries(test_opaque PRIVATE ecc cmocka-static)
    add_executable(test_pre test/test_pre.c)
    target_link_libraries(test_pre PRIVATE ecc cmocka-static)

    enable_testing()
    add_test(NAME test_util COMMAND test_util)
    add_test(NAME test_kdf COMMAND test_kdf)
    add_test(NAME test_bls12_381 COMMAND test_bls12_381)
    add_test(NAME test_h2c COMMAND test_h2c)
    add_test(NAME test_oprf COMMAND test_oprf)
    add_test(NAME test_opaque COMMAND test_opaque)
    add_test(NAME test_pre COMMAND test_pre)
endif()
