#
# Copyright (c) 2021-2022, Alden Torres
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

project(ecc VERSION 1.0.9)
project(ecc LANGUAGES C)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake/Modules)

function(SET_EXTRA_COMPILER_FLAGS TARGET_ARG)
    if(CMAKE_CXX_COMPILER_ID MATCHES Clang)
        target_compile_options(${TARGET_ARG} PRIVATE
            -Weverything
            -Werror
        )
        target_compile_definitions(${TARGET_ARG} PRIVATE _FORTIFY_SOURCE=2)
    elseif(CMAKE_CXX_COMPILER_ID MATCHES GNU)
        target_compile_options(${TARGET_ARG} PRIVATE
            -Wall
            -Wextra
            -Wpedantic
            -Werror
        )
        target_compile_definitions(${TARGET_ARG} PRIVATE _FORTIFY_SOURCE=2)
    endif()
endfunction()

include(ExternalProject)
if(EMSCRIPTEN)
    ExternalProject_Add(
        libsodium-external
        SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/deps/libsodium
        CONFIGURE_COMMAND emconfigure ${CMAKE_CURRENT_SOURCE_DIR}/deps/libsodium/configure
            "CFLAGS=-DSODIUM_STATIC=1 -Oz -Wno-cpp"
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
        BUILD_COMMAND AR=emar ./build.sh CC=emcc -D__BLST_PORTABLE__ -Oz
        BUILD_IN_SOURCE 1
        INSTALL_COMMAND ""
    )
elseif(NOT WIN32)
    ExternalProject_Add(
        libsodium-external
        SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/deps/libsodium
        CONFIGURE_COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/deps/libsodium/configure
            "CFLAGS=-DSODIUM_STATIC=1 -O2 -Wno-cpp"
            --prefix=${CMAKE_CURRENT_SOURCE_DIR}/build/libsodium
            --disable-ssp
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
        BUILD_COMMAND ./build.sh -O2
        BUILD_IN_SOURCE 1
        INSTALL_COMMAND ""
    )
endif()

if(NOT WIN32)
    # setup build configure for libsodium
    ExternalProject_Add_Step(
        libsodium-external autogen
        COMMAND ./autogen.sh -s
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/deps/libsodium
        COMMENT "Running autogen.sh tool"
        DEPENDERS configure
    )
endif()

file(MAKE_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/build/libsodium/include)

add_library(libsodium STATIC IMPORTED GLOBAL)
if(NOT WIN32)
    add_dependencies(libsodium libsodium-external)
endif()

set_target_properties(libsodium PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES ${CMAKE_CURRENT_SOURCE_DIR}/build/libsodium/include
    IMPORTED_LOCATION ${CMAKE_CURRENT_SOURCE_DIR}/build/libsodium/lib/libsodium.a
)

add_library(blst STATIC IMPORTED GLOBAL)
if(NOT WIN32)
    add_dependencies(blst blst-external)
endif()

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
    src/sign.h src/sign.c
    src/pre.h src/pre.c
    src/ecc.h
)

# ecc
if(EMSCRIPTEN)
    add_library(ecc STATIC ${ecc_src_files})
    target_compile_options(ecc PRIVATE -Oz)
else()
    add_library(ecc SHARED ${ecc_src_files})
    target_compile_options(ecc PRIVATE -O2)
    set_extra_compiler_flags(ecc)
endif()

target_compile_features(ecc PUBLIC c_std_11)
target_link_libraries(ecc PRIVATE libsodium blst)
target_compile_definitions(ecc PRIVATE ECC_EXPORT_SYMBOLS)
target_include_directories(ecc PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

if(NOT DEFINED EMSCRIPTEN)
    # ecc static
    add_library(ecc_static STATIC ${ecc_src_files})

    target_compile_features(ecc_static PUBLIC c_std_11)
    target_compile_options(ecc_static PRIVATE -O2)
    target_link_libraries(ecc_static PRIVATE libsodium blst)
    target_include_directories(ecc_static PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    )
    set_extra_compiler_flags(ecc_static)

    # jvm
    add_library(ecc-jvm SHARED
        bindings/jvm/jni.h
        bindings/jvm/libecc.c
    )

    target_compile_features(ecc-jvm PUBLIC c_std_11)
    target_compile_options(ecc-jvm PRIVATE -O2)
    target_link_libraries(ecc-jvm PRIVATE ecc_static)
endif()

if(NOT DEFINED EMSCRIPTEN)
    include(FetchCmocka)

    add_library(ecc_test STATIC
        test/ecc_test.h test/ecc_test.c
        test/cJSON.h test/cJSON.c
    )
    target_link_libraries(ecc_test PUBLIC ecc cmocka-static)
    set_extra_compiler_flags(ecc_test)

    # tests executables
    add_executable(test_util test/test_util.c)
    target_link_libraries(test_util PRIVATE ecc_test)
    add_executable(test_kdf test/test_kdf.c)
    target_link_libraries(test_kdf PRIVATE ecc_test)
    add_executable(test_bls12_381 test/test_bls12_381.c)
    target_link_libraries(test_bls12_381 PRIVATE ecc_test)
    add_executable(test_h2c test/test_h2c.c)
    target_link_libraries(test_h2c PRIVATE ecc_test)
    add_executable(test_oprf test/test_oprf.c)
    target_link_libraries(test_oprf PRIVATE ecc_test)
    add_executable(test_opaque test/test_opaque.c)
    target_link_libraries(test_opaque PRIVATE ecc_test)
    add_executable(test_sign test/test_sign.c)
    target_link_libraries(test_sign PRIVATE ecc_test)
    add_executable(test_pre test/test_pre.c)
    target_link_libraries(test_pre PRIVATE ecc_test)
    add_executable(test_json test/test_json.c)
    target_link_libraries(test_json PRIVATE ecc_test)

    set_extra_compiler_flags(test_util)
    set_extra_compiler_flags(test_kdf)
    set_extra_compiler_flags(test_bls12_381)
    set_extra_compiler_flags(test_h2c)
    set_extra_compiler_flags(test_oprf)
    set_extra_compiler_flags(test_opaque)
    set_extra_compiler_flags(test_sign)
    set_extra_compiler_flags(test_pre)
    set_extra_compiler_flags(test_json)

    # setup coverage
    if(CODE_COVERAGE)
        include(code-coverage)
        add_code_coverage_all_targets(EXCLUDE test/*)
        target_code_coverage(ecc AUTO ALL)
        target_code_coverage(test_util AUTO ALL EXTERNAL)
        target_code_coverage(test_kdf AUTO ALL EXTERNAL)
        target_code_coverage(test_bls12_381 AUTO ALL EXTERNAL)
        target_code_coverage(test_h2c AUTO ALL EXTERNAL)
        target_code_coverage(test_oprf AUTO ALL EXTERNAL)
        target_code_coverage(test_opaque AUTO ALL EXTERNAL)
        target_code_coverage(test_sign AUTO ALL EXTERNAL)
        target_code_coverage(test_pre AUTO ALL EXTERNAL)
        target_code_coverage(test_json AUTO ALL EXTERNAL)
    endif()

    enable_testing()
    add_test(NAME test_util COMMAND test_util)
    add_test(NAME test_kdf COMMAND test_kdf)
    add_test(NAME test_bls12_381 COMMAND test_bls12_381)
    add_test(NAME test_h2c COMMAND test_h2c)
    add_test(NAME test_oprf COMMAND test_oprf)
    add_test(NAME test_opaque COMMAND test_opaque)
    add_test(NAME test_sign COMMAND test_sign)
    add_test(NAME test_pre COMMAND test_pre)
    add_test(NAME test_json COMMAND test_json)
endif()
