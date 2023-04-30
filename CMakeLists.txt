#
# Copyright (c) 2021-2023, Alden Torres
#
# Licensed under the terms of the MIT license.
# Copy of the license at https://opensource.org/licenses/MIT
#

cmake_minimum_required(VERSION 3.16)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_VISIBILITY_PRESET hidden)

if(APPLE)
    set(CMAKE_OSX_DEPLOYMENT_TARGET "11" CACHE STRING "" FORCE)
    if($ENV{ECC_CFLAGS} MATCHES "-arch x86_64")
        set(CMAKE_OSX_ARCHITECTURES "x86_64" CACHE STRING "" FORCE)
        set(CONFIGURE_HOST_OPTION "--host=x86_64-apple-darwin" CACHE STRING "" FORCE)
    elseif($ENV{ECC_CFLAGS} MATCHES "-arch arm64")
        set(CMAKE_OSX_ARCHITECTURES "arm64" CACHE STRING "" FORCE)
        set(CONFIGURE_HOST_OPTION "--host=arm64-apple-darwin" CACHE STRING "" FORCE)
    else()
        set(CONFIGURE_HOST_OPTION "" CACHE STRING "" FORCE)
    endif()
endif()

if(EMSCRIPTEN)
    set(BUILD_SHARED_LIBS OFF)
else()
    set(BUILD_SHARED_LIBS ON)
endif()

project(ecc VERSION 1.0.20)
project(ecc LANGUAGES C)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake/Modules)

# setup extra compiler flags to a target
function(SET_EXTRA_COMPILER_FLAGS TARGET_ARG)
    if(CMAKE_CXX_COMPILER_ID MATCHES Clang)
        target_compile_options(${TARGET_ARG} PRIVATE
            -Weverything
            -Werror
            -Wno-declaration-after-statement
        )
        target_compile_definitions(${TARGET_ARG} PRIVATE _FORTIFY_SOURCE=2)
    elseif(CMAKE_CXX_COMPILER_ID MATCHES GNU)
        target_compile_options(${TARGET_ARG} PRIVATE
            -Wall
            -Wextra
            -Wpedantic
            -Werror
        )
        if(NOT WIN32)
            target_compile_definitions(${TARGET_ARG} PRIVATE _FORTIFY_SOURCE=2)
        endif()
    endif()
endfunction()

# setup a unit test
function(SETUP_TARGET_TEST TARGET_ARG)
    add_executable(test_${TARGET_ARG} test/test_${TARGET_ARG}.c)
    target_link_libraries(test_${TARGET_ARG} PRIVATE ecc_test)
    set_extra_compiler_flags(test_${TARGET_ARG})

    if(CODE_COVERAGE)
        target_code_coverage(test_${TARGET_ARG} AUTO ALL EXTERNAL)
    endif()

    add_test(NAME test_${TARGET_ARG} COMMAND test_${TARGET_ARG})
endfunction()

# common dependencies directories
set(LIBSODIUM_DEPS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/deps/libsodium)
set(LIBSODIUM_BUILD_DIR ${CMAKE_CURRENT_SOURCE_DIR}/build/libsodium)
set(BLST_DEPS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/deps/blst)

# setup external projects libsodium and blst
include(ExternalProject)
if(EMSCRIPTEN)
    ExternalProject_Add(
        libsodium_external
        SOURCE_DIR ${LIBSODIUM_DEPS_DIR}
        CONFIGURE_COMMAND emconfigure ${LIBSODIUM_DEPS_DIR}/configure
            "CFLAGS=-DSODIUM_STATIC=1 -Oz -Wno-cpp"
            --prefix=${LIBSODIUM_BUILD_DIR}
            --disable-ssp
            --disable-asm
            --disable-pie
            --disable-shared
            --without-pthreads
        PREFIX ${LIBSODIUM_BUILD_DIR}
        BUILD_COMMAND emmake make -j4
        BUILD_IN_SOURCE 1
    )
    ExternalProject_Add(
        blst_external
        SOURCE_DIR ${BLST_DEPS_DIR}
        CONFIGURE_COMMAND ""
        BUILD_COMMAND AR=emar ./build.sh CC=emcc -D__BLST_PORTABLE__ -Oz
        BUILD_IN_SOURCE 1
        INSTALL_COMMAND ""
    )
elseif(NOT WIN32)
    ExternalProject_Add(
        libsodium_external
        SOURCE_DIR ${LIBSODIUM_DEPS_DIR}
        CONFIGURE_COMMAND ${LIBSODIUM_DEPS_DIR}/configure ${CONFIGURE_HOST_OPTION}
            "CFLAGS=-DSODIUM_STATIC=1 -O2 -Wno-cpp $ENV{ECC_CFLAGS}"
            --prefix=${LIBSODIUM_BUILD_DIR}
            --disable-ssp
            --disable-shared
            --without-pthreads
        PREFIX ${LIBSODIUM_BUILD_DIR}
        BUILD_COMMAND make -j4
        BUILD_IN_SOURCE 1
        BUILD_BYPRODUCTS ${LIBSODIUM_BUILD_DIR}/lib/libsodium.a
    )
    ExternalProject_Add(
        blst_external
        SOURCE_DIR ${BLST_DEPS_DIR}
        CONFIGURE_COMMAND ""
        BUILD_COMMAND ./build.sh -O2 "$ENV{ECC_CFLAGS}"
        BUILD_IN_SOURCE 1
        BUILD_BYPRODUCTS ${BLST_DEPS_DIR}/libblst.a
        INSTALL_COMMAND ""
    )
endif()

# since we are using libsodium master branch, autogen needs to be run
if(NOT WIN32)
    # setup build configure for libsodium
    ExternalProject_Add_Step(
        libsodium_external autogen
        COMMAND ./autogen.sh -s
        WORKING_DIRECTORY ${LIBSODIUM_DEPS_DIR}
        COMMENT "Running autogen.sh tool"
        DEPENDERS configure
    )
endif()

# setup libsodium library
file(MAKE_DIRECTORY ${LIBSODIUM_BUILD_DIR}/include)
add_library(libsodium STATIC IMPORTED GLOBAL)
if(NOT WIN32 AND (NOT ${CMAKE_SYSTEM_NAME} MATCHES "iOS"))
    add_dependencies(libsodium libsodium_external)
endif()
set_target_properties(libsodium PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES ${LIBSODIUM_BUILD_DIR}/include
    IMPORTED_LOCATION ${LIBSODIUM_BUILD_DIR}/lib/libsodium.a
)

# setup blst library
add_library(blst STATIC IMPORTED GLOBAL)
if(NOT WIN32 AND (NOT ${CMAKE_SYSTEM_NAME} MATCHES "iOS"))
    add_dependencies(blst blst_external)
endif()
set_target_properties(blst PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES ${BLST_DEPS_DIR}/bindings
    IMPORTED_LOCATION ${BLST_DEPS_DIR}/libblst.a
)

# main set of source files
set(ecc_src_files
    src/export.h
    src/util.h src/util.c
    src/hash.h src/hash.c
    src/mac.h src/mac.c
    src/kdf.h src/kdf.c
    src/aead.h src/aead.c
    src/ed25519.h src/ed25519.c
    src/ristretto255.h src/ristretto255.c
    src/bls12_381.h src/bls12_381.c
    src/h2c.h src/h2c.c
    src/voprf.h src/voprf.c
    src/opaque.h src/opaque.c
    src/sign.h src/sign.c
    src/frost.h src/frost.c
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
    add_library(ecc_jvm SHARED
        bindings/jvm/jni.h bindings/jvm/libecc.c
    )
    set_target_properties(ecc_jvm PROPERTIES OUTPUT_NAME "ecc-jvm")

    target_compile_features(ecc_jvm PUBLIC c_std_11)
    target_compile_options(ecc_jvm PRIVATE -O2)
    target_link_libraries(ecc_jvm PRIVATE ecc_static)
endif()

# unit tests
if(NOT DEFINED EMSCRIPTEN)
    include(FetchCmocka)

    add_library(ecc_test STATIC
        test/ecc_test.h test/ecc_test.c
        test/cJSON.h test/cJSON.c
    )
    target_link_libraries(ecc_test PUBLIC ecc cmocka-static)
    set_extra_compiler_flags(ecc_test)

    # setup coverage
    if(CODE_COVERAGE)
        include(code-coverage)
        add_code_coverage_all_targets(EXCLUDE test/*)
        target_code_coverage(ecc AUTO ALL)
    endif()

    enable_testing()

    # unit tests executables
    setup_target_test(json)
    setup_target_test(util)
    setup_target_test(hash)
    setup_target_test(mac)
    setup_target_test(kdf)
    setup_target_test(aead)
    setup_target_test(ed25519)
    setup_target_test(ristretto255)
    setup_target_test(bls12_381)
    setup_target_test(h2c)
    setup_target_test(voprf)
    setup_target_test(opaque)
    setup_target_test(sign)
    setup_target_test(frost)
    setup_target_test(pre)
endif()
