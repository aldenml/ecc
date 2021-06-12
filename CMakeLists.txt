cmake_minimum_required(VERSION 3.16)
project(ecc LANGUAGES C)

set(CMAKE_C_STANDARD 11)

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
else()
    ExternalProject_Add(
        libsodium-external
        SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/libsodium
        CONFIGURE_COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/libsodium/configure
            "CFLAGS=-DSODIUM_STATIC=1 -O2"
            --prefix=${CMAKE_CURRENT_SOURCE_DIR}/build/libsodium
            --disable-ssp
            --disable-shared
            --without-pthreads
        PREFIX ${CMAKE_CURRENT_SOURCE_DIR}/build/libsodium
        BUILD_COMMAND make -j4
        BUILD_IN_SOURCE 1
    )
endif()

file(MAKE_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/build/libsodium/include)

add_library(libsodium STATIC IMPORTED GLOBAL)
add_dependencies(libsodium libsodium-external)

set_target_properties(libsodium PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES ${CMAKE_CURRENT_SOURCE_DIR}/build/libsodium/include
    IMPORTED_LOCATION ${CMAKE_CURRENT_SOURCE_DIR}/build/libsodium/lib/libsodium.a
)

# hash
add_library(hash STATIC
    c/export.h
    c/hash.h c/hash.c
)

target_compile_features(hash PUBLIC c_std_11)
target_link_libraries(hash PRIVATE libsodium)

# ecc
if(NOT DEFINED EMSCRIPTEN)
    add_library(ecc SHARED
        c/export.h
        c/hash.h c/hash.c
    )

    target_compile_features(ecc PUBLIC c_std_11)
    target_link_libraries(ecc PRIVATE libsodium)

    add_library(ecc_static STATIC
        c/export.h
        c/hash.h c/hash.c
    )

    target_compile_features(ecc_static PUBLIC c_std_11)
    target_link_libraries(ecc_static PRIVATE libsodium)

    include(cmake/FetchCmocka.cmake)

    add_executable(hash_test c/test/hash_test.c)
    target_link_libraries(hash_test PRIVATE hash cmocka-static)

    enable_testing()
    add_test(NAME hash_test COMMAND hash_test)
endif()
