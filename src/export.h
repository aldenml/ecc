/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#ifndef ECC_EXPORT_H
#define ECC_EXPORT_H

#ifdef __cplusplus
    #define SYMBOL_EXPORT extern "C" __attribute__((visibility("default"))) __attribute__((used))
#else
    #define SYMBOL_EXPORT __attribute__((visibility("default"))) __attribute__((used))
#endif

#if defined ECC_EXPORT_SYMBOLS
    #define ECC_EXPORT SYMBOL_EXPORT
#else
    #define ECC_EXPORT
#endif

typedef unsigned char byte_t;

#endif // ECC_EXPORT_H
