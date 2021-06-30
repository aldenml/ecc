/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#ifndef ECC_UTIL_H
#define ECC_UTIL_H

#include "export.h"

ECC_OPRF_EXPORT
ECC_OPAQUE_EXPORT
ECC_EXPORT
void ecc_memzero(BYTE *p, int len);

ECC_EXPORT
void ecc_bin2hex(char *hex, const byte_t *bin, int bin_len);

ECC_EXPORT
void ecc_hex2bin(byte_t *bin, const char *hex, int hex_len);

/**
 * Concatenates two byte arrays. Sames as a || b.
 *
 * a || b: denotes the concatenation of byte strings a and b. For
 * example, "ABC" || "DEF" == "ABCDEF".
 *
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-11#section-4
 *
 * @param out
 * @param a
 * @param b
 */
ECC_EXPORT
void ecc_concat2(
    byte_t *out,
    const byte_t *a1, int a1_len,
    const byte_t *a2, int a2_len
);

ECC_EXPORT
void ecc_concat3(
    byte_t *out,
    byte_t *a1, int a1_len,
    byte_t *a2, int a2_len,
    byte_t *a3, int a3_len
);

ECC_EXPORT
void ecc_concat4(
    byte_t *out,
    byte_t *a1, int a1_len,
    byte_t *a2, int a2_len,
    byte_t *a3, int a3_len,
    byte_t *a4, int a4_len
);

ECC_EXPORT
void ecc_concat5(
    byte_t *out,
    byte_t *a1, int a1_len,
    byte_t *a2, int a2_len,
    byte_t *a3, int a3_len,
    byte_t *a4, int a4_len,
    byte_t *a5, int a5_len
);

ECC_EXPORT
void strxor(byte_t *out, const byte_t *a, const byte_t *b, int len);

// https://datatracker.ietf.org/doc/html/rfc8017#section-4.1
ECC_EXPORT
void ecc_I2OSP(byte_t *out, int x, int xLen);

#endif // ECC_UTIL_H
