/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#include "util.h"
#include <string.h>
#include <sodium.h>

void ecc_memzero(byte_t *p, int len) {
    sodium_memzero(p, len);
}

int ecc_compare(const byte_t *a, const byte_t *b, int len) {
    return sodium_compare(a, b, len);
}

void ecc_randombytes(byte_t *buf, int n) {
    randombytes_buf(buf, n);
}

void ecc_bin2hex(char *hex, const byte_t *bin, int bin_len) {
    sodium_bin2hex(hex, bin_len * 2 + 1, bin, bin_len);
}

void ecc_hex2bin(byte_t *bin, const char *hex, int hex_len) {
    sodium_hex2bin(bin, hex_len / 2, hex, hex_len, NULL, NULL, NULL);
}

byte_t *ecc_concat2(
    byte_t *out,
    const byte_t *a1, const int a1_len,
    const byte_t *a2, const int a2_len
) {
    memcpy(out, a1, a1_len); out += a1_len;
    memcpy(out, a2, a2_len); out += a2_len;
    return out;
}

void ecc_concat3(
    byte_t *out,
    const byte_t *a1, int a1_len,
    const byte_t *a2, int a2_len,
    const byte_t *a3, int a3_len
) {
    memcpy(out, a1, a1_len); out += a1_len;
    memcpy(out, a2, a2_len); out += a2_len;
    memcpy(out, a3, a3_len);
}

void ecc_concat4(
    byte_t *out,
    const byte_t *a1, int a1_len,
    const byte_t *a2, int a2_len,
    const byte_t *a3, int a3_len,
    const byte_t *a4, int a4_len
) {
    memcpy(out, a1, a1_len); out += a1_len;
    memcpy(out, a2, a2_len); out += a2_len;
    memcpy(out, a3, a3_len); out += a3_len;
    memcpy(out, a4, a4_len);
}

void ecc_concat5(
    byte_t *out,
    const byte_t *a1, int a1_len,
    const byte_t *a2, int a2_len,
    const byte_t *a3, int a3_len,
    const byte_t *a4, int a4_len,
    const byte_t *a5, int a5_len
) {
    memcpy(out, a1, a1_len); out += a1_len;
    memcpy(out, a2, a2_len); out += a2_len;
    memcpy(out, a3, a3_len); out += a3_len;
    memcpy(out, a4, a4_len); out += a4_len;
    memcpy(out, a5, a5_len);
}

void strxor(byte_t *out, const byte_t *a, const byte_t *b, int len) {
    for (int i = 0; i < len; i++) {
        out[i] = a[i] ^ b[i];
    }
}

void ecc_I2OSP(byte_t *out, int x, int xLen) {
    for (int i = xLen - 1; i >= 0; i--) {
        out[i] = x & 0xff;
        x = x >> 8;
    }
}

int ecc_is_zero(const BYTE *n, int len) {
    return sodium_is_zero(n, len);
}

void ecc_increment(BYTE *n, int len) {
    return sodium_increment(n, len);
}

void ecc_add(BYTE *a, const BYTE *b, int len) {
    sodium_add(a, b, len);
}

void ecc_sub(BYTE *a, const BYTE *b, int len) {
    sodium_sub(a, b, len);
}
