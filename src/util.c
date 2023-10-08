/*
 * Copyright (c) 2021-2023, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#include "util.h"
#include <string.h>
#include <sodium.h>

void ecc_memzero(byte_t *buf, const int len) {
    sodium_memzero(buf, (size_t) len);
}

void ecc_randombytes(byte_t *buf, const int n) {
    randombytes_buf(buf, (size_t) n);
}

void ecc_bin2hex(char *hex, const byte_t *bin, const int bin_len) {
    sodium_bin2hex(hex, 2 * ((size_t) bin_len) + 1, bin, (size_t) bin_len);
}

void ecc_hex2bin(byte_t *bin, const char *hex, const int hex_len) {
    sodium_hex2bin(bin, ((size_t) hex_len) / 2, hex, (size_t) hex_len, NULL, NULL, NULL);
}

void ecc_concat2(
    byte_t *out,
    const byte_t *a1, const int a1_len,
    const byte_t *a2, const int a2_len
) {
    memcpy(out, a1, (size_t) a1_len); out += a1_len;
    memcpy(out, a2, (size_t) a2_len);
}

void ecc_concat3(
    byte_t *out,
    const byte_t *a1, const int a1_len,
    const byte_t *a2, const int a2_len,
    const byte_t *a3, const int a3_len
) {
    memcpy(out, a1, (size_t) a1_len); out += a1_len;
    memcpy(out, a2, (size_t) a2_len); out += a2_len;
    memcpy(out, a3, (size_t) a3_len);
}

void ecc_concat4(
    byte_t *out,
    const byte_t *a1, const int a1_len,
    const byte_t *a2, const int a2_len,
    const byte_t *a3, const int a3_len,
    const byte_t *a4, const int a4_len
) {
    memcpy(out, a1, (size_t) a1_len); out += a1_len;
    memcpy(out, a2, (size_t) a2_len); out += a2_len;
    memcpy(out, a3, (size_t) a3_len); out += a3_len;
    memcpy(out, a4, (size_t) a4_len);
}

void ecc_strxor(byte_t *out, const byte_t *a, const byte_t *b, const int len) {
    for (int i = 0; i < len; i++) {
        out[i] = a[i] ^ b[i];
    }
}

void ecc_I2OSP(byte_t *out, int x, const int xLen) {
    for (int i = xLen - 1; i >= 0; i--) {
        out[i] = x & 0xff;
        x = x >> 8;
    }
}

int ecc_compare(const byte_t *a, const byte_t *b, const int len) {
    return sodium_compare(a, b, (size_t) len);
}

int ecc_is_zero(const byte_t *n, const int len) {
    return sodium_is_zero(n, (size_t) len);
}

int ecc_version(byte_t *out, const int len) {
    const char *v = "1.1.0";
    const int v_len = (int) strlen(v);

    memcpy(out, v, (size_t) (v_len < len ? v_len : len));
    if (v_len < len) out[v_len] = 0;

    return v_len;
}

byte_t *ecc_malloc(const int size) {
    return malloc((size_t) size);
}

void ecc_free(byte_t *p, const int size) {
    ecc_memzero(p, size);
    free(p);
}

#if ECC_LOG
void ecc_log(const char *label, const byte_t *data, const int data_len) {
    char *hex = malloc(2 * ((size_t) data_len) + 1);
    ecc_bin2hex(hex, data, data_len);
    printf("%s: %s\n", label, hex);
    free(hex);
}
#endif
