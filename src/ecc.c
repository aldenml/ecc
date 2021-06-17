#include "ecc.h"
#include <sodium.h>

void ecc_randombytes(BYTE *buf, int n) {
    randombytes_buf(buf, n);
}

int ecc_compare(const BYTE *a, const BYTE *b, int len) {
    return sodium_compare(a, b, len);
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
