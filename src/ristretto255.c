/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#include "ristretto255.h"
#include <sodium.h>

int ecc_ristretto255_is_valid_point(const byte_t *p) {
    return crypto_core_ristretto255_is_valid_point(p);
}

int ecc_ristretto255_add(byte_t *r, const byte_t *p, const byte_t *q) {
    return crypto_core_ristretto255_add(r, p, q);
}

int ecc_ristretto255_sub(byte_t *r, const byte_t *p, const byte_t *q) {
    return crypto_core_ristretto255_sub(r, p, q);
}

void ecc_ristretto255_from_hash(byte_t *p, const byte_t *r) {
    crypto_core_ristretto255_from_hash(p, r);
}

void ecc_ristretto255_random(byte_t *p) {
    crypto_core_ristretto255_random(p);
}

void ecc_ristretto255_scalar_random(byte_t *r) {
    crypto_core_ristretto255_scalar_random(r);
}

int ecc_ristretto255_scalar_invert(byte_t *recip, const byte_t *s) {
    return crypto_core_ristretto255_scalar_invert(recip, s);
}

void ecc_ristretto255_scalar_negate(byte_t *neg, const byte_t *s) {
    crypto_core_ristretto255_scalar_negate(neg, s);
}

void ecc_ristretto255_scalar_complement(byte_t *comp, const byte_t *s) {
    crypto_core_ristretto255_scalar_complement(comp, s);
}

void ecc_ristretto255_scalar_add(byte_t *z, const byte_t *x, const byte_t *y) {
    crypto_core_ristretto255_scalar_add(z, x, y);
}

void ecc_ristretto255_scalar_sub(byte_t *z, const byte_t *x, const byte_t *y) {
    crypto_core_ristretto255_scalar_sub(z, x, y);
}

void ecc_ristretto255_scalar_mul(byte_t *z, const byte_t *x, const byte_t *y) {
    crypto_core_ristretto255_scalar_mul(z, x, y);
}

void ecc_ristretto255_scalar_reduce(byte_t *r, const byte_t *s) {
    crypto_core_ristretto255_scalar_reduce(r, s);
}

int ecc_ristretto255_scalarmult(byte_t *q, const byte_t *n, const byte_t *p) {
    return crypto_scalarmult_ristretto255(q, n, p);
}

int ecc_ristretto255_scalarmult_base(byte_t *q, const byte_t *n) {
    return crypto_scalarmult_ristretto255_base(q, n);
}
