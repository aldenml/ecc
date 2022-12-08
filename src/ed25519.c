/*
 * Copyright (c) 2021-2022, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#include "ed25519.h"

#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcpp"
#endif

#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wcpp"
#endif

#include <sodium.h>

#ifdef __clang__
#pragma clang diagnostic pop
#endif

#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

int ecc_ed25519_is_valid_point(const byte_t *p) {
    return crypto_core_ed25519_is_valid_point(p);
}

int ecc_ed25519_add(byte_t *r, const byte_t *p, const byte_t *q) {
    return crypto_core_ed25519_add(r, p, q);
}

int ecc_ed25519_sub(byte_t *r, const byte_t *p, const byte_t *q) {
    return crypto_core_ed25519_sub(r, p, q);
}

void ecc_ed25519_generator(byte_t *g) {
    byte_t one[ecc_ed25519_SCALARSIZE] = {0};
    one[0] = 0x01;
    ecc_ed25519_scalarmult_base(g, one);
}

void ecc_ed25519_from_uniform(byte_t *p, const byte_t *r) {
    crypto_core_ed25519_from_uniform(p, r);
}

void ecc_ed25519_random(byte_t *p) {
    crypto_core_ed25519_random(p);
}

void ecc_ed25519_scalar_random(byte_t *r) {
    crypto_core_ed25519_scalar_random(r);
}

int ecc_ed25519_scalar_invert(byte_t *recip, const byte_t *s) {
    return crypto_core_ed25519_scalar_invert(recip, s);
}

void ecc_ed25519_scalar_negate(byte_t *neg, const byte_t *s) {
    crypto_core_ed25519_scalar_negate(neg, s);
}

void ecc_ed25519_scalar_complement(byte_t *comp, const byte_t *s) {
    crypto_core_ed25519_scalar_complement(comp, s);
}

void ecc_ed25519_scalar_add(byte_t *z, const byte_t *x, const byte_t *y) {
    crypto_core_ed25519_scalar_add(z, x, y);
}

void ecc_ed25519_scalar_sub(byte_t *z, const byte_t *x, const byte_t *y) {
    crypto_core_ed25519_scalar_sub(z, x, y);
}

void ecc_ed25519_scalar_mul(byte_t *z, const byte_t *x, const byte_t *y) {
    crypto_core_ed25519_scalar_mul(z, x, y);
}

void ecc_ed25519_scalar_reduce(byte_t *r, const byte_t *s) {
    crypto_core_ed25519_scalar_reduce(r, s);
}

int ecc_ed25519_scalarmult(byte_t *q, const byte_t *n, const byte_t *p) {
    return crypto_scalarmult_ed25519(q, n, p);
}

int ecc_ed25519_scalarmult_base(byte_t *q, const byte_t *n) {
    return crypto_scalarmult_ed25519_base(q, n);
}
