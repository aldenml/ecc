/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#include "ed25519.h"
#include <sodium.h>

int ecc_ed25519_is_valid_point(const byte_t *p) {
    return crypto_core_ed25519_is_valid_point(p);
}

int ecc_ed25519_add(byte_t *r, const byte_t *p, const byte_t *q) {
    return crypto_core_ed25519_add(r, p, q);
}

int ecc_ed25519_sub(byte_t *r, const byte_t *p, const byte_t *q) {
    return crypto_core_ed25519_sub(r, p, q);
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
    return crypto_scalarmult_ed25519_noclamp(q, n, p);
}

int ecc_ed25519_scalarmult_base(byte_t *q, const byte_t *n) {
    return crypto_scalarmult_ed25519_base_noclamp(q, n);
}

void ecc_ed25519_sign(byte_t *sig, const byte_t *msg, int msg_len, const byte_t *sk) {
    crypto_sign_ed25519_detached(sig, NULL, msg, msg_len, sk);
}

int ecc_ed25519_sign_verify(const byte_t *sig, const byte_t *msg, int msg_len, const byte_t *pk) {
    return crypto_sign_ed25519_verify_detached(sig, msg, msg_len, pk);
}

void ecc_ed25519_sign_keypair(byte_t *pk, byte_t *sk) {
    crypto_sign_ed25519_keypair(pk, sk);
}

void ecc_ed25519_sign_seed_keypair(byte_t *pk, byte_t *sk, const byte_t *seed) {
    crypto_sign_ed25519_seed_keypair(pk, sk, seed);
}

void ecc_ed25519_sign_sk_to_seed(byte_t *seed, const byte_t *sk) {
    crypto_sign_ed25519_sk_to_seed(seed, sk);
}

void ecc_ed25519_sign_sk_to_pk(byte_t *pk, const byte_t *sk) {
    crypto_sign_ed25519_sk_to_pk(pk, sk);
}
