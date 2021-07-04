/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#include "ed25519.h"
#include <sodium.h>

int ecc_ed25519_is_valid_point(const BYTE *p) {
    return crypto_core_ed25519_is_valid_point(p);
}

int ecc_ed25519_add(BYTE *r, const BYTE *p, const BYTE *q) {
    return crypto_core_ed25519_add(r, p, q);
}

int ecc_ed25519_sub(BYTE *r, const BYTE *p, const BYTE *q) {
    return crypto_core_ed25519_sub(r, p, q);
}

int ecc_ed25519_from_uniform(BYTE *p, const BYTE *r) {
    return crypto_core_ed25519_from_uniform(p, r);
}

void ecc_ed25519_random(BYTE *p) {
    crypto_core_ed25519_random(p);
}

void ecc_ed25519_scalar_random(BYTE *r) {
    crypto_core_ed25519_scalar_random(r);
}

int ecc_ed25519_scalar_invert(BYTE *recip, const BYTE *s) {
    return crypto_core_ed25519_scalar_invert(recip, s);
}

void ecc_ed25519_scalar_negate(BYTE *neg, const BYTE *s) {
    crypto_core_ed25519_scalar_negate(neg, s);
}

void ecc_ed25519_scalar_complement(BYTE *comp, const BYTE *s) {
    crypto_core_ed25519_scalar_complement(comp, s);
}

void ecc_ed25519_scalar_add(BYTE *z, const BYTE *x, const BYTE *y) {
    crypto_core_ed25519_scalar_add(z, x, y);
}

void ecc_ed25519_scalar_sub(BYTE *z, const BYTE *x, const BYTE *y) {
    crypto_core_ed25519_scalar_sub(z, x, y);
}

void ecc_ed25519_scalar_mul(BYTE *z, const BYTE *x, const BYTE *y) {
    crypto_core_ed25519_scalar_mul(z, x, y);
}

/*
 * The interval `s` is sampled from should be at least 317 bits to
 * ensure almost uniformity of `r` over `L`.
 */
void ecc_ed25519_scalar_reduce(BYTE *r, const BYTE *s) {
    crypto_core_ed25519_scalar_reduce(r, s);
}

int ecc_ed25519_scalarmultx(byte_t *q, const byte_t *n, const byte_t *p) {
    return crypto_scalarmult_ed25519(q, n, p);
}

int ecc_ed25519_scalarmult_noclamp(byte_t *q, const byte_t *n, const byte_t *p) {
    return crypto_scalarmult_ed25519_noclamp(q, n, p);
}

int ecc_ed25519_scalarmult_base(byte_t *q, const byte_t *n) {
    return crypto_scalarmult_ed25519_base(q, n);
}

int ecc_ed25519_scalarmult_base_noclamp(byte_t *q, const byte_t *n) {
    return crypto_scalarmult_ed25519_base_noclamp(q, n);
}

int ecc_ed25519_sign(BYTE *sm, int *smlen_p, const BYTE *m, int mlen, const BYTE *sk) {
    return crypto_sign_ed25519(sm, (unsigned long long *) smlen_p, m, mlen, sk);
}

int ecc_ed25519_sign_open(BYTE *m, int *mlen_p, const BYTE *sm, int smlen, const BYTE *pk) {
    return crypto_sign_ed25519_open(m, (unsigned long long *) mlen_p, sm, smlen, pk);
}

int ecc_ed25519_sign_detached(BYTE *sig, int *siglen_p, const BYTE *m, int mlen, const BYTE *sk) {
    return crypto_sign_ed25519_detached(sig, (unsigned long long *) siglen_p, m, mlen, sk);
}

int ecc_ed25519_sign_verify_detached(const BYTE *sig, const BYTE *m, int mlen, const BYTE *pk) {
    return crypto_sign_ed25519_verify_detached(sig, m, mlen, pk);
}

int ecc_ed25519_sign_keypair(BYTE *pk, BYTE *sk) {
    return crypto_sign_ed25519_keypair(pk, sk);
}

int ecc_ed25519_sign_seed_keypair(BYTE *pk, BYTE *sk, const BYTE *seed) {
    return crypto_sign_ed25519_seed_keypair(pk, sk, seed);
}

int ecc_ed25519_sign_sk_to_seed(BYTE *seed, const BYTE *sk) {
    return crypto_sign_ed25519_sk_to_seed(seed, sk);
}

int ecc_ed25519_sign_sk_to_pk(BYTE *pk, const BYTE *sk) {
    return crypto_sign_ed25519_sk_to_pk(pk, sk);
}
