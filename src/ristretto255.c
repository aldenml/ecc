#include "ristretto255.h"
#include <sodium.h>

int ecc_ristretto255_is_valid_point(const BYTE *p) {
    return crypto_core_ristretto255_is_valid_point(p);
}

int ecc_ristretto255_add(BYTE *r, const BYTE *p, const BYTE *q) {
    return crypto_core_ristretto255_add(r, p, q);
}

int ecc_ristretto255_sub(BYTE *r, const BYTE *p, const BYTE *q) {
    return crypto_core_ristretto255_sub(r, p, q);
}

int ecc_ristretto255_from_hash(BYTE *p, const BYTE *r) {
    return crypto_core_ristretto255_from_hash(p, r);
}

void ecc_ristretto255_random(BYTE *p) {
    crypto_core_ristretto255_random(p);
}

void ecc_ristretto255_scalar_random(BYTE *r) {
    crypto_core_ristretto255_scalar_random(r);
}

int ecc_ristretto255_scalar_invert(BYTE *recip, const BYTE *s) {
    return crypto_core_ristretto255_scalar_invert(recip, s);
}

void ecc_ristretto255_scalar_negate(BYTE *neg, const BYTE *s) {
    crypto_core_ristretto255_scalar_negate(neg, s);
}

void ecc_ristretto255_scalar_complement(BYTE *comp, const BYTE *s) {
    crypto_core_ristretto255_scalar_complement(comp, s);
}

void ecc_ristretto255_scalar_add(BYTE *z, const BYTE *x, const BYTE *y) {
    crypto_core_ristretto255_scalar_add(z, x, y);
}

void ecc_ristretto255_scalar_sub(BYTE *z, const BYTE *x, const BYTE *y) {
    crypto_core_ristretto255_scalar_sub(z, x, y);
}

void ecc_ristretto255_scalar_mul(BYTE *z, const BYTE *x, const BYTE *y) {
    crypto_core_ristretto255_scalar_mul(z, x, y);
}

/*
 * The interval `s` is sampled from should be at least 317 bits to
 * ensure almost uniformity of `r` over `L`.
 */
void ecc_ristretto255_scalar_reduce(BYTE *r, const BYTE *s) {
    crypto_core_ristretto255_scalar_reduce(r, s);
}
