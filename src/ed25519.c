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
