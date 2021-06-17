#ifndef ECC_ED25519_H
#define ECC_ED25519_H

#include "export.h"

ECC_EXPORT
int ecc_ed25519_is_valid_point(const BYTE *p);

ECC_EXPORT
int ecc_ed25519_add(BYTE *r, const BYTE *p, const BYTE *q);

ECC_EXPORT
int ecc_ed25519_sub(BYTE *r, const BYTE *p, const BYTE *q);

ECC_EXPORT
int ecc_ed25519_from_uniform(BYTE *p, const BYTE *r);

ECC_EXPORT
void ecc_ed25519_random(BYTE *p);

ECC_EXPORT
void ecc_ed25519_scalar_random(BYTE *r);

ECC_EXPORT
int ecc_ed25519_scalar_invert(BYTE *recip, const BYTE *s);

ECC_EXPORT
void ecc_ed25519_scalar_negate(BYTE *neg, const BYTE *s);

ECC_EXPORT
void ecc_ed25519_scalar_complement(BYTE *comp, const BYTE *s);

ECC_EXPORT
void ecc_ed25519_scalar_add(BYTE *z, const BYTE *x, const BYTE *y);

ECC_EXPORT
void ecc_ed25519_scalar_sub(BYTE *z, const BYTE *x, const BYTE *y);

ECC_EXPORT
void ecc_ed25519_scalar_mul(BYTE *z, const BYTE *x, const BYTE *y);

/*
 * The interval `s` is sampled from should be at least 317 bits to
 * ensure almost uniformity of `r` over `L`.
 */
ECC_EXPORT
void ecc_ed25519_scalar_reduce(BYTE *r, const BYTE *s);

#endif // ECC_ED25519_H
