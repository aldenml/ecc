/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

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

ECC_EXPORT
int ecc_ed25519_scalarmult(byte_t *q, const byte_t *n, const byte_t *p);

ECC_EXPORT
int ecc_ed25519_scalarmult_noclamp(byte_t *q, const byte_t *n, const byte_t *p);

ECC_EXPORT
int ecc_ed25519_scalarmult_base(byte_t *q, const byte_t *n);

ECC_EXPORT
int ecc_ed25519_scalarmult_base_noclamp(byte_t *q, const byte_t *n);

ECC_EXPORT
int ecc_ed25519_sign(BYTE *sm, int *smlen_p, const BYTE *m, int mlen, const BYTE *sk);

ECC_EXPORT
int ecc_ed25519_sign_open(BYTE *m, int *mlen_p, const BYTE *sm, int smlen, const BYTE *pk);

ECC_EXPORT
int ecc_ed25519_sign_detached(BYTE *sig, int *siglen_p, const BYTE *m, int mlen, const BYTE *sk);

ECC_EXPORT
int ecc_ed25519_sign_verify_detached(const BYTE *sig, const BYTE *m, int mlen, const BYTE *pk);

ECC_EXPORT
int ecc_ed25519_sign_keypair(BYTE *pk, BYTE *sk);

ECC_EXPORT
int ecc_ed25519_sign_seed_keypair(BYTE *pk, BYTE *sk, const BYTE *seed);

ECC_EXPORT
int ecc_ed25519_sign_sk_to_seed(BYTE *seed, const BYTE *sk);

ECC_EXPORT
int ecc_ed25519_sign_sk_to_pk(BYTE *pk, const BYTE *sk);

#endif // ECC_ED25519_H
