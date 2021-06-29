/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#ifndef ECC_RISTRETTO255_H
#define ECC_RISTRETTO255_H

#include "export.h"

#define ecc_ristretto255_SIZE 32
#define ecc_ristretto255_HASHSIZE 64
#define ecc_ristretto255_SCALARSIZE 32
#define ecc_ristretto255_NONREDUCEDSCALARSIZE 64

ECC_EXPORT
int ecc_ristretto255_is_valid_point(const BYTE *p);

ECC_EXPORT
int ecc_ristretto255_add(BYTE *r, const BYTE *p, const BYTE *q);

ECC_EXPORT
int ecc_ristretto255_sub(BYTE *r, const BYTE *p, const BYTE *q);

ECC_OPRF_EXPORT
ECC_EXPORT
int ecc_ristretto255_from_hash(byte_t *p, const byte_t *r);

ECC_EXPORT
void ecc_ristretto255_random(BYTE *p);

ECC_OPRF_EXPORT
ECC_EXPORT
void ecc_ristretto255_scalar_random(byte_t *r);

ECC_OPRF_EXPORT
ECC_EXPORT
int ecc_ristretto255_scalar_invert(BYTE *recip, const BYTE *s);

ECC_EXPORT
void ecc_ristretto255_scalar_negate(BYTE *neg, const BYTE *s);

ECC_EXPORT
void ecc_ristretto255_scalar_complement(BYTE *comp, const BYTE *s);

ECC_EXPORT
void ecc_ristretto255_scalar_add(BYTE *z, const BYTE *x, const BYTE *y);

ECC_EXPORT
void ecc_ristretto255_scalar_sub(BYTE *z, const BYTE *x, const BYTE *y);

ECC_EXPORT
void ecc_ristretto255_scalar_mul(BYTE *z, const BYTE *x, const BYTE *y);

/*
 * The interval `s` is sampled from should be at least 317 bits to
 * ensure almost uniformity of `r` over `L`.
 */
ECC_EXPORT
void ecc_ristretto255_scalar_reduce(BYTE *r, const BYTE *s);

ECC_OPRF_EXPORT
ECC_EXPORT
int ecc_ristretto255_scalarmult(byte_t *q, const byte_t *n, const byte_t *p);

ECC_EXPORT
int ecc_ristretto255_scalarmult_base(byte_t *q, const byte_t *n);

#endif // ECC_RISTRETTO255_H
