/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#ifndef ECC_RISTRETTO255_H
#define ECC_RISTRETTO255_H

#include "export.h"

/**
 * Size of the serialized group elements.
 */
#define ecc_ristretto255_SIZE 32

/**
 * Size of the hash input to use on the hash to map operation.
 */
#define ecc_ristretto255_HASHSIZE 64

/**
 * Size of the scalar used in the curve operations.
 */
#define ecc_ristretto255_SCALARSIZE 32

/**
 * Size of a non reduced scalar.
 */
#define ecc_ristretto255_NONREDUCEDSCALARSIZE 64

/**
 * Checks that p is a valid ristretto255-encoded element. This operation
 * only checks that p is in canonical form.
 *
 * @param p potential point to test
 * @return 1 on success, and 0 if the checks didn't pass.
 */
ECC_EXPORT
int ecc_ristretto255_is_valid_point(const byte_t *p);

/**
 * Adds the element represented by p to the element q and stores
 * the resulting element into r.
 *
 * @param r (output) the result
 * @param p input point operand
 * @param q input point operand
 * @return 0 on success, or -1 if p and/or q are not valid encoded elements
 */
ECC_EXPORT
int ecc_ristretto255_add(byte_t *r, const byte_t *p, const byte_t *q);

/**
 * Subtracts the element represented by p to the element q and stores
 * the resulting element into r.
 *
 * @param r (output) the result
 * @param p input point operand
 * @param q input point operand
 * @return 0 on success, or -1 if p and/or q are not valid encoded elements
 */
ECC_EXPORT
int ecc_ristretto255_sub(byte_t *r, const byte_t *p, const byte_t *q);

/**
 * Maps a 64 bytes vector r (usually the output of a hash function) to
 * a group element, and stores its representation into p.
 *
 * @param p (output) group element
 * @param r bytes vector hash
 */
ECC_EXPORT
void ecc_ristretto255_from_hash(byte_t *p, const byte_t *r);

/**
 * Fills p with the representation of a random group element.
 *
 * @param p (output) random group element
 */
ECC_EXPORT
void ecc_ristretto255_random(byte_t *p);

/**
 * Fills r with a bytes representation of the scalar in
 * the ]0..L[ interval where L is the order of the
 * group (2^252 + 27742317777372353535851937790883648493).
 *
 * @param r (output) random scalar
 */
ECC_EXPORT
void ecc_ristretto255_scalar_random(byte_t *r);

/**
 * Computes the multiplicative inverse of s over L, and puts it into recip.
 *
 * @param recip (output) the result
 * @param s an scalar
 * @return 0 on success, or -1 if s is zero
 */
ECC_EXPORT
int ecc_ristretto255_scalar_invert(byte_t *recip, const byte_t *s);

/**
 * Returns neg so that s + neg = 0 (mod L).
 *
 * @param neg (output) the result
 * @param s an scalar
 */
ECC_EXPORT
void ecc_ristretto255_scalar_negate(byte_t *neg, const byte_t *s);

/**
 * Returns comp so that s + comp = 1 (mod L).
 *
 * @param comp (output) the result
 * @param s an scalar
 */
ECC_EXPORT
void ecc_ristretto255_scalar_complement(byte_t *comp, const byte_t *s);

/**
 * Stores x + y (mod L) into z.
 *
 * @param z (output) the result
 * @param x input scalar operand
 * @param y input scalar operand
 */
ECC_EXPORT
void ecc_ristretto255_scalar_add(byte_t *z, const byte_t *x, const byte_t *y);

/**
 * Stores x - y (mod L) into z.
 *
 * @param z (output) the result
 * @param x input scalar operand
 * @param y input scalar operand
 */
ECC_EXPORT
void ecc_ristretto255_scalar_sub(byte_t *z, const byte_t *x, const byte_t *y);

/**
 * Stores x * y (mod L) into z.
 *
 * @param z (output) the result
 * @param x input scalar operand
 * @param y input scalar operand
 */
ECC_EXPORT
void ecc_ristretto255_scalar_mul(byte_t *z, const byte_t *x, const byte_t *y);

/**
 * Reduces s to s mod L and puts the bytes integer into r where
 * L = 2^252 + 27742317777372353535851937790883648493 is the order
 * of the group.
 *
 * The interval `s` is sampled from should be at least 317 bits to
 * ensure almost uniformity of `r` over `L`.
 *
 * @param r (output) the reduced scalar
 * @param s the integer to reduce
 */
ECC_EXPORT
void ecc_ristretto255_scalar_reduce(byte_t *r, const byte_t *s);

/**
 * Multiplies an element represented by p by a valid scalar n
 * and puts the resulting element into q.
 *
 * @param q (output) the result
 * @param n the valid input scalar
 * @param p the point on the curve
 * @return 0 on success, or -1 if q is the identity element.
 */
ECC_EXPORT
int ecc_ristretto255_scalarmult(byte_t *q, const byte_t *n, const byte_t *p);

/**
 * Multiplies the generator by a valid scalar n and puts the resulting
 * element into q.
 *
 * @param q (output) the result
 * @param n the valid input scalar
 * @return -1 if n is 0, and 0 otherwise.
 */
ECC_EXPORT
int ecc_ristretto255_scalarmult_base(byte_t *q, const byte_t *n);

#endif // ECC_RISTRETTO255_H
