/*
 * Copyright (c) 2021-2022, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#ifndef ECC_RISTRETTO255_H
#define ECC_RISTRETTO255_H

#include "export.h"

// const
/**
 * Size of the serialized group elements.
 */
#define ecc_ristretto255_ELEMENTSIZE 32

// const
/**
 * Size of the hash input to use on the hash to map operation.
 */
#define ecc_ristretto255_HASHSIZE 64

// const
/**
 * Size of the scalar used in the curve operations.
 */
#define ecc_ristretto255_SCALARSIZE 32

// const
/**
 * Size of a non reduced scalar.
 */
#define ecc_ristretto255_NONREDUCEDSCALARSIZE 64

/**
 * Checks that p is a valid ristretto255-encoded element. This operation
 * only checks that p is in canonical form.
 *
 * @param p potential point to test, size:ecc_ristretto255_ELEMENTSIZE
 * @return 1 on success, and 0 if the checks didn't pass.
 */
ECC_EXPORT
int ecc_ristretto255_is_valid_point(const byte_t *p);

/**
 * Adds the element represented by p to the element q and stores
 * the resulting element into r.
 *
 * @param[out] r the result, size:ecc_ristretto255_ELEMENTSIZE
 * @param p input point operand, size:ecc_ristretto255_ELEMENTSIZE
 * @param q input point operand, size:ecc_ristretto255_ELEMENTSIZE
 * @return 0 on success, or -1 if p and/or q are not valid encoded elements
 */
ECC_EXPORT
int ecc_ristretto255_add(byte_t *r, const byte_t *p, const byte_t *q);

/**
 * Subtracts the element represented by p to the element q and stores
 * the resulting element into r.
 *
 * @param[out] r the result, size:ecc_ristretto255_ELEMENTSIZE
 * @param p input point operand, size:ecc_ristretto255_ELEMENTSIZE
 * @param q input point operand, size:ecc_ristretto255_ELEMENTSIZE
 * @return 0 on success, or -1 if p and/or q are not valid encoded elements
 */
ECC_EXPORT
int ecc_ristretto255_sub(byte_t *r, const byte_t *p, const byte_t *q);

/**
 *
 * @param[out] g size:ecc_ristretto255_ELEMENTSIZE
 */
ECC_EXPORT
void ecc_ristretto255_generator(byte_t *g);

/**
 * Maps a 64 bytes vector r (usually the output of a hash function) to
 * a group element, and stores its representation into p.
 *
 * @param[out] p group element, size:ecc_ristretto255_ELEMENTSIZE
 * @param r bytes vector hash, size:ecc_ristretto255_HASHSIZE
 */
ECC_EXPORT
void ecc_ristretto255_from_hash(byte_t *p, const byte_t *r);

/**
 * Fills p with the representation of a random group element.
 *
 * @param[out] p random group element, size:ecc_ristretto255_ELEMENTSIZE
 */
ECC_EXPORT
void ecc_ristretto255_random(byte_t *p);

/**
 * Fills r with a bytes representation of the scalar in
 * the ]0..L[ interval where L is the order of the
 * group (2^252 + 27742317777372353535851937790883648493).
 *
 * @param[out] r random scalar, size:ecc_ristretto255_SCALARSIZE
 */
ECC_EXPORT
void ecc_ristretto255_scalar_random(byte_t *r);

/**
 * Computes the multiplicative inverse of s over L, and puts it into recip.
 *
 * @param[out] recip the result, size:ecc_ristretto255_SCALARSIZE
 * @param s an scalar, size:ecc_ristretto255_SCALARSIZE
 * @return 0 on success, or -1 if s is zero
 */
ECC_EXPORT
int ecc_ristretto255_scalar_invert(byte_t *recip, const byte_t *s);

/**
 * Returns neg so that s + neg = 0 (mod L).
 *
 * @param[out] neg the result, size:ecc_ristretto255_SCALARSIZE
 * @param s an scalar, size:ecc_ristretto255_SCALARSIZE
 */
ECC_EXPORT
void ecc_ristretto255_scalar_negate(byte_t *neg, const byte_t *s);

/**
 * Returns comp so that s + comp = 1 (mod L).
 *
 * @param[out] comp the result, size:ecc_ristretto255_SCALARSIZE
 * @param s an scalar, size:ecc_ristretto255_SCALARSIZE
 */
ECC_EXPORT
void ecc_ristretto255_scalar_complement(byte_t *comp, const byte_t *s);

/**
 * Stores x + y (mod L) into z.
 *
 * @param[out] z the result, size:ecc_ristretto255_SCALARSIZE
 * @param x input scalar operand, size:ecc_ristretto255_SCALARSIZE
 * @param y input scalar operand, size:ecc_ristretto255_SCALARSIZE
 */
ECC_EXPORT
void ecc_ristretto255_scalar_add(byte_t *z, const byte_t *x, const byte_t *y);

/**
 * Stores x - y (mod L) into z.
 *
 * @param[out] z the result, size:ecc_ristretto255_SCALARSIZE
 * @param x input scalar operand, size:ecc_ristretto255_SCALARSIZE
 * @param y input scalar operand, size:ecc_ristretto255_SCALARSIZE
 */
ECC_EXPORT
void ecc_ristretto255_scalar_sub(byte_t *z, const byte_t *x, const byte_t *y);

/**
 * Stores x * y (mod L) into z.
 *
 * @param[out] z the result, size:ecc_ristretto255_SCALARSIZE
 * @param x input scalar operand, size:ecc_ristretto255_SCALARSIZE
 * @param y input scalar operand, size:ecc_ristretto255_SCALARSIZE
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
 * @param[out] r the reduced scalar, size:ecc_ristretto255_SCALARSIZE
 * @param s the integer to reduce, size:ecc_ristretto255_NONREDUCEDSCALARSIZE
 */
ECC_EXPORT
void ecc_ristretto255_scalar_reduce(byte_t *r, const byte_t *s);

/**
 * Multiplies an element represented by p by a valid scalar n
 * and puts the resulting element into q.
 *
 * @param[out] q the result, size:ecc_ristretto255_ELEMENTSIZE
 * @param n the valid input scalar, size:ecc_ristretto255_SCALARSIZE
 * @param p the point on the curve, size:ecc_ristretto255_ELEMENTSIZE
 * @return 0 on success, or -1 if q is the identity element.
 */
ECC_EXPORT
int ecc_ristretto255_scalarmult(byte_t *q, const byte_t *n, const byte_t *p);

/**
 * Multiplies the generator by a valid scalar n and puts the resulting
 * element into q.
 *
 * @param[out] q the result, size:ecc_ristretto255_ELEMENTSIZE
 * @param n the valid input scalar, size:ecc_ristretto255_SCALARSIZE
 * @return -1 if n is 0, and 0 otherwise.
 */
ECC_EXPORT
int ecc_ristretto255_scalarmult_base(byte_t *q, const byte_t *n);

#endif // ECC_RISTRETTO255_H
