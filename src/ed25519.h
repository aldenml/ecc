/*
 * Copyright (c) 2021-2022, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#ifndef ECC_ED25519_H
#define ECC_ED25519_H

#include "export.h"

// const
/**
 * Size of the serialized group elements.
 */
#define ecc_ed25519_ELEMENTSIZE 32

// const
/**
 * Size of the input to perform the Elligator 2 map operation.
 */
#define ecc_ed25519_UNIFORMSIZE 32

// const
/**
 * Size of the scalar used in the curve operations.
 */
#define ecc_ed25519_SCALARSIZE 32

// const
/**
 * Size of a non reduced scalar.
 */
#define ecc_ed25519_NONREDUCEDSCALARSIZE 64

/**
 * Checks that p represents a point on the edwards25519 curve, in canonical
 * form, on the main subgroup, and that the point doesn't have a small order.
 *
 * @param p potential point to test, size:ecc_ed25519_ELEMENTSIZE
 * @return 1 on success, and 0 if the checks didn't pass
 */
ECC_EXPORT
int ecc_ed25519_is_valid_point(const byte_t *p);

/**
 * Adds the point p to the point q and stores the resulting point into r.
 *
 * @param[out] r the result, size:ecc_ed25519_ELEMENTSIZE
 * @param p input point operand, size:ecc_ed25519_ELEMENTSIZE
 * @param q input point operand, size:ecc_ed25519_ELEMENTSIZE
 * @return 0 on success, or -1 if p and/or q are not valid points
 */
ECC_EXPORT
int ecc_ed25519_add(byte_t *r, const byte_t *p, const byte_t *q);

/**
 * Subtracts the point p to the point q and stores the resulting point into r.
 *
 * @param[out] r the result, size:ecc_ed25519_ELEMENTSIZE
 * @param p input point operand, size:ecc_ed25519_ELEMENTSIZE
 * @param q input point operand, size:ecc_ed25519_ELEMENTSIZE
 * @return 0 on success, or -1 if p and/or q are not valid points
 */
ECC_EXPORT
int ecc_ed25519_sub(byte_t *r, const byte_t *p, const byte_t *q);

/**
 * Main group base point (x, 4/5), generator of the prime group.
 *
 * @param[out] g size:ecc_ed25519_ELEMENTSIZE
 */
ECC_EXPORT
void ecc_ed25519_generator(byte_t *g);

/**
 * Maps a 32 bytes vector r to a point, and stores its compressed
 * representation into p. The point is guaranteed to be on the main
 * subgroup.
 *
 * This function directly exposes the Elligator 2 map. Uses the high
 * bit to set the sign of the X coordinate, and the resulting point is
 * multiplied by the cofactor.
 *
 * @param[out] p point in the main subgroup, size:ecc_ed25519_ELEMENTSIZE
 * @param r input vector, size:ecc_ed25519_UNIFORMSIZE
 */
ECC_EXPORT
void ecc_ed25519_from_uniform(byte_t *p, const byte_t *r);

/**
 * Fills p with the representation of a random group element.
 *
 * @param[out] p random group element, size:ecc_ed25519_ELEMENTSIZE
 */
ECC_EXPORT
void ecc_ed25519_random(byte_t *p);

/**
 * Chose a random scalar in the [0..L[ interval, L being the order of the
 * main subgroup (2^252 + 27742317777372353535851937790883648493) and fill
 * r with the bytes.
 *
 * @param[out] r scalar, size:ecc_ed25519_SCALARSIZE
 */
ECC_EXPORT
void ecc_ed25519_scalar_random(byte_t *r);

/**
 * Computes the multiplicative inverse of s over L, and puts it into recip.
 *
 * @param[out] recip the result, size:ecc_ed25519_SCALARSIZE
 * @param s an scalar, size:ecc_ed25519_SCALARSIZE
 * @return 0 on success, or -1 if s is zero
 */
ECC_EXPORT
int ecc_ed25519_scalar_invert(byte_t *recip, const byte_t *s);

/**
 * Returns neg so that s + neg = 0 (mod L).
 *
 * @param[out] neg the result, size:ecc_ed25519_SCALARSIZE
 * @param s an scalar, size:ecc_ed25519_SCALARSIZE
 */
ECC_EXPORT
void ecc_ed25519_scalar_negate(byte_t *neg, const byte_t *s);

/**
 * Returns comp so that s + comp = 1 (mod L).
 *
 * @param[out] comp the result, size:ecc_ed25519_SCALARSIZE
 * @param s an scalar, size:ecc_ed25519_SCALARSIZE
 */
ECC_EXPORT
void ecc_ed25519_scalar_complement(byte_t *comp, const byte_t *s);

/**
 * Stores x + y (mod L) into z.
 *
 * @param[out] z the result, size:ecc_ed25519_SCALARSIZE
 * @param x input scalar operand, size:ecc_ed25519_SCALARSIZE
 * @param y input scalar operand, size:ecc_ed25519_SCALARSIZE
 */
ECC_EXPORT
void ecc_ed25519_scalar_add(byte_t *z, const byte_t *x, const byte_t *y);

/**
 * Stores x - y (mod L) into z.
 *
 * @param[out] z the result, size:ecc_ed25519_SCALARSIZE
 * @param x input scalar operand, size:ecc_ed25519_SCALARSIZE
 * @param y input scalar operand, size:ecc_ed25519_SCALARSIZE
 */
ECC_EXPORT
void ecc_ed25519_scalar_sub(byte_t *z, const byte_t *x, const byte_t *y);

/**
 * Stores x * y (mod L) into z.
 *
 * @param[out] z the result, size:ecc_ed25519_SCALARSIZE
 * @param x input scalar operand, size:ecc_ed25519_SCALARSIZE
 * @param y input scalar operand, size:ecc_ed25519_SCALARSIZE
 */
ECC_EXPORT
void ecc_ed25519_scalar_mul(byte_t *z, const byte_t *x, const byte_t *y);

/**
 * Reduces s to s mod L and puts the bytes representing the integer
 * into r where L = (2^252 + 27742317777372353535851937790883648493) is
 * the order of the group.
 *
 * The interval `s` is sampled from should be at least 317 bits to
 * ensure almost uniformity of `r` over `L`.
 *
 * @param[out] r the reduced scalar, size:ecc_ed25519_SCALARSIZE
 * @param s the integer to reduce, size:ecc_ed25519_NONREDUCEDSCALARSIZE
 */
ECC_EXPORT
void ecc_ed25519_scalar_reduce(byte_t *r, const byte_t *s);

/**
 * Multiplies a point p by a valid scalar n (clamped) and puts
 * the Y coordinate of the resulting point into q.
 *
 * This function returns 0 on success, or -1 if n is 0 or if p is not
 * on the curve, not on the main subgroup, is a point of small order,
 * or is not provided in canonical form.
 *
 * Note that n is "clamped" (the 3 low bits are cleared to make it a
 * multiple of the cofactor, bit 254 is set and bit 255 is cleared to
 * respect the original design). This prevents attacks using small
 * subgroups. If you want to implement protocols that involve blinding
 * operations, use ristretto255.
 *
 * @param[out] q the result, size:ecc_ed25519_ELEMENTSIZE
 * @param n the valid input scalar, size:ecc_ed25519_SCALARSIZE
 * @param p the point on the curve, size:ecc_ed25519_ELEMENTSIZE
 * @return 0 on success, or -1 otherwise.
 */
ECC_EXPORT
int ecc_ed25519_scalarmult(byte_t *q, const byte_t *n, const byte_t *p);

/**
 * Multiplies the base point (x, 4/5) by a scalar n (clamped) and puts
 * the Y coordinate of the resulting point into q.
 *
 * Note that n is "clamped" (the 3 low bits are cleared to make it a
 * multiple of the cofactor, bit 254 is set and bit 255 is cleared to
 * respect the original design). This prevents attacks using small
 * subgroups. If you want to implement protocols that involve blinding
 * operations, use ristretto255.
 *
 * @param[out] q the result, size:ecc_ed25519_ELEMENTSIZE
 * @param n the valid input scalar, size:ecc_ed25519_SCALARSIZE
 * @return -1 if n is 0, and 0 otherwise.
 */
ECC_EXPORT
int ecc_ed25519_scalarmult_base(byte_t *q, const byte_t *n);

#endif // ECC_ED25519_H
