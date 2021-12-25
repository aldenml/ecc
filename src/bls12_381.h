/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#ifndef ECC_BLS12_381_H
#define ECC_BLS12_381_H

#include "export.h"

// const
/**
 * Size of a an element in G1.
 */
#define ecc_bls12_381_G1SIZE 96

// const
/**
 * Size of an element in G2.
 */
#define ecc_bls12_381_G2SIZE 192

// const
/**
 * Size of the scalar used in the curve operations.
 */
#define ecc_bls12_381_SCALARSIZE 32

// const
/**
 * Size of an element in Fp.
 */
#define ecc_bls12_381_FPSIZE 48

// const
/**
 * Size of an element in Fp12.
 */
#define ecc_bls12_381_FP12SIZE 576

// Fp operations

/**
 * Computes a random element of BLS12-381 Fp.
 *
 * @param[out] ret the result, size:ecc_bls12_381_FPSIZE
 */
ECC_EXPORT
void ecc_bls12_381_fp_random(byte_t *ret);

// Fp12 operations

/**
 * Get the identity element of BLS12-381 Fp12.
 *
 * @param[out] ret the result, size:ecc_bls12_381_FP12SIZE
 */
ECC_EXPORT
void ecc_bls12_381_fp12_one(byte_t *ret);

/**
 * Determine if an element is the identity in BLS12-381 Fp12.
 *
 * @param a the input, size:ecc_bls12_381_FP12SIZE
 * @return 0 if the element a is the identity in BLS12-381 Fp12.
 */
ECC_EXPORT
int ecc_bls12_381_fp12_is_one(const byte_t *a);

/**
 * Computes the inverse of an element in BLS12-381 Fp12.
 *
 * @param[out] ret the result, size:ecc_bls12_381_FP12SIZE
 * @param a the input, size:ecc_bls12_381_FP12SIZE
 */
ECC_EXPORT
void ecc_bls12_381_fp12_inverse(byte_t *ret, const byte_t *a);

/**
 * Computes the square of an element in BLS12-381 Fp12.
 *
 * @param[out] ret the result, size:ecc_bls12_381_FP12SIZE
 * @param a the input, size:ecc_bls12_381_FP12SIZE
 */
ECC_EXPORT
void ecc_bls12_381_fp12_sqr(byte_t *ret, const byte_t *a);

/**
 * Perform a * b in Fp12.
 *
 * @param[out] ret the result, size:ecc_bls12_381_FP12SIZE
 * @param a input group element, size:ecc_bls12_381_FP12SIZE
 * @param b input group element, size:ecc_bls12_381_FP12SIZE
 */
ECC_EXPORT
void ecc_bls12_381_fp12_mul(byte_t *ret, const byte_t *a, const byte_t *b);

/**
 * This is a naive implementation of an iterative exponentiation by squaring.
 *
 * NOTE: This method is not side-channel attack resistant on `n`, the algorithm
 * leaks information about it, don't use this if `n` is a secret.
 *
 * @param[out] ret the result, size:ecc_bls12_381_FP12SIZE
 * @param a the base, size:ecc_bls12_381_FP12SIZE
 * @param n the exponent
 */
ECC_EXPORT
void ecc_bls12_381_fp12_pow(byte_t *ret, const byte_t *a, int n);

/**
 * Computes a random element of BLS12-381 Fp12.
 *
 * @param[out] ret the result, size:ecc_bls12_381_FP12SIZE
 */
ECC_EXPORT
void ecc_bls12_381_fp12_random(byte_t *ret);

// G1 operations

/**
 *
 * @param[out] r size:ecc_bls12_381_G1SIZE
 * @param p size:ecc_bls12_381_G1SIZE
 * @param q size:ecc_bls12_381_G1SIZE
 */
ECC_EXPORT
void ecc_bls12_381_g1_add(byte_t *r, const byte_t *p, const byte_t *q);

/**
 *
 * @param[out] neg size:ecc_bls12_381_G1SIZE
 * @param p size:ecc_bls12_381_G1SIZE
 */
ECC_EXPORT
void ecc_bls12_381_g1_negate(byte_t *neg, byte_t *p);

/**
 *
 * @param[out] g size:ecc_bls12_381_G1SIZE
 */
ECC_EXPORT
void ecc_bls12_381_g1_generator(byte_t *g);

/**
 * Multiplies an element represented by p by a valid scalar n
 * and puts the resulting element into q.
 *
 * @param[out] q the result, size:ecc_bls12_381_G1SIZE
 * @param n the valid input scalar, size:ecc_bls12_381_SCALARSIZE
 * @param p the point on the curve, size:ecc_bls12_381_G1SIZE
 */
ECC_EXPORT
void ecc_bls12_381_g1_scalarmult(byte_t *q, const byte_t *n, const byte_t *p);

/**
 * Multiplies the generator by a valid scalar n and puts the resulting
 * element into q.
 *
 * @param[out] q the result, size:ecc_bls12_381_G1SIZE
 * @param n the valid input scalar, size:ecc_bls12_381_SCALARSIZE
 */
ECC_EXPORT
void ecc_bls12_381_g1_scalarmult_base(byte_t *q, const byte_t *n);

// G2 operations

/**
 *
 * @param[out] r size:ecc_bls12_381_G2SIZE
 * @param p size:ecc_bls12_381_G2SIZE
 * @param q size:ecc_bls12_381_G2SIZE
 */
ECC_EXPORT
void ecc_bls12_381_g2_add(byte_t *r, const byte_t *p, const byte_t *q);

/**
 *
 * @param[out] neg size:ecc_bls12_381_G2SIZE
 * @param p size:ecc_bls12_381_G2SIZE
 */
ECC_EXPORT
void ecc_bls12_381_g2_negate(byte_t *neg, byte_t *p);

/**
 *
 * @param[out] g size:ecc_bls12_381_G2SIZE
 */
ECC_EXPORT
void ecc_bls12_381_g2_generator(byte_t *g);

/**
 * Multiplies the generator by a valid scalar n and puts the resulting
 * element into q.
 *
 * @param[out] q the result, size:ecc_bls12_381_G2SIZE
 * @param n the valid input scalar, size:ecc_bls12_381_SCALARSIZE
 */
ECC_EXPORT
void ecc_bls12_381_g2_scalarmult_base(byte_t *q, const byte_t *n);

// general

/**
 * Fills r with a bytes representation of an scalar.
 *
 * @param[out] r random scalar, size:ecc_bls12_381_SCALARSIZE
 */
ECC_EXPORT
void ecc_bls12_381_scalar_random(byte_t *r);

/**
 * Evaluates a pairing of BLS12-381.
 *
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-pairing-friendly-curves-09#section-2.2
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-pairing-friendly-curves-09#section-2.4
 *
 * G1 is a subgroup of E(GF(p)) of order r.
 * G2 is a subgroup of E'(GF(p^2)) of order r.
 * GT is a subgroup of a multiplicative group (GF(p^12))^* of order r.
 *
 * @param[out] ret the result of the pairing evaluation in GT, size:ecc_bls12_381_FP12SIZE
 * @param p1_g1 point in G1, size:ecc_bls12_381_G1SIZE
 * @param p2_g2 point in G2, size:ecc_bls12_381_G2SIZE
 */
ECC_EXPORT
void ecc_bls12_381_pairing(byte_t *ret, const byte_t *p1_g1, const byte_t *p2_g2);

/**
 *
 * @param[out] ret size:ecc_bls12_381_FP12SIZE
 * @param p1_g1 size:ecc_bls12_381_G1SIZE
 * @param p2_g2 size:ecc_bls12_381_G2SIZE
 */
ECC_EXPORT
void ecc_bls12_381_pairing_miller_loop(byte_t *ret, const byte_t *p1_g1, const byte_t *p2_g2);

/**
 *
 * @param[out] ret size:ecc_bls12_381_FP12SIZE
 * @param a size:ecc_bls12_381_FP12SIZE
 */
ECC_EXPORT
void ecc_bls12_381_pairing_final_exp(byte_t *ret, const byte_t *a);

/**
 * Perform the verification of a pairing match. Useful if the
 * inputs are raw output values from the miller loop.
 *
 * @param a the first argument to verify, size:ecc_bls12_381_FP12SIZE
 * @param b the second argument to verify, size:ecc_bls12_381_FP12SIZE
 * @return 1 if it's a pairing match, else 0
 */
ECC_EXPORT
int ecc_bls12_381_pairing_final_verify(const byte_t *a, const byte_t *b);

#endif // ECC_BLS12_381_H
