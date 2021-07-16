/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#ifndef ECC_BLS12_381_H
#define ECC_BLS12_381_H

#include "export.h"

/**
 * Size of a an element in G1.
 */
#define ecc_bls12_381_G1SIZE 96

/**
 * Size of an element in G2.
 */
#define ecc_bls12_381_G2SIZE 192

/**
 * Size of the scalar used in the curve operations.
 */
#define ecc_bls12_381_SCALARSIZE 32

/**
 * Size of an element in Fp12.
 */
#define ecc_bls12_381_FP12SIZE 576

// Fp12 operations

ECC_EXPORT
void ecc_bls12_381_fp12_one(byte_t *ret);

ECC_EXPORT
int ecc_bls12_381_fp12_is_one(const byte_t *a);

ECC_EXPORT
void ecc_bls12_381_fp12_inverse(byte_t *ret, const byte_t *a);

ECC_EXPORT
void ecc_bls12_381_fp12_sqr(byte_t *ret, const byte_t *a);

ECC_EXPORT
void ecc_bls12_381_fp12_mul(byte_t *ret, const byte_t *a, const byte_t *b);

// G1 operations

/**
 * Multiplies the generator by a valid scalar n and puts the resulting
 * element into q.
 *
 * @param q (output) the result
 * @param n the valid input scalar
 */
ECC_EXPORT
void ecc_bls12_381_g1_scalarmult_base(byte_t *q, const byte_t *n);

// G2 operations

/**
 * Multiplies the generator by a valid scalar n and puts the resulting
 * element into q.
 *
 * @param q (output) the result
 * @param n the valid input scalar
 */
ECC_EXPORT
void ecc_bls12_381_g2_scalarmult_base(byte_t *q, const byte_t *n);

// general

/**
 * Fills r with a bytes representation of an scalar.
 *
 * @param r (output) random scalar
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
 * @param ret (output) the result of the pairing evaluation in GT
 * @param p1_g1 point in G1
 * @param p2_g2 point in G2
 */
ECC_EXPORT
void ecc_bls12_381_pairing(byte_t *ret, const byte_t *p1_g1, const byte_t *p2_g2);

ECC_EXPORT
int ecc_bls12_381_pairing_miller_loop(byte_t *ret, const byte_t *p1_g1, const byte_t *p2_g2);

ECC_EXPORT
void ecc_bls12_381_pairing_final_exp(byte_t *ret, const byte_t *a);

/**
 * Perform the verification of a pairing match. Useful if the
 * inputs are raw output values from the miller loop.
 *
 * @param a the first argument to verify
 * @param b the second argument to verify
 * @return 1 if it's a pairing match, else 0
 */
ECC_EXPORT
int ecc_bls12_381_pairing_final_verify(const byte_t *a, const byte_t *b);

/**
 *
 * @param out_SK
 * @param IKM
 * @param IKM_len
 */
ECC_EXPORT
void ecc_bls12_381_sign_keygen(byte_t *sk, const byte_t *ikm, int ikm_len);

#endif // ECC_BLS12_381_H
