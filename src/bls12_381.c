/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#include "bls12_381.h"
#include <assert.h>
#include <string.h>
#include <blst.h>
#include "util.h"

static_assert(sizeof(blst_scalar) == ecc_bls12_381_SCALARSIZE, "");
static_assert(sizeof(blst_fp12) == ecc_bls12_381_FP12SIZE, "");

void ecc_bls12_381_fp12_one(byte_t *ret) {
    memcpy(ret, blst_fp12_one(), ecc_bls12_381_FP12SIZE);
}

int ecc_bls12_381_fp12_is_one(const byte_t *a) {
    return blst_fp12_is_one((blst_fp12 *) a);
}

void ecc_bls12_381_fp12_inverse(byte_t *ret, const byte_t *a) {
    blst_fp12_inverse((blst_fp12 *) ret, (blst_fp12 *) a);
}

void ecc_bls12_381_fp12_sqr(byte_t *ret, const byte_t *a) {
    blst_fp12_sqr((blst_fp12 *) ret, (blst_fp12 *) a);
}

void ecc_bls12_381_fp12_mul(byte_t *ret, const byte_t *a, const byte_t *b) {
    blst_fp12_mul((blst_fp12 *) ret, (blst_fp12 *) a, (blst_fp12 *) b);
}

void ecc_bls12_381_g1_scalarmult_base(byte_t *q, const byte_t *n) {
    blst_p1 out;
    blst_p1_mult(&out, blst_p1_generator(), n, ecc_bls12_381_SCALARSIZE * 8);
    blst_p1_serialize(q, &out);
}

void ecc_bls12_381_g2_scalarmult_base(byte_t *q, const byte_t *n) {
    blst_p2 out;
    blst_p2_mult(&out, blst_p2_generator(), n, ecc_bls12_381_SCALARSIZE * 8);
    blst_p2_serialize(q, &out);
}

void ecc_bls12_381_scalar_random(byte_t *r) {
    byte_t s[ecc_bls12_381_SCALARSIZE];
    ecc_randombytes(s, sizeof s);
    blst_scalar_from_le_bytes((blst_scalar *) r, s, sizeof s);
}

void ecc_bls12_381_pairing(byte_t *ret, const byte_t *p1_g1, const byte_t *p2_g2) {

    blst_p1_affine p1;
    blst_p1_deserialize(&p1, p1_g1);

    blst_p2_affine p2;
    blst_p2_deserialize(&p2, p2_g2);

    blst_fp12 miller_ret;
    blst_miller_loop(&miller_ret, &p2, &p1);

    blst_final_exp((blst_fp12 *) ret, &miller_ret);
}

int ecc_bls12_381_pairing_miller_loop(byte_t *ret, const byte_t *p1_g1, const byte_t *p2_g2) {

    blst_p1_affine p1;
    if (blst_p1_deserialize(&p1, p1_g1))
        return -1;

    blst_p2_affine p2;
    if (blst_p2_deserialize(&p2, p2_g2))
        return -1;

    blst_miller_loop((blst_fp12 *) ret, &p2, &p1);

    return 0;
}

void ecc_bls12_381_pairing_final_exp(byte_t *ret, const byte_t *a) {
    blst_final_exp((blst_fp12 *) ret, (blst_fp12 *) a);
}

int ecc_bls12_381_pairing_final_verify(const byte_t *a, const byte_t *b) {
    return blst_fp12_finalverify((blst_fp12 *) a, (blst_fp12 *) b);
}

void ecc_bls12_381_sign_keygen(byte_t *sk, const byte_t *ikm, int ikm_len) {
    blst_keygen((blst_scalar *) sk, ikm, ikm_len, 0, 0);
}
