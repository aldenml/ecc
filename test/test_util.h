/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#ifndef ECC_TEST_UTIL_H
#define ECC_TEST_UTIL_H

#include "ecc.h"

static void logd(const char *label, const byte_t *data, const int data_len) {
    char hex[512] = {0};
    ecc_bin2hex(hex, data, data_len);
    printf("%s: %s\n", label, hex);
}

/**
 * This is a naive implementation of an iterative exponentiation by squaring.
 *
 * @param ret (output) the result
 * @param a the base
 * @param n the exponent
 */
static void ecc_bls12_381_fp12_pow(byte_t *ret, const byte_t *a, int n) {
    if (n == 0) {
        ecc_bls12_381_fp12_one(ret);
        return;
    }

    byte_t x[ecc_bls12_381_FP12SIZE];
    if (n < 0) {
        ecc_bls12_381_fp12_inverse(x, a);
        n = -n;
    } else {
        memcpy(x, a, ecc_bls12_381_FP12SIZE);
    }

    byte_t y[ecc_bls12_381_FP12SIZE];
    ecc_bls12_381_fp12_one(y);
    while (n > 1) {
        if (n % 2 == 0) {
            ecc_bls12_381_fp12_sqr(x, x);
            n = n / 2;
        } else {
            ecc_bls12_381_fp12_mul(y, x, y);
            ecc_bls12_381_fp12_sqr(x, x);
            n = (n - 1) / 2;
        }
    }

    ecc_bls12_381_fp12_mul(ret, x, y);
}

/**
 * Computes a random element of BLS12-381 Fp12.
 *
 * @param r the result
 */
static void ecc_bls12_381_fp12_random(byte_t *r) {
    // NOTE: this method use a pairing operation that looks
    // like a very costly proposition, but I don't have any
    // other way without opening up non-api private functions
    // inside blst.

    byte_t a[ecc_bls12_381_SCALARSIZE];
    byte_t b[ecc_bls12_381_SCALARSIZE];

    ecc_bls12_381_scalar_random(a);
    ecc_bls12_381_scalar_random(b);

    byte_t aP[ecc_bls12_381_G1SIZE];
    byte_t bQ[ecc_bls12_381_G2SIZE];

    ecc_bls12_381_g1_scalarmult_base(aP, a);
    ecc_bls12_381_g2_scalarmult_base(bQ, b);

    ecc_bls12_381_pairing(r, aP, bQ);
}

#endif // ECC_TEST_UTIL_H
