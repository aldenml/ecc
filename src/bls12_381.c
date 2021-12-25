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
static_assert(sizeof(blst_fp) == ecc_bls12_381_FPSIZE, "");
static_assert(sizeof(blst_fp12) == ecc_bls12_381_FP12SIZE, "");

void ecc_bls12_381_fp_random(byte_t *ret) {
    byte_t a[ecc_bls12_381_FPSIZE];
    ecc_randombytes(a, sizeof a);
    blst_fp_from_lendian((blst_fp *) ret, a);
    ecc_memzero(a, sizeof a);
}

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

void ecc_bls12_381_fp12_pow(byte_t *ret, const byte_t *a, int n) {
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

    ecc_memzero((byte_t *) &x, sizeof x);
    ecc_memzero((byte_t *) &y, sizeof y);
}

void ecc_bls12_381_fp12_random(byte_t *ret) {
    blst_fp12 a;
    ecc_bls12_381_fp_random((byte_t *) &a.fp6[0].fp2[0].fp[0]);
    ecc_bls12_381_fp_random((byte_t *) &a.fp6[0].fp2[0].fp[1]);
    ecc_bls12_381_fp_random((byte_t *) &a.fp6[0].fp2[1].fp[0]);
    ecc_bls12_381_fp_random((byte_t *) &a.fp6[0].fp2[1].fp[1]);
    ecc_bls12_381_fp_random((byte_t *) &a.fp6[0].fp2[2].fp[0]);
    ecc_bls12_381_fp_random((byte_t *) &a.fp6[0].fp2[2].fp[1]);
    ecc_bls12_381_fp_random((byte_t *) &a.fp6[1].fp2[0].fp[0]);
    ecc_bls12_381_fp_random((byte_t *) &a.fp6[1].fp2[0].fp[1]);
    ecc_bls12_381_fp_random((byte_t *) &a.fp6[1].fp2[1].fp[0]);
    ecc_bls12_381_fp_random((byte_t *) &a.fp6[1].fp2[1].fp[1]);
    ecc_bls12_381_fp_random((byte_t *) &a.fp6[1].fp2[2].fp[0]);
    ecc_bls12_381_fp_random((byte_t *) &a.fp6[1].fp2[2].fp[1]);
    // force Fp12 arithmetic
    blst_fp12_inverse((blst_fp12 *) ret, &a);
    ecc_memzero((byte_t *) &a, sizeof a);
}

void ecc_bls12_381_g1_add(byte_t *r, const byte_t *p, const byte_t *q) {
    blst_p1_affine p1_affine;
    blst_p1_deserialize(&p1_affine, p);

    blst_p1 p1;
    blst_p1_from_affine(&p1, &p1_affine);

    blst_p1_affine q1_affine;
    blst_p1_deserialize(&q1_affine, q);

    blst_p1 q1;
    blst_p1_from_affine(&q1, &q1_affine);

    blst_p1 out;
    blst_p1_add(&out, &p1, &q1);
    blst_p1_serialize(r, &out);

    ecc_memzero((byte_t *) &p1_affine, sizeof p1_affine);
    ecc_memzero((byte_t *) &p1, sizeof p1);
    ecc_memzero((byte_t *) &q1_affine, sizeof q1_affine);
    ecc_memzero((byte_t *) &q1, sizeof q1);
    ecc_memzero((byte_t *) &out, sizeof out);
}

void ecc_bls12_381_g1_negate(byte_t *neg, byte_t *p) {
    blst_p1_affine p1_affine;
    blst_p1_deserialize(&p1_affine, p);

    blst_p1 p1;
    blst_p1_from_affine(&p1, &p1_affine);

    blst_p1_cneg(&p1, 1);
    blst_p1_serialize(neg, &p1);

    ecc_memzero((byte_t *) &p1_affine, sizeof p1_affine);
    ecc_memzero((byte_t *) &p1, sizeof p1);
}

void ecc_bls12_381_g1_generator(byte_t *g) {
    memcpy(g, blst_p1_generator(), ecc_bls12_381_G1SIZE);
}

void ecc_bls12_381_g1_scalarmult(byte_t *q, const byte_t *n, const byte_t *p) {
    blst_p1_affine p1_affine;
    blst_p1_deserialize(&p1_affine, p);

    blst_p1 p1;
    blst_p1_from_affine(&p1, &p1_affine);

    blst_p1 out;
    blst_p1_mult(&out, &p1, n, ecc_bls12_381_SCALARSIZE * 8);
    blst_p1_serialize(q, &out);

    ecc_memzero((byte_t *) &p1_affine, sizeof p1_affine);
    ecc_memzero((byte_t *) &p1, sizeof p1);
    ecc_memzero((byte_t *) &out, sizeof out);
}

void ecc_bls12_381_g1_scalarmult_base(byte_t *q, const byte_t *n) {
    blst_p1 out;
    blst_p1_mult(&out, blst_p1_generator(), n, ecc_bls12_381_SCALARSIZE * 8);
    blst_p1_serialize(q, &out);
    ecc_memzero((byte_t *) &out, sizeof out);
}

void ecc_bls12_381_g2_add(byte_t *r, const byte_t *p, const byte_t *q) {
    blst_p2_affine p2_affine;
    blst_p2_deserialize(&p2_affine, p);

    blst_p2 p2;
    blst_p2_from_affine(&p2, &p2_affine);

    blst_p2_affine q2_affine;
    blst_p2_deserialize(&q2_affine, q);

    blst_p2 q2;
    blst_p2_from_affine(&q2, &q2_affine);

    blst_p2 out;
    blst_p2_add(&out, &p2, &q2);
    blst_p2_serialize(r, &out);

    ecc_memzero((byte_t *) &p2_affine, sizeof p2_affine);
    ecc_memzero((byte_t *) &p2, sizeof p2);
    ecc_memzero((byte_t *) &q2_affine, sizeof q2_affine);
    ecc_memzero((byte_t *) &q2, sizeof q2);
    ecc_memzero((byte_t *) &out, sizeof out);
}

void ecc_bls12_381_g2_negate(byte_t *neg, byte_t *p) {
    blst_p2_affine p2_affine;
    blst_p2_deserialize(&p2_affine, p);

    blst_p2 p2;
    blst_p2_from_affine(&p2, &p2_affine);

    blst_p2_cneg(&p2, 1);
    blst_p2_serialize(neg, &p2);

    ecc_memzero((byte_t *) &p2_affine, sizeof p2_affine);
    ecc_memzero((byte_t *) &p2, sizeof p2);
}

void ecc_bls12_381_g2_generator(byte_t *g) {
    blst_p2_serialize(g, blst_p2_generator());
}

void ecc_bls12_381_g2_scalarmult_base(byte_t *q, const byte_t *n) {
    blst_p2 out;
    blst_p2_mult(&out, blst_p2_generator(), n, ecc_bls12_381_SCALARSIZE * 8);
    blst_p2_serialize(q, &out);
    ecc_memzero((byte_t *) &out, sizeof out);
}

void ecc_bls12_381_scalar_random(byte_t *r) {
    byte_t s[ecc_bls12_381_SCALARSIZE];
    ecc_randombytes(s, sizeof s);
    blst_scalar_from_le_bytes((blst_scalar *) r, s, sizeof s);
    ecc_memzero(s, sizeof s);
}

void ecc_bls12_381_pairing(byte_t *ret, const byte_t *p1_g1, const byte_t *p2_g2) {
    blst_p1_affine p1;
    blst_p1_deserialize(&p1, p1_g1);

    blst_p2_affine p2;
    blst_p2_deserialize(&p2, p2_g2);

    blst_fp12 miller_ret;
    blst_miller_loop(&miller_ret, &p2, &p1);

    blst_final_exp((blst_fp12 *) ret, &miller_ret);

    ecc_memzero((byte_t *) &p1, sizeof p1);
    ecc_memzero((byte_t *) &p2, sizeof p2);
    ecc_memzero((byte_t *) &miller_ret, sizeof miller_ret);
}

void ecc_bls12_381_pairing_miller_loop(byte_t *ret, const byte_t *p1_g1, const byte_t *p2_g2) {
    blst_p1_affine p1;
    blst_p1_deserialize(&p1, p1_g1);

    blst_p2_affine p2;
    blst_p2_deserialize(&p2, p2_g2);

    blst_miller_loop((blst_fp12 *) ret, &p2, &p1);

    ecc_memzero((byte_t *) &p1, sizeof p1);
    ecc_memzero((byte_t *) &p2, sizeof p2);
}

void ecc_bls12_381_pairing_final_exp(byte_t *ret, const byte_t *a) {
    blst_final_exp((blst_fp12 *) ret, (blst_fp12 *) a);
}

int ecc_bls12_381_pairing_final_verify(const byte_t *a, const byte_t *b) {
    return blst_fp12_finalverify((blst_fp12 *) a, (blst_fp12 *) b);
}
