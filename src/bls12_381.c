/*
 * Copyright (c) 2021-2023, Alden Torres
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

static void ecc_bls12_381_fp12_from_bytes(blst_fp12 *ret, const byte_t *a) {
    memcpy(ret, a, ecc_bls12_381_FP12SIZE);
}

static void ecc_bls12_381_fp12_to_bytes(byte_t *ret, const blst_fp12 *a) {
    memcpy(ret, a, ecc_bls12_381_FP12SIZE);
}

void ecc_bls12_381_fp_random(byte_t *ret) {
    byte_t a[ecc_bls12_381_FPSIZE];
    ecc_randombytes(a, sizeof a);

    blst_fp fp;
    blst_fp_from_bendian(&fp, a);
    blst_bendian_from_fp(ret, &fp);

    // cleanup stack memory
    ecc_memzero(a, sizeof a);
    ecc_memzero((byte *) &fp, sizeof fp);
}

void ecc_bls12_381_fp12_one(byte_t *ret) {
    ecc_bls12_381_fp12_to_bytes(ret, blst_fp12_one());
}

int ecc_bls12_381_fp12_is_one(const byte_t *a) {
    blst_fp12 x;
    ecc_bls12_381_fp12_from_bytes(&x, a);

    int ret = blst_fp12_is_one(&x);

    // cleanup stack memory
    ecc_memzero((byte *) &x, sizeof x);

    return ret;
}

void ecc_bls12_381_fp12_inverse(byte_t *ret, const byte_t *a) {
    blst_fp12 x;
    ecc_bls12_381_fp12_from_bytes(&x, a);

    blst_fp12 inv;
    blst_fp12_inverse(&inv, &x);

    ecc_bls12_381_fp12_to_bytes(ret, &inv);

    // cleanup stack memory
    ecc_memzero((byte *) &x, sizeof x);
    ecc_memzero((byte *) &inv, sizeof inv);
}

void ecc_bls12_381_fp12_sqr(byte_t *ret, const byte_t *a) {
    blst_fp12 x;
    ecc_bls12_381_fp12_from_bytes(&x, a);

    blst_fp12 sqr;
    blst_fp12_sqr(&sqr, &x);

    ecc_bls12_381_fp12_to_bytes(ret, &sqr);

    // cleanup stack memory
    ecc_memzero((byte *) &x, sizeof x);
    ecc_memzero((byte *) &sqr, sizeof sqr);
}

void ecc_bls12_381_fp12_mul(byte_t *ret, const byte_t *a, const byte_t *b) {
    blst_fp12 x1;
    ecc_bls12_381_fp12_from_bytes(&x1, a);
    blst_fp12 x2;
    ecc_bls12_381_fp12_from_bytes(&x2, b);

    blst_fp12 mul;
    blst_fp12_mul(&mul, &x1, &x2);

    ecc_bls12_381_fp12_to_bytes(ret, &mul);

    // cleanup stack memory
    ecc_memzero((byte *) &x1, sizeof x1);
    ecc_memzero((byte *) &x2, sizeof x2);
    ecc_memzero((byte *) &mul, sizeof mul);
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

    // cleanup stack memory
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
    blst_fp12 inv;
    blst_fp12_inverse(&inv, &a);

    ecc_bls12_381_fp12_to_bytes(ret, &inv);

    // cleanup stack memory
    ecc_memzero((byte_t *) &a, sizeof a);
    ecc_memzero((byte_t *) &inv, sizeof inv);
}

void ecc_bls12_381_g1_add(byte_t *r, const byte_t *p, const byte_t *q) {
    blst_p1_affine p1_affine;
    blst_p1_uncompress(&p1_affine, p);

    blst_p1 p1;
    blst_p1_from_affine(&p1, &p1_affine);

    blst_p1_affine q1_affine;
    blst_p1_uncompress(&q1_affine, q);

    blst_p1 q1;
    blst_p1_from_affine(&q1, &q1_affine);

    blst_p1 out;
    blst_p1_add(&out, &p1, &q1);
    blst_p1_compress(r, &out);

    // cleanup stack memory
    ecc_memzero((byte_t *) &p1_affine, sizeof p1_affine);
    ecc_memzero((byte_t *) &p1, sizeof p1);
    ecc_memzero((byte_t *) &q1_affine, sizeof q1_affine);
    ecc_memzero((byte_t *) &q1, sizeof q1);
    ecc_memzero((byte_t *) &out, sizeof out);
}

void ecc_bls12_381_g1_negate(byte_t *neg, const byte_t *p) {
    blst_p1_affine p1_affine;
    blst_p1_uncompress(&p1_affine, p);

    blst_p1 p1;
    blst_p1_from_affine(&p1, &p1_affine);

    blst_p1_cneg(&p1, 1);
    blst_p1_compress(neg, &p1);

    // cleanup stack memory
    ecc_memzero((byte_t *) &p1_affine, sizeof p1_affine);
    ecc_memzero((byte_t *) &p1, sizeof p1);
}

void ecc_bls12_381_g1_generator(byte_t *g) {
    blst_p1_compress(g, blst_p1_generator());
}

void ecc_bls12_381_g1_random(byte_t *p) {
    byte_t a[ecc_bls12_381_SCALARSIZE];
    ecc_bls12_381_scalar_random(a);
    ecc_bls12_381_g1_scalarmult_base(p, a);

    // cleanup stack memory
    ecc_memzero(a, sizeof a);
}

void ecc_bls12_381_g1_scalarmult(byte_t *q, const byte_t *n, const byte_t *p) {
    blst_p1_affine p1_affine;
    blst_p1_uncompress(&p1_affine, p);

    blst_p1 p1;
    blst_p1_from_affine(&p1, &p1_affine);

    blst_p1 out;
    blst_p1_mult(&out, &p1, n, ecc_bls12_381_SCALARSIZE * 8);
    blst_p1_compress(q, &out);

    // cleanup stack memory
    ecc_memzero((byte_t *) &p1_affine, sizeof p1_affine);
    ecc_memzero((byte_t *) &p1, sizeof p1);
    ecc_memzero((byte_t *) &out, sizeof out);
}

void ecc_bls12_381_g1_scalarmult_base(byte_t *q, const byte_t *n) {
    blst_p1 out;
    blst_p1_mult(&out, blst_p1_generator(), n, ecc_bls12_381_SCALARSIZE * 8);
    blst_p1_compress(q, &out);

    // cleanup stack memory
    ecc_memzero((byte_t *) &out, sizeof out);
}

void ecc_bls12_381_g2_add(byte_t *r, const byte_t *p, const byte_t *q) {
    blst_p2_affine p2_affine;
    blst_p2_uncompress(&p2_affine, p);

    blst_p2 p2;
    blst_p2_from_affine(&p2, &p2_affine);

    blst_p2_affine q2_affine;
    blst_p2_uncompress(&q2_affine, q);

    blst_p2 q2;
    blst_p2_from_affine(&q2, &q2_affine);

    blst_p2 out;
    blst_p2_add(&out, &p2, &q2);
    blst_p2_compress(r, &out);

    // cleanup stack memory
    ecc_memzero((byte_t *) &p2_affine, sizeof p2_affine);
    ecc_memzero((byte_t *) &p2, sizeof p2);
    ecc_memzero((byte_t *) &q2_affine, sizeof q2_affine);
    ecc_memzero((byte_t *) &q2, sizeof q2);
    ecc_memzero((byte_t *) &out, sizeof out);
}

void ecc_bls12_381_g2_negate(byte_t *neg, const byte_t *p) {
    blst_p2_affine p2_affine;
    blst_p2_uncompress(&p2_affine, p);

    blst_p2 p2;
    blst_p2_from_affine(&p2, &p2_affine);

    blst_p2_cneg(&p2, 1);
    blst_p2_compress(neg, &p2);

    // cleanup stack memory
    ecc_memzero((byte_t *) &p2_affine, sizeof p2_affine);
    ecc_memzero((byte_t *) &p2, sizeof p2);
}

void ecc_bls12_381_g2_generator(byte_t *g) {
    blst_p2_compress(g, blst_p2_generator());
}

void ecc_bls12_381_g2_random(byte_t *p) {
    byte_t a[ecc_bls12_381_SCALARSIZE];
    ecc_bls12_381_scalar_random(a);
    ecc_bls12_381_g2_scalarmult_base(p, a);

    // cleanup stack memory
    ecc_memzero(a, sizeof a);
}

void ecc_bls12_381_g2_scalarmult(byte_t *q, const byte_t *n, const byte_t *p) {
    blst_p2_affine p1_affine;
    blst_p2_uncompress(&p1_affine, p);

    blst_p2 p1;
    blst_p2_from_affine(&p1, &p1_affine);

    blst_p2 out;
    blst_p2_mult(&out, &p1, n, ecc_bls12_381_SCALARSIZE * 8);
    blst_p2_compress(q, &out);

    // cleanup stack memory
    ecc_memzero((byte_t *) &p1_affine, sizeof p1_affine);
    ecc_memzero((byte_t *) &p1, sizeof p1);
    ecc_memzero((byte_t *) &out, sizeof out);
}

void ecc_bls12_381_g2_scalarmult_base(byte_t *q, const byte_t *n) {
    blst_p2 out;
    blst_p2_mult(&out, blst_p2_generator(), n, ecc_bls12_381_SCALARSIZE * 8);
    blst_p2_compress(q, &out);

    // cleanup stack memory
    ecc_memzero((byte_t *) &out, sizeof out);
}

void ecc_bls12_381_scalar_random(byte_t *r) {
    byte_t s[ecc_bls12_381_SCALARSIZE];
    ecc_randombytes(s, sizeof s);
    blst_scalar_from_bendian((blst_scalar *) r, s);

    // cleanup stack memory
    ecc_memzero(s, sizeof s);
}

void ecc_bls12_381_pairing(byte_t *ret, const byte_t *p1_g1, const byte_t *p2_g2) {
    blst_p1_affine p1;
    blst_p1_uncompress(&p1, p1_g1);

    blst_p2_affine p2;
    blst_p2_uncompress(&p2, p2_g2);

    blst_fp12 miller_ret;
    blst_miller_loop(&miller_ret, &p2, &p1);

    blst_fp12 exp_ret;
    blst_final_exp(&exp_ret, &miller_ret);
    ecc_bls12_381_fp12_to_bytes(ret, &exp_ret);

    // cleanup stack memory
    ecc_memzero((byte_t *) &p1, sizeof p1);
    ecc_memzero((byte_t *) &p2, sizeof p2);
    ecc_memzero((byte_t *) &miller_ret, sizeof miller_ret);
    ecc_memzero((byte_t *) &exp_ret, sizeof exp_ret);
}

void ecc_bls12_381_pairing_miller_loop(byte_t *ret, const byte_t *p1_g1, const byte_t *p2_g2) {
    blst_p1_affine p1;
    blst_p1_uncompress(&p1, p1_g1);

    blst_p2_affine p2;
    blst_p2_uncompress(&p2, p2_g2);

    blst_fp12 miller_ret;
    blst_miller_loop(&miller_ret, &p2, &p1);
    ecc_bls12_381_fp12_to_bytes(ret, &miller_ret);

    // cleanup stack memory
    ecc_memzero((byte_t *) &p1, sizeof p1);
    ecc_memzero((byte_t *) &p2, sizeof p2);
    ecc_memzero((byte_t *) &miller_ret, sizeof miller_ret);
}

void ecc_bls12_381_pairing_final_exp(byte_t *ret, const byte_t *a) {
    blst_fp12 e;
    ecc_bls12_381_fp12_from_bytes(&e, a);

    blst_fp12 exp_ret;
    blst_final_exp(&exp_ret, &e);
    ecc_bls12_381_fp12_to_bytes(ret, &exp_ret);

    // cleanup stack memory
    ecc_memzero((byte_t *) &e, sizeof e);
    ecc_memzero((byte_t *) &exp_ret, sizeof exp_ret);
}

int ecc_bls12_381_pairing_final_verify(const byte_t *a, const byte_t *b) {
    blst_fp12 ea;
    ecc_bls12_381_fp12_from_bytes(&ea, a);

    blst_fp12 eb;
    ecc_bls12_381_fp12_from_bytes(&eb, b);

    int ret = blst_fp12_finalverify(&ea, &eb);

    // cleanup stack memory
    ecc_memzero((byte_t *) &ea, sizeof ea);
    ecc_memzero((byte_t *) &eb, sizeof eb);

    return ret;
}
