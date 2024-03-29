/*
 * Copyright (c) 2021-2023, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#include "ecc_test.h"

static void test_ecc_bls12_381_fp12_one(void **state) {
    ECC_UNUSED(state);

    byte_t one[ecc_bls12_381_FP12SIZE];
    ecc_bls12_381_fp12_one(one);

    ecc_log("bls12_381_fp12_one", one, sizeof one);

    int r = ecc_bls12_381_fp12_is_one(one);
    assert_int_equal(r, 1);
}

static void test_ecc_bls12_381_fp12_one_rand(void **state) {
    ECC_UNUSED(state);

    byte_t a[ecc_bls12_381_FP12SIZE];
    ecc_bls12_381_fp12_random(a);

    int r = ecc_bls12_381_fp12_is_one(a);
    assert_int_equal(r, 0);
}

static void test_ecc_bls12_381_fp12_pow(void **state) {
    ECC_UNUSED(state);

    byte_t n;
    byte_t m;
    ecc_randombytes(&n, 1);
    ecc_randombytes(&m, 1);

    byte_t a[ecc_bls12_381_FP12SIZE];
    ecc_bls12_381_fp12_random(a);

    byte_t an[ecc_bls12_381_FP12SIZE];
    byte_t am[ecc_bls12_381_FP12SIZE];
    byte_t anm[ecc_bls12_381_FP12SIZE];
    ecc_bls12_381_fp12_pow(an, a, n);
    ecc_bls12_381_fp12_pow(am, a, m);
    ecc_bls12_381_fp12_pow(anm, a, (int) n + (int) m);

    byte_t r[ecc_bls12_381_FP12SIZE];
    ecc_bls12_381_fp12_mul(r, an, am);

    assert_memory_equal(r, anm, ecc_bls12_381_FP12SIZE);
}

static void test_ecc_bls12_381_fp12_pow_inverse(void **state) {
    ECC_UNUSED(state);

    byte_t n;
    ecc_randombytes(&n, 1);

    byte_t a[ecc_bls12_381_FP12SIZE];
    ecc_bls12_381_fp12_random(a);

    byte_t a1[ecc_bls12_381_FP12SIZE];
    byte_t a2[ecc_bls12_381_FP12SIZE];
    ecc_bls12_381_fp12_pow(a1, a, n);
    ecc_bls12_381_fp12_pow(a2, a, -n);

    byte_t a12[ecc_bls12_381_FP12SIZE];
    ecc_bls12_381_fp12_mul(a12, a1, a2);

    int r = ecc_bls12_381_fp12_is_one(a12);
    assert_int_equal(r, 1);
}

static void test_ecc_bls12_381_pairing(void **state) {
    ECC_UNUSED(state);

    byte_t a[ecc_bls12_381_SCALARSIZE] = {0};
    byte_t b[ecc_bls12_381_SCALARSIZE] = {0};
    ecc_randombytes(a, 1);
    ecc_randombytes(b, 1);

    byte_t aP[ecc_bls12_381_G1SIZE];
    byte_t bQ[ecc_bls12_381_G2SIZE];

    ecc_bls12_381_g1_scalarmult_base(aP, a); // a * P
    ecc_bls12_381_g2_scalarmult_base(bQ, b); // b * Q

    byte_t pairing1[ecc_bls12_381_FP12SIZE];
    ecc_bls12_381_pairing(pairing1, aP, bQ); // e(a * P, b * Q)

    byte_t one[ecc_bls12_381_SCALARSIZE] = {1, 0}; // 1 (one)

    byte_t P[ecc_bls12_381_G1SIZE];
    byte_t Q[ecc_bls12_381_G2SIZE];

    ecc_bls12_381_g1_scalarmult_base(P, one); // P
    ecc_bls12_381_g2_scalarmult_base(Q, one); // Q

    byte_t pairing2[ecc_bls12_381_FP12SIZE];
    ecc_bls12_381_pairing(pairing2, P, Q); // e(P, Q)

    byte_t r[ecc_bls12_381_FP12SIZE];
    ecc_bls12_381_fp12_pow(r, pairing2, a[0] * b[0]);

    assert_memory_equal(pairing1, r, ecc_bls12_381_FP12SIZE);
}

static void test_ecc_bls12_381_pairing_reverse_scalars(void **state) {
    ECC_UNUSED(state);

    byte_t a[ecc_bls12_381_SCALARSIZE] = {0};
    byte_t b[ecc_bls12_381_SCALARSIZE] = {0};
    ecc_randombytes(a, 1);
    ecc_randombytes(b, 1);

    byte_t aP[ecc_bls12_381_G1SIZE];
    byte_t bQ[ecc_bls12_381_G2SIZE];

    ecc_bls12_381_g1_scalarmult_base(aP, a); // a * P
    ecc_bls12_381_g2_scalarmult_base(bQ, b); // b * Q

    byte_t pairing1[ecc_bls12_381_FP12SIZE];
    ecc_bls12_381_pairing(pairing1, aP, bQ); // e(a * P, b * Q)

    byte_t bP[ecc_bls12_381_G1SIZE];
    byte_t aQ[ecc_bls12_381_G2SIZE];

    ecc_bls12_381_g1_scalarmult_base(bP, b); // b * P
    ecc_bls12_381_g2_scalarmult_base(aQ, a); // a * Q

    byte_t pairing2[ecc_bls12_381_FP12SIZE];
    ecc_bls12_381_pairing(pairing2, bP, aQ); // e(b * P, a * Q)

    // is e(a * P, b * Q) == e(b * P, a * Q) ?
    assert_memory_equal(pairing1, pairing2, ecc_bls12_381_FP12SIZE);
}

static void test_ecc_bls12_381_pairing_perform(void **state) {
    ECC_UNUSED(state);

    byte_t a[ecc_bls12_381_SCALARSIZE];
    byte_t b[ecc_bls12_381_SCALARSIZE];
    ecc_bls12_381_scalar_random(a);
    ecc_bls12_381_scalar_random(b);

    byte_t aP[ecc_bls12_381_G1SIZE];
    byte_t bQ[ecc_bls12_381_G2SIZE];

    ecc_bls12_381_g1_scalarmult_base(aP, a); // a * P
    ecc_bls12_381_g2_scalarmult_base(bQ, b); // b * Q

    byte_t pairing[ecc_bls12_381_FP12SIZE];
    ecc_bls12_381_pairing(pairing, aP, bQ); // e(a * P, b * Q)
}

static void test_ecc_bls12_381_pairing_miller_loop(void **state) {
    ECC_UNUSED(state);

    byte_t a[ecc_bls12_381_SCALARSIZE] = {2, 0};
    byte_t b[ecc_bls12_381_SCALARSIZE] = {1, 0};

    byte_t aP[ecc_bls12_381_G1SIZE];
    byte_t bQ[ecc_bls12_381_G2SIZE];

    ecc_bls12_381_g1_scalarmult_base(aP, a); // a * P
    ecc_bls12_381_g2_scalarmult_base(bQ, b); // b * Q

    byte_t pairing1[ecc_bls12_381_FP12SIZE];
    ecc_bls12_381_pairing_miller_loop(pairing1, aP, bQ); // e(a * P, b * Q)

    byte_t one[ecc_bls12_381_SCALARSIZE] = {1, 0}; // 1 (one)

    byte_t P[ecc_bls12_381_G1SIZE];
    byte_t Q[ecc_bls12_381_G2SIZE];

    ecc_bls12_381_g1_scalarmult_base(P, one); // P
    ecc_bls12_381_g2_scalarmult_base(Q, one); // Q

    byte_t pairing2[ecc_bls12_381_FP12SIZE];
    ecc_bls12_381_pairing_miller_loop(pairing2, P, Q); // e(P, Q)

    byte_t r[ecc_bls12_381_FP12SIZE];
    ecc_bls12_381_fp12_mul(r, pairing2, pairing2);

    int v = ecc_bls12_381_pairing_final_verify(pairing1, r);

    assert_int_equal(v, 1);
}

static void test_ecc_bls12_381_pairing_g2_inverse(void **state) {
    ECC_UNUSED(state);

    byte_t a[ecc_bls12_381_SCALARSIZE];
    ecc_bls12_381_scalar_random(a);

    byte_t g1[ecc_bls12_381_G1SIZE];
    ecc_bls12_381_g1_generator(g1);

    byte_t P[ecc_bls12_381_G2SIZE];

    ecc_bls12_381_g2_scalarmult_base(P, a); // P = a * g2

    byte_t pairing[ecc_bls12_381_FP12SIZE];
    ecc_bls12_381_pairing(pairing, g1, P); // e(g1, a * g2)

    byte_t pairing_inverse[ecc_bls12_381_FP12SIZE];
    ecc_bls12_381_fp12_inverse(pairing_inverse, pairing); // e(g1, a * g2)^(-1)

    byte_t mul[ecc_bls12_381_FP12SIZE];
    ecc_bls12_381_fp12_mul(mul, pairing, pairing_inverse);

    int r = ecc_bls12_381_fp12_is_one(mul);
    assert_int_equal(r, 1);
}

static void test_ecc_bls12_381_g1_negate(void **state) {
    ECC_UNUSED(state);

    byte_t A[ecc_bls12_381_G1SIZE];
    ecc_bls12_381_g1_random(A);
    byte_t B[ecc_bls12_381_G1SIZE];
    ecc_bls12_381_g1_random(B);

    byte_t A_neg[ecc_bls12_381_G1SIZE];
    ecc_bls12_381_g1_negate(A_neg, A);

    byte_t B_neg[ecc_bls12_381_G1SIZE];
    ecc_bls12_381_g1_negate(B_neg, B);

    byte_t S1[ecc_bls12_381_G1SIZE];
    ecc_bls12_381_g1_add(S1, A, B);

    byte_t S1_neg[ecc_bls12_381_G1SIZE];
    ecc_bls12_381_g1_negate(S1_neg, S1);

    byte_t S2[ecc_bls12_381_G1SIZE];
    ecc_bls12_381_g1_add(S2, A_neg, B_neg);

    int r = ecc_compare(S1_neg, S2, ecc_bls12_381_G1SIZE);
    assert_int_equal(r, 0);
}

static void test_ecc_bls12_381_g2_negate(void **state) {
    ECC_UNUSED(state);

    byte_t A[ecc_bls12_381_G2SIZE];
    ecc_bls12_381_g2_random(A);
    byte_t B[ecc_bls12_381_G2SIZE];
    ecc_bls12_381_g2_random(B);

    byte_t A_neg[ecc_bls12_381_G2SIZE];
    ecc_bls12_381_g2_negate(A_neg, A);

    byte_t B_neg[ecc_bls12_381_G2SIZE];
    ecc_bls12_381_g2_negate(B_neg, B);

    byte_t S1[ecc_bls12_381_G2SIZE];
    ecc_bls12_381_g2_add(S1, A, B);

    byte_t S1_neg[ecc_bls12_381_G2SIZE];
    ecc_bls12_381_g2_negate(S1_neg, S1);

    byte_t S2[ecc_bls12_381_G2SIZE];
    ecc_bls12_381_g2_add(S2, A_neg, B_neg);

    int r = ecc_compare(S1_neg, S2, ecc_bls12_381_G2SIZE);
    assert_int_equal(r, 0);
}

static void test_ecc_bls12_381_g1_scalarmult(void **state) {
    ECC_UNUSED(state);

    byte_t g1[ecc_bls12_381_G1SIZE];
    ecc_bls12_381_g1_generator(g1);

    byte_t a[ecc_bls12_381_SCALARSIZE];
    ecc_bls12_381_scalar_random(a);

    byte_t A[ecc_bls12_381_G1SIZE];
    ecc_bls12_381_g1_scalarmult(A, a, g1);

    byte_t B[ecc_bls12_381_G1SIZE];
    ecc_bls12_381_g1_scalarmult_base(B, a);

    int r = ecc_compare(A, B, ecc_bls12_381_G1SIZE);
    assert_int_equal(r, 0);
}

static void test_ecc_bls12_381_g2_scalarmult(void **state) {
    ECC_UNUSED(state);

    byte_t g2[ecc_bls12_381_G2SIZE];
    ecc_bls12_381_g2_generator(g2);

    byte_t a[ecc_bls12_381_SCALARSIZE];
    ecc_bls12_381_scalar_random(a);

    byte_t A[ecc_bls12_381_G2SIZE];
    ecc_bls12_381_g2_scalarmult(A, a, g2);

    byte_t B[ecc_bls12_381_G2SIZE];
    ecc_bls12_381_g2_scalarmult_base(B, a);

    int r = ecc_compare(A, B, ecc_bls12_381_G2SIZE);
    assert_int_equal(r, 0);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_ecc_bls12_381_fp12_one),
        cmocka_unit_test(test_ecc_bls12_381_fp12_one_rand),
        cmocka_unit_test(test_ecc_bls12_381_fp12_pow),
        cmocka_unit_test(test_ecc_bls12_381_fp12_pow_inverse),
        cmocka_unit_test(test_ecc_bls12_381_pairing),
        cmocka_unit_test(test_ecc_bls12_381_pairing_reverse_scalars),
        cmocka_unit_test(test_ecc_bls12_381_pairing_perform),
        cmocka_unit_test(test_ecc_bls12_381_pairing_miller_loop),
        cmocka_unit_test(test_ecc_bls12_381_pairing_g2_inverse),
        cmocka_unit_test(test_ecc_bls12_381_g1_negate),
        cmocka_unit_test(test_ecc_bls12_381_g2_negate),
        cmocka_unit_test(test_ecc_bls12_381_g1_scalarmult),
        cmocka_unit_test(test_ecc_bls12_381_g2_scalarmult),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
