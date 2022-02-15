/*
 * Copyright (c) 2022, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#include "ecc_test.h"

static void test_ecc_frost_ristretto255_sha512_schnorr_signature(void **state) {
    ECC_UNUSED(state);

    byte_t sk[ecc_frost_ristretto255_sha512_SECRETKEYSIZE];
    byte_t pk[ecc_frost_ristretto255_sha512_PUBLICKEYSIZE];
    byte_t msg[5] = "hello";

    ecc_ristretto255_scalar_random(sk);
    ecc_ristretto255_scalarmult_base(pk, sk);

    byte_t signature[ecc_frost_ristretto255_sha512_SIGNATURESIZE];
    ecc_frost_ristretto255_sha512_schnorr_signature_generate(signature, msg, sizeof msg, sk);

    int r = ecc_frost_ristretto255_sha512_schnorr_signature_verify(msg, sizeof msg, signature, pk);
    assert_int_equal(r, 1);
}

static void test_ecc_frost_ristretto255_sha512_polynomial_evaluate_small_numbers(void **state) {
    ECC_UNUSED(state);

    byte_t a0[ecc_frost_ristretto255_sha512_SCALARSIZE] = {1, 0};
    byte_t a1[ecc_frost_ristretto255_sha512_SCALARSIZE] = {2, 0};
    byte_t a2[ecc_frost_ristretto255_sha512_SCALARSIZE] = {3, 0};
    byte_t a3[ecc_frost_ristretto255_sha512_SCALARSIZE] = {4, 0};

    byte_t coeffs[4 * ecc_frost_ristretto255_sha512_SCALARSIZE];
    ecc_concat4(
        coeffs,
        a0, sizeof a0,
        a1, sizeof a1,
        a2, sizeof a2,
        a3, sizeof a3
    );

    // f(0)
    byte_t x1[ecc_frost_ristretto255_sha512_SCALARSIZE] = {0};
    byte_t r1[ecc_frost_ristretto255_sha512_SCALARSIZE] = {1, 0};
    byte_t v1[ecc_frost_ristretto255_sha512_SCALARSIZE];
    ecc_frost_ristretto255_sha512_polynomial_evaluate(v1, x1, coeffs, 4);
    assert_memory_equal(v1, r1, ecc_frost_ristretto255_sha512_SCALARSIZE);

    // f(1)
    byte_t x2[ecc_frost_ristretto255_sha512_SCALARSIZE] = {1, 0};
    byte_t r2[ecc_frost_ristretto255_sha512_SCALARSIZE] = {10, 0};
    byte_t v2[ecc_frost_ristretto255_sha512_SCALARSIZE];
    ecc_frost_ristretto255_sha512_polynomial_evaluate(v2, x2, coeffs, 4);
    assert_memory_equal(v2, r2, ecc_frost_ristretto255_sha512_SCALARSIZE);

    // f(2)
    byte_t x3[ecc_frost_ristretto255_sha512_SCALARSIZE] = {2, 0};
    byte_t r3[ecc_frost_ristretto255_sha512_SCALARSIZE] = {49, 0};
    byte_t v3[ecc_frost_ristretto255_sha512_SCALARSIZE];
    ecc_frost_ristretto255_sha512_polynomial_evaluate(v3, x3, coeffs, 4);
    assert_memory_equal(v3, r3, ecc_frost_ristretto255_sha512_SCALARSIZE);
}

static void test_ecc_frost_ristretto255_sha512_derive_lagrange_coefficient_1(void **state) {
    ECC_UNUSED(state);

    byte_t x0[ecc_frost_ristretto255_sha512_SCALARSIZE] = {1, 0};
    byte_t x1[ecc_frost_ristretto255_sha512_SCALARSIZE] = {2, 0};
    byte_t x2[ecc_frost_ristretto255_sha512_SCALARSIZE] = {3, 0};
    byte_t x3[ecc_frost_ristretto255_sha512_SCALARSIZE] = {4, 0};

    byte_t L[4 * ecc_frost_ristretto255_sha512_SCALARSIZE];
    ecc_concat4(
        L,
        x0, sizeof x0,
        x1, sizeof x1,
        x2, sizeof x2,
        x3, sizeof x3
    );

    byte_t L_0[ecc_frost_ristretto255_sha512_SCALARSIZE];
    ecc_frost_ristretto255_sha512_derive_lagrange_coefficient(L_0, x0, L, 4);
    ecc_log("L_0", L_0, sizeof L_0);
    char L_0_hex[2 * ecc_frost_ristretto255_sha512_SCALARSIZE + 1];
    ecc_bin2hex(L_0_hex, L_0, sizeof L_0);
    assert_string_equal(L_0_hex, "0400000000000000000000000000000000000000000000000000000000000000");

    byte_t L_1[ecc_frost_ristretto255_sha512_SCALARSIZE];
    ecc_frost_ristretto255_sha512_derive_lagrange_coefficient(L_1, x1, L, 4);
    ecc_log("L_1", L_1, sizeof L_1);
    char L_1_hex[2 * ecc_frost_ristretto255_sha512_SCALARSIZE + 1];
    ecc_bin2hex(L_1_hex, L_1, sizeof L_1);
    assert_string_equal(L_1_hex, "e7d3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010");
}

static void test_ecc_frost_ristretto255_sha512_derive_lagrange_coefficient_with_points_1(void **state) {
    ECC_UNUSED(state);

    byte_t p0[ecc_frost_ristretto255_sha512_POINTSIZE] = {1, 0};
    byte_t p1[ecc_frost_ristretto255_sha512_POINTSIZE] = {2, 0};
    byte_t p2[ecc_frost_ristretto255_sha512_POINTSIZE] = {3, 0};
    byte_t p3[ecc_frost_ristretto255_sha512_POINTSIZE] = {4, 0};

    byte_t L[4 * ecc_frost_ristretto255_sha512_POINTSIZE];
    ecc_concat4(
        L,
        p0, sizeof p0,
        p1, sizeof p1,
        p2, sizeof p2,
        p3, sizeof p3
    );

    byte_t L_0[ecc_frost_ristretto255_sha512_SCALARSIZE];
    ecc_frost_ristretto255_sha512_derive_lagrange_coefficient_with_points(L_0, p0, L, 4); // x is first in p
    ecc_log("L_0", L_0, sizeof L_0);
    char L_0_hex[2 * ecc_frost_ristretto255_sha512_SCALARSIZE + 1];
    ecc_bin2hex(L_0_hex, L_0, sizeof L_0);
    assert_string_equal(L_0_hex, "0400000000000000000000000000000000000000000000000000000000000000");

    byte_t L_1[ecc_frost_ristretto255_sha512_SCALARSIZE];
    ecc_frost_ristretto255_sha512_derive_lagrange_coefficient_with_points(L_1, p1, L, 4); // x is first in p
    ecc_log("L_1", L_1, sizeof L_1);
    char L_1_hex[2 * ecc_frost_ristretto255_sha512_SCALARSIZE + 1];
    ecc_bin2hex(L_1_hex, L_1, sizeof L_1);
    assert_string_equal(L_1_hex, "e7d3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010");
}

static void test_ecc_frost_ristretto255_sha512_polynomial_interpolation_small_numbers_1(void **state) {
    ECC_UNUSED(state);

    byte_t a0[ecc_frost_ristretto255_sha512_SCALARSIZE] = {1, 0};
    byte_t a1[ecc_frost_ristretto255_sha512_SCALARSIZE] = {2, 0};
    byte_t a2[ecc_frost_ristretto255_sha512_SCALARSIZE] = {3, 0};
    byte_t a3[ecc_frost_ristretto255_sha512_SCALARSIZE] = {4, 0};

    byte_t coeffs[4 * ecc_frost_ristretto255_sha512_SCALARSIZE];
    ecc_concat4(
        coeffs,
        a0, sizeof a0,
        a1, sizeof a1,
        a2, sizeof a2,
        a3, sizeof a3
    );

    byte_t p0[ecc_frost_ristretto255_sha512_POINTSIZE] = {1, 0};
    byte_t p1[ecc_frost_ristretto255_sha512_POINTSIZE] = {2, 0};
    byte_t p2[ecc_frost_ristretto255_sha512_POINTSIZE] = {3, 0};
    byte_t p3[ecc_frost_ristretto255_sha512_POINTSIZE] = {4, 0};

    ecc_frost_ristretto255_sha512_polynomial_evaluate(&p0[ecc_frost_ristretto255_sha512_SCALARSIZE], p0, coeffs, 4);
    ecc_frost_ristretto255_sha512_polynomial_evaluate(&p1[ecc_frost_ristretto255_sha512_SCALARSIZE], p1, coeffs, 4);
    ecc_frost_ristretto255_sha512_polynomial_evaluate(&p2[ecc_frost_ristretto255_sha512_SCALARSIZE], p2, coeffs, 4);
    ecc_frost_ristretto255_sha512_polynomial_evaluate(&p3[ecc_frost_ristretto255_sha512_SCALARSIZE], p3, coeffs, 4);

    byte_t points[4 * ecc_frost_ristretto255_sha512_POINTSIZE];
    ecc_concat4(
        points,
        p0, sizeof p0,
        p1, sizeof p1,
        p2, sizeof p2,
        p3, sizeof p3
    );

    byte_t constant_term[ecc_frost_ristretto255_sha512_SCALARSIZE];
    ecc_frost_ristretto255_sha512_polynomial_interpolation(constant_term, points, 4);
    assert_memory_equal(constant_term, a0, ecc_frost_ristretto255_sha512_SCALARSIZE);
}

static void test_ecc_frost_ristretto255_sha512_polynomial_interpolation_small_numbers_2(void **state) {
    ECC_UNUSED(state);

    byte_t a0[ecc_frost_ristretto255_sha512_SCALARSIZE] = {4, 0};
    byte_t a1[ecc_frost_ristretto255_sha512_SCALARSIZE] = {1, 0};
    byte_t a2[ecc_frost_ristretto255_sha512_SCALARSIZE] = {2, 0};
    byte_t a3[ecc_frost_ristretto255_sha512_SCALARSIZE] = {3, 0};

    byte_t coeffs[4 * ecc_frost_ristretto255_sha512_SCALARSIZE];
    ecc_concat4(
        coeffs,
        a0, sizeof a0,
        a1, sizeof a1,
        a2, sizeof a2,
        a3, sizeof a3
    );

    byte_t p0[ecc_frost_ristretto255_sha512_POINTSIZE] = {4, 0};
    byte_t p1[ecc_frost_ristretto255_sha512_POINTSIZE] = {1, 0};
    byte_t p2[ecc_frost_ristretto255_sha512_POINTSIZE] = {2, 0};
    byte_t p3[ecc_frost_ristretto255_sha512_POINTSIZE] = {3, 0};

    ecc_frost_ristretto255_sha512_polynomial_evaluate(&p0[ecc_frost_ristretto255_sha512_SCALARSIZE], p0, coeffs, 4);
    ecc_frost_ristretto255_sha512_polynomial_evaluate(&p1[ecc_frost_ristretto255_sha512_SCALARSIZE], p1, coeffs, 4);
    ecc_frost_ristretto255_sha512_polynomial_evaluate(&p2[ecc_frost_ristretto255_sha512_SCALARSIZE], p2, coeffs, 4);
    ecc_frost_ristretto255_sha512_polynomial_evaluate(&p3[ecc_frost_ristretto255_sha512_SCALARSIZE], p3, coeffs, 4);

    byte_t points[4 * ecc_frost_ristretto255_sha512_POINTSIZE];
    ecc_concat4(
        points,
        p0, sizeof p0,
        p1, sizeof p1,
        p2, sizeof p2,
        p3, sizeof p3
    );

    byte_t constant_term[ecc_frost_ristretto255_sha512_SCALARSIZE];
    ecc_frost_ristretto255_sha512_polynomial_interpolation(constant_term, points, 4);
    assert_memory_equal(constant_term, a0, ecc_frost_ristretto255_sha512_SCALARSIZE);
}

static void test_ecc_frost_ristretto255_sha512_commit_with_nonce(void **state) {
    ECC_UNUSED(state);

    byte_t nonce[64];
    ecc_hex2bin(&nonce[0], "0100000000000000000000000000000000000000000000000000000000000000", 64);
    ecc_hex2bin(&nonce[32], "0200000000000000000000000000000000000000000000000000000000000000", 64);

    byte_t comm[64];
    ecc_frost_ristretto255_sha512_commit_with_nonce(comm, nonce);
    ecc_log("comm", comm, sizeof comm);

    char comm_hex[129];
    ecc_bin2hex(comm_hex, comm, sizeof comm);
    assert_string_equal(comm_hex,
        "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d766a493210f7499cd17fecb510ae0cea23a110e8d5b901f8acadd3095c73a3b919");
}

int main() {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_ecc_frost_ristretto255_sha512_schnorr_signature),
        cmocka_unit_test(test_ecc_frost_ristretto255_sha512_polynomial_evaluate_small_numbers),
        cmocka_unit_test(test_ecc_frost_ristretto255_sha512_derive_lagrange_coefficient_1),
        cmocka_unit_test(test_ecc_frost_ristretto255_sha512_derive_lagrange_coefficient_with_points_1),
        cmocka_unit_test(test_ecc_frost_ristretto255_sha512_polynomial_interpolation_small_numbers_1),
        cmocka_unit_test(test_ecc_frost_ristretto255_sha512_polynomial_interpolation_small_numbers_2),
        cmocka_unit_test(test_ecc_frost_ristretto255_sha512_commit_with_nonce),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
