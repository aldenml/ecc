/*
 * Copyright (c) 2022, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#include "ecc_test.h"

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

int main() {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_ecc_frost_ristretto255_sha512_polynomial_evaluate_small_numbers),
        cmocka_unit_test(test_ecc_frost_ristretto255_sha512_derive_lagrange_coefficient_1),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
