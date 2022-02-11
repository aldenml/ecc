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

int main() {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_ecc_frost_ristretto255_sha512_polynomial_evaluate_small_numbers),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
