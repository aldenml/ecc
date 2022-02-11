/*
 * Copyright (c) 2022, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#include "ecc_test.h"

static void test_ecc_ristretto255_scalar_invert(void **state) {
    ECC_UNUSED(state);

    byte_t s[ecc_ristretto255_SCALARSIZE];
    ecc_ristretto255_scalar_random(s);

    byte_t s_inv[ecc_ristretto255_SCALARSIZE];
    ecc_ristretto255_scalar_invert(s_inv, s);

    byte_t m[ecc_ristretto255_SCALARSIZE];
    ecc_ristretto255_scalar_mul(m, s, s_inv);

    ecc_log("s * s_inv", m, sizeof m);

    byte_t one[ecc_ristretto255_SCALARSIZE] = {1, 0};
    assert_memory_equal(one, m, ecc_ristretto255_SCALARSIZE);
}

int main() {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_ecc_ristretto255_scalar_invert),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
