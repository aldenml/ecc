/*
 * Copyright (c) 2022, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#include "ecc_test.h"

static void test_ecc_ed25519_generator(void **state) {
    ECC_UNUSED(state);

    byte_t g[ecc_ed25519_ELEMENTSIZE];
    ecc_ed25519_generator(g);
    ecc_log("ed25519 G", g, sizeof g);

    char g_hex[2 * ecc_ed25519_ELEMENTSIZE + 1];
    ecc_bin2hex(g_hex, g, sizeof g);

    // x point: 15112221349535400772501151409588531511454012693041857206046113283949847762202
    // y point: 46316835694926478169428394003475163141307993866256225615783033603165251855960
    assert_string_equal(g_hex, "693e47972caf527c7883ad1b39822f026f47db2ab0e1919955b8993aa04411d1");
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_ecc_ed25519_generator),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
