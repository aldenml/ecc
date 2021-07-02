/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#include "ecc.h"
#include <stdarg.h>
#include <setjmp.h>
#include <string.h>
#include <cmocka.h>
#include <stdio.h>

static void ecc_bin2hex_test1(void **state) {
    const byte_t bin[2] = {0xab, 0xcd};
    char hex[5];
    ecc_bin2hex(hex, bin, 2);
    assert_string_equal(hex, "abcd");
}

static void ecc_hex2bin_test1(void **state) {
    const char hex[4] = "abcd";
    byte_t bin[2];
    ecc_hex2bin(bin, hex, 4);
    const byte_t r[2] = {0xab, 0xcd};
    assert_memory_equal(bin, r, 2);
}

static void ecc_concat3_test1(void **state) {
    byte_t a1[2] = "a1";
    byte_t a2[3] = "b22";
    byte_t a3[4] = "c333";
    byte_t r1[9];
    ecc_concat3(r1, a1, 2, a2, 3, a3, 4);
    const byte_t r2[9] = "a1b22c333";
    assert_memory_equal(r1, r2, 9);
}

static void ecc_I2OSP_test1(void **state) {
    const char hex[4] = "abcd";
    byte_t bin[2];
    ecc_hex2bin(bin, hex, 4);
    const byte_t r[2] = {0xab, 0xcd};
    assert_memory_equal(bin, r, 2);
}

int main() {
    const struct CMUnitTest tests[] = {
        // ecc_bin2hex
        cmocka_unit_test(ecc_bin2hex_test1),
        // ecc_hex2bin
        cmocka_unit_test(ecc_hex2bin_test1),
        // concat
        cmocka_unit_test(ecc_concat3_test1),
        // ecc_I2OSP
        cmocka_unit_test(ecc_I2OSP_test1),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
