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

static void ecc_memzero_test(void **state) {
    ECC_UNUSED(state);

    const int len = 100;
    byte_t buf[len];
    ecc_randombytes(buf, len);
    ecc_memzero(buf, len);
    int count = 0;
    for (int i = 0; i < len; i++) {
        if (buf[i] == 0) count++;
    }
    assert_int_equal(count, len);
}

static void ecc_randombytes_test(void **state) {
    ECC_UNUSED(state);

    const int len = 10;
    byte_t buf[len];
    ecc_randombytes(buf, len);
    int count = 0;
    for (int i = 0; i < len; i++) {
        if (buf[i] == 0) count++;
    }
    // what are the odds of having more than one 0 in a random of 10 elements
    assert_true(count < 2);
}

static void ecc_bin2hex_test(void **state) {
    ECC_UNUSED(state);

    const byte_t bin[2] = {0xab, 0xcd};
    char hex[6];
    ecc_bin2hex(hex, bin, 2);
    assert_string_equal(hex, "abcd");
}

static void ecc_hex2bin_test(void **state) {
    ECC_UNUSED(state);

    const char hex[4] = "abcd";
    byte_t bin[2];
    ecc_hex2bin(bin, hex, 4);
    const byte_t r[2] = {0xab, 0xcd};
    assert_memory_equal(bin, r, 2);
}

static void ecc_concat3_test1(void **state) {
    ECC_UNUSED(state);
    byte_t a1[2] = "a1";
    byte_t a2[3] = "b22";
    byte_t a3[4] = "c333";
    byte_t r1[9];
    ecc_concat3(r1, a1, 2, a2, 3, a3, 4);
    const byte_t r2[9] = "a1b22c333";
    assert_memory_equal(r1, r2, 9);
}

static void ecc_concat4_test1(void **state) {
    ECC_UNUSED(state);
    byte_t a1[2] = "a1";
    byte_t a2[3] = "b22";
    byte_t a3[4] = "c333";
    byte_t a4[5] = "d4444";
    byte_t r1[14];
    ecc_concat4(r1, a1, 2, a2, 3, a3, 4, a4, 5);
    const byte_t r2[14] = "a1b22c333d4444";
    assert_memory_equal(r1, r2, 14);
}

static void ecc_strxor_test1(void **state) {
    ECC_UNUSED(state);
    byte_t a[3] = "abc";
    byte_t b[3] = "XYZ";
    byte_t r[3];
    ecc_strxor(r, a, b, 3);
    assert_memory_equal(r, "9;9", 2);
}

static void ecc_I2OSP_test1(void **state) {
    ECC_UNUSED(state);
    const char hex[4] = "abcd";
    byte_t bin[2];
    ecc_hex2bin(bin, hex, 4);
    const byte_t r[2] = {0xab, 0xcd};
    assert_memory_equal(bin, r, 2);
}

int main() {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(ecc_memzero_test),
        cmocka_unit_test(ecc_randombytes_test),
        cmocka_unit_test(ecc_bin2hex_test),
        cmocka_unit_test(ecc_hex2bin_test),
        cmocka_unit_test(ecc_concat3_test1),
        cmocka_unit_test(ecc_concat4_test1),
        cmocka_unit_test(ecc_strxor_test1),
        cmocka_unit_test(ecc_I2OSP_test1),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
