/*
 * Copyright (c) 2021-2022, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#include "ecc_test.h"

static void test_ecc_memzero(void **state) {
    ECC_UNUSED(state);

    const int len = 100;
    byte_t buf[100];
    ecc_randombytes(buf, len);
    ecc_memzero(buf, len);
    int count = 0;
    for (int i = 0; i < len; i++) {
        if (buf[i] == 0) count++;
    }
    assert_int_equal(count, len);
}

static void test_ecc_randombytes(void **state) {
    ECC_UNUSED(state);

    const int len = 10;
    byte_t buf[10];
    ecc_randombytes(buf, len);
    int count = 0;
    for (int i = 0; i < len; i++) {
        if (buf[i] == 0) count++;
    }
    // what are the odds of having more than one 0 in a random of 10 elements
    assert_true(count < 2);
}

static void test_ecc_bin2hex(void **state) {
    ECC_UNUSED(state);

    const byte_t bin[2] = {0xab, 0xcd};
    char hex[6];
    ecc_bin2hex(hex, bin, 2);
    assert_string_equal(hex, "abcd");
}

static void test_ecc_hex2bin(void **state) {
    ECC_UNUSED(state);

    const char hex[4] = "abcd";
    byte_t bin[2];
    ecc_hex2bin(bin, hex, 4);
    const byte_t r[2] = {0xab, 0xcd};
    assert_memory_equal(bin, r, 2);
}

static void test_ecc_concat2(void **state) {
    ECC_UNUSED(state);
    byte_t a1[2] = "a1";
    byte_t a2[3] = "b22";
    byte_t r1[9];
    ecc_concat2(r1, a1, 2, a2, 3);
    const byte_t r2[5] = "a1b22";
    assert_memory_equal(r1, r2, 5);
}

static void test_ecc_concat3(void **state) {
    ECC_UNUSED(state);
    byte_t a1[2] = "a1";
    byte_t a2[3] = "b22";
    byte_t a3[4] = "c333";
    byte_t r1[9];
    ecc_concat3(r1, a1, 2, a2, 3, a3, 4);
    const byte_t r2[9] = "a1b22c333";
    assert_memory_equal(r1, r2, 9);
}

static void test_ecc_concat4(void **state) {
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

static void test_ecc_strxor(void **state) {
    ECC_UNUSED(state);
    byte_t a[3] = "abc";
    byte_t b[3] = "XYZ";
    byte_t r[3];
    ecc_strxor(r, a, b, 3);
    assert_memory_equal(r, "9;9", 3);
}

static void test_ecc_I2OSP(void **state) {
    ECC_UNUSED(state);
    byte_t buf[2];
    ecc_I2OSP(buf, 0xabcd, 2);
    const byte_t r[2] = {0xab, 0xcd};
    assert_memory_equal(buf, r, 2);
}

static void test_ecc_compare_equal(void **state) {
    ECC_UNUSED(state);

    const byte_t a[2] = {0xab, 0xcd};
    const byte_t b[2] = {0xab, 0xcd};
    const int r = ecc_compare(a, b, 2);
    assert_int_equal(r, 0);
}

static void test_ecc_compare_different(void **state) {
    ECC_UNUSED(state);

    const byte_t a[2] = {0xfb, 0xcd};
    const byte_t b[2] = {0xab, 0xcd};
    const int r1 = ecc_compare(a, b, 2);
    const int r2 = ecc_compare(b, a, 2);
    assert_int_equal(r1, 1);
    assert_int_equal(r2, -1);
}

static void test_ecc_is_zero(void **state) {
    ECC_UNUSED(state);

    const byte_t a[2] = {0x0, 0x0};
    const byte_t b[2] = {0xab, 0xcd};
    const int r1 = ecc_is_zero(a, 2);
    const int r2 = ecc_is_zero(b, 2);
    assert_true(r1);
    assert_false(r2);
}

static void test_ecc_malloc(void **state) {
    ECC_UNUSED(state);

    const int len = 100;
    byte_t *ptr = ecc_malloc(len);
    assert_non_null(ptr);
    ecc_free(ptr, len);
}

int main() {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_ecc_memzero),
        cmocka_unit_test(test_ecc_randombytes),
        cmocka_unit_test(test_ecc_bin2hex),
        cmocka_unit_test(test_ecc_hex2bin),
        cmocka_unit_test(test_ecc_concat2),
        cmocka_unit_test(test_ecc_concat3),
        cmocka_unit_test(test_ecc_concat4),
        cmocka_unit_test(test_ecc_strxor),
        cmocka_unit_test(test_ecc_I2OSP),
        cmocka_unit_test(test_ecc_compare_equal),
        cmocka_unit_test(test_ecc_compare_different),
        cmocka_unit_test(test_ecc_is_zero),
        cmocka_unit_test(test_ecc_malloc),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
