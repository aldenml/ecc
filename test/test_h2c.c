/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#include "ecc_test.h"
#include <stdarg.h>
#include <setjmp.h>
#include <string.h>
#include <cmocka.h>
#include <stdio.h>

// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-11#appendix-K.2

const byte_t dst[27] = "QUUX-V01-CS02-with-expander";
const int dst_len = 27;

static void ecc_h2c_expand_message_xmd_sha256_test1(void **state) {
    ECC_UNUSED(state);

    const byte_t msg[0];
    const int msg_len = 0;
    const int len_in_bytes = 0x20;
    byte_t uniform_bytes[0x20];

    ecc_h2c_expand_message_xmd_sha256(uniform_bytes, msg, msg_len, dst, dst_len, len_in_bytes);

    char hex[0x40 + 1];
    ecc_bin2hex(hex, uniform_bytes, 0x20);
    assert_string_equal(hex, "f659819a6473c1835b25ea59e3d38914c98b374f0970b7e4"
                             "c92181df928fca88");
}

static void ecc_h2c_expand_message_xmd_sha256_test1_null(void **state) {
    ECC_UNUSED(state);

    const int len_in_bytes = 0x20;
    byte_t uniform_bytes[0x20];

    ecc_h2c_expand_message_xmd_sha256(uniform_bytes, NULL, 0, dst, dst_len, len_in_bytes);

    char hex[0x40 + 1];
    ecc_bin2hex(hex, uniform_bytes, 0x20);
    assert_string_equal(hex, "f659819a6473c1835b25ea59e3d38914c98b374f0970b7e4"
                             "c92181df928fca88");
}

static void ecc_h2c_expand_message_xmd_sha256_test2(void **state) {
    ECC_UNUSED(state);

    const byte_t msg[3] = "abc";
    const int msg_len = 3;
    const int len_in_bytes = 0x20;
    byte_t uniform_bytes[0x20];

    ecc_h2c_expand_message_xmd_sha256(uniform_bytes, msg, msg_len, dst, dst_len, len_in_bytes);

    char hex[0x40 + 1];
    ecc_bin2hex(hex, uniform_bytes, 0x20);
    assert_string_equal(hex, "1c38f7c211ef233367b2420d04798fa4698080a8901021a7"
                             "95a1151775fe4da7");
}

static void ecc_h2c_expand_message_xmd_sha512_test1(void **state) {
    ECC_UNUSED(state);

    const byte_t msg[0];
    const int msg_len = 0;
    const int len_in_bytes = 0x20;
    byte_t uniform_bytes[0x20];

    ecc_h2c_expand_message_xmd_sha512(uniform_bytes, msg, msg_len, dst, dst_len, len_in_bytes);

    char hex[0x40 + 1];
    ecc_bin2hex(hex, uniform_bytes, 0x20);
    assert_string_equal(hex, "2eaa1f7b5715f4736e6a5dbe288257abf1faa028680c1d93"
                             "8cd62ac699ead642");
}

static void ecc_h2c_expand_message_xmd_sha512_test1_null(void **state) {
    ECC_UNUSED(state);

    const int len_in_bytes = 0x20;
    byte_t uniform_bytes[0x20];

    ecc_h2c_expand_message_xmd_sha512(uniform_bytes, NULL, 0, dst, dst_len, len_in_bytes);

    char hex[0x40 + 1];
    ecc_bin2hex(hex, uniform_bytes, 0x20);
    assert_string_equal(hex, "2eaa1f7b5715f4736e6a5dbe288257abf1faa028680c1d93"
                             "8cd62ac699ead642");
}

static void ecc_h2c_expand_message_xmd_sha512_test2(void **state) {
    ECC_UNUSED(state);

    const byte_t msg[3] = "abc";
    const int msg_len = 3;
    const int len_in_bytes = 0x20;
    byte_t uniform_bytes[0x20];

    ecc_h2c_expand_message_xmd_sha512(uniform_bytes, msg, msg_len, dst, dst_len, len_in_bytes);

    char hex[0x40 + 1];
    ecc_bin2hex(hex, uniform_bytes, 0x20);
    assert_string_equal(hex, "0eeda81f69376c80c0f8986496f22f21124cb3c562cf1dc6"
                             "08d2c13005553b0f");
}

static void ecc_h2c_expand_message_xmd_sha512_test3(void **state) {
    ECC_UNUSED(state);

    const byte_t msg[16] = "abcdef0123456789";
    const int msg_len = 16;
    const int len_in_bytes = 0x20;
    byte_t uniform_bytes[0x20];

    ecc_h2c_expand_message_xmd_sha512(uniform_bytes, msg, msg_len, dst, dst_len, len_in_bytes);

    char hex[0x40 + 1];
    ecc_bin2hex(hex, uniform_bytes, 0x20);
    assert_string_equal(hex, "2e375fc05e05e80dbf3083796fde2911789d9e8847e1fceb"
                             "f4ca4b36e239b338");
}

static void ecc_h2c_expand_message_xmd_sha512_test4(void **state) {
    ECC_UNUSED(state);

    const byte_t msg[] = "q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"
                           "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"
                           "qqqqqqqqqqqqqqqqqqqqqqqqq";
    const int msg_len = 133;
    const int len_in_bytes = 0x20;
    byte_t uniform_bytes[0x20];

    ecc_h2c_expand_message_xmd_sha512(uniform_bytes, msg, msg_len, dst, dst_len, len_in_bytes);

    char hex[0x40 + 1];
    ecc_bin2hex(hex, uniform_bytes, 0x20);
    assert_string_equal(hex, "c37f9095fe7fe4f01c03c3540c1229e6ac8583b075100859"
                             "20f62ec66acc0197");
}

static void ecc_h2c_expand_message_xmd_sha512_test5(void **state) {
    ECC_UNUSED(state);

    const byte_t msg[0];
    const int msg_len = 0;
    const int len_in_bytes = 0x80;
    byte_t uniform_bytes[0x80];

    ecc_h2c_expand_message_xmd_sha512(uniform_bytes, msg, msg_len, dst, dst_len, len_in_bytes);

    char hex[0x100 + 1];
    ecc_bin2hex(hex, uniform_bytes, 0x80);
    assert_string_equal(hex, "0687ce02eba5eb3faf1c3c539d1f04babd3c0f420edae244"
                             "eeb2253b6c6d6865145c31458e824b4e87ca61c3442dc7c8c9872b"
                             "0b7250aa33e0668ccebbd2b386de658ca11a1dcceb51368721ae6d"
                             "cd2d4bc86eaebc4e0d11fa02ad053289c9b28a03da6c942b2e12c1"
                             "4e88dbde3b0ba619d6214f47212b628f3e1b537b66efcf");
}

static void ecc_h2c_expand_message_xmd_sha512_test6(void **state) {
    ECC_UNUSED(state);

    const byte_t msg[3] = "abc";
    const int msg_len = 3;
    const int len_in_bytes = 0x80;
    byte_t uniform_bytes[0x80];

    ecc_h2c_expand_message_xmd_sha512(uniform_bytes, msg, msg_len, dst, dst_len, len_in_bytes);

    char hex[0x100 + 1];
    ecc_bin2hex(hex, uniform_bytes, 0x80);
    assert_string_equal(hex, "779ae4fd8a92f365e4df96b9fde97b40486bb005c1a2096c"
                             "86f55f3d92875d89045fbdbc4a0e9f2d3e1e6bcd870b2d7131d868"
                             "225b6fe72881a81cc5166b5285393f71d2e68bb0ac603479959370"
                             "d06bdbe5f0d8bfd9af9494d1e4029bd68ab35a561341dd3f866b3e"
                             "f0c95c1fdfaab384ce24a23427803dda1db0c7d8d5344a");
}

static void ecc_h2c_expand_message_xmd_sha512_test7(void **state) {
    ECC_UNUSED(state);

    const byte_t msg[16] = "abcdef0123456789";
    const int msg_len = 16;
    const int len_in_bytes = 0x80;
    byte_t uniform_bytes[0x80];

    ecc_h2c_expand_message_xmd_sha512(uniform_bytes, msg, msg_len, dst, dst_len, len_in_bytes);

    char hex[0x100 + 1];
    ecc_bin2hex(hex, uniform_bytes, 0x80);
    assert_string_equal(hex, "f0953d28846a50e9f88b7ae35b643fc43733c9618751b569"
                             "a73960c655c068db7b9f044ad5a40d49d91c62302eaa26163c12ab"
                             "fa982e2b5d753049e000adf7630ae117aeb1fb9b61fc724431ac68"
                             "b369e12a9481b4294384c3c890d576a79264787bc8076e7cdabe50"
                             "c044130e480501046920ff090c1a091c88391502f0fbac");
}

static void ecc_h2c_expand_message_xmd_sha512_test8(void **state) {
    ECC_UNUSED(state);

    const byte_t msg[] = "q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"
                         "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"
                         "qqqqqqqqqqqqqqqqqqqqqqqqq";
    const int msg_len = 133;
    const int len_in_bytes = 0x80;
    byte_t uniform_bytes[0x80];

    ecc_h2c_expand_message_xmd_sha512(uniform_bytes, msg, msg_len, dst, dst_len, len_in_bytes);

    char hex[0x100 + 1];
    ecc_bin2hex(hex, uniform_bytes, 0x80);
    assert_string_equal(hex, "64d3e59f0bc3c5e653011c914b419ba8310390a9585311fd"
                             "db26791d26663bd71971c347e1b5e88ba9274d2445ed9dcf48eea9"
                             "528d807b7952924159b7c27caa4f25a2ea94df9508e70a7012dfce"
                             "0e8021b37e59ea21b80aa9af7f1a1f2efa4fbe523c4266ce7d342a"
                             "caacd438e452c501c131156b4945515e9008d2b155c258");
}

int main() {
    const struct CMUnitTest tests[] = {
        // ecc_h2c_expand_message_xmd_sha256
        cmocka_unit_test(ecc_h2c_expand_message_xmd_sha256_test1),
        cmocka_unit_test(ecc_h2c_expand_message_xmd_sha256_test1_null),
        cmocka_unit_test(ecc_h2c_expand_message_xmd_sha256_test2),
        // ecc_h2c_expand_message_xmd_sha512
        cmocka_unit_test(ecc_h2c_expand_message_xmd_sha512_test1),
        cmocka_unit_test(ecc_h2c_expand_message_xmd_sha512_test1_null),
        cmocka_unit_test(ecc_h2c_expand_message_xmd_sha512_test2),
        cmocka_unit_test(ecc_h2c_expand_message_xmd_sha512_test3),
        cmocka_unit_test(ecc_h2c_expand_message_xmd_sha512_test4),
        cmocka_unit_test(ecc_h2c_expand_message_xmd_sha512_test5),
        cmocka_unit_test(ecc_h2c_expand_message_xmd_sha512_test6),
        cmocka_unit_test(ecc_h2c_expand_message_xmd_sha512_test7),
        cmocka_unit_test(ecc_h2c_expand_message_xmd_sha512_test8),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
