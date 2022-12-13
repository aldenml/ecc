/*
 * Copyright (c) 2021-2022, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#include "ecc_test.h"

// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-16#appendix-K-1
static void test_ecc_h2c_expand_message_xmd_sha256(void **state) {
    ECC_UNUSED(state);

    static const byte_t DST[38] = "QUUX-V01-CS02-with-expander-SHA256-128";

    ecc_json_t json = ecc_json_load("../test/data/h2c/expand_message_xmd_sha256.json");

    const int n = ecc_json_array_size(json, "vectors");

    for (int i = 0; i < n; i++) {
        ecc_json_t item = ecc_json_array_item(json, "vectors", i);

        const char *msg = ecc_json_string(item, "msg");
        int msg_len = (int) strlen(msg);

        const double len_in_bytes_num = ecc_json_number(item, "len_in_bytes");
        const int len_in_bytes = (int) len_in_bytes_num;

        byte_t uniform_bytes[ecc_h2c_expand_message_xmd_sha256_MAXSIZE];
        int uniform_bytes_len;
        ecc_json_hex(uniform_bytes, &uniform_bytes_len, item, "uniform_bytes");
        ecc_log("uniform_bytes", uniform_bytes, uniform_bytes_len);

        byte_t out[ecc_h2c_expand_message_xmd_sha256_MAXSIZE];
        ecc_h2c_expand_message_xmd_sha256(out, (const byte_t *) msg, msg_len, DST, sizeof DST, len_in_bytes);

        assert_int_equal(len_in_bytes, uniform_bytes_len);
        assert_memory_equal(out, uniform_bytes, (size_t) len_in_bytes);
    }

    ecc_json_destroy(json);
}

// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-16#appendix-K-3
static void test_ecc_h2c_expand_message_xmd_sha512(void **state) {
    ECC_UNUSED(state);

    static const byte_t DST[38] = "QUUX-V01-CS02-with-expander-SHA512-256";

    ecc_json_t json = ecc_json_load("../test/data/h2c/expand_message_xmd_sha512.json");

    const int n = ecc_json_array_size(json, "vectors");

    for (int i = 0; i < n; i++) {
        ecc_json_t item = ecc_json_array_item(json, "vectors", i);

        const char *msg = ecc_json_string(item, "msg");
        int msg_len = (int) strlen(msg);

        const double len_in_bytes_num = ecc_json_number(item, "len_in_bytes");
        const int len_in_bytes = (int) len_in_bytes_num;

        byte_t uniform_bytes[ecc_h2c_expand_message_xmd_sha512_MAXSIZE];
        int uniform_bytes_len;
        ecc_json_hex(uniform_bytes, &uniform_bytes_len, item, "uniform_bytes");
        ecc_log("uniform_bytes", uniform_bytes, uniform_bytes_len);

        byte_t out[ecc_h2c_expand_message_xmd_sha512_MAXSIZE];
        ecc_h2c_expand_message_xmd_sha512(out, (const byte_t *) msg, msg_len, DST, sizeof DST, len_in_bytes);

        assert_int_equal(len_in_bytes, uniform_bytes_len);
        assert_memory_equal(out, uniform_bytes, (size_t) len_in_bytes);
    }

    ecc_json_destroy(json);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_ecc_h2c_expand_message_xmd_sha256),
        cmocka_unit_test(test_ecc_h2c_expand_message_xmd_sha512),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
