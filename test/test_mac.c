/*
 * Copyright (c) 2022, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#include "ecc_test.h"

// https://datatracker.ietf.org/doc/html/rfc4231#section-4
static void test_ecc_mac_hmac_sha2(void **state) {
    ECC_UNUSED(state);

    ecc_json_t *json = ecc_json_load("../test/data/mac/hmac_sha2.json");

    const int n = ecc_json_array_size(json, "vectors");

    for (int i = 0; i < n; i++) {
        ecc_json_t *item = ecc_json_array_item(json, "vectors", i);
        const char *key_hex = ecc_json_string(item, "key");
        const char *data_hex = ecc_json_string(item, "data");

        const int key_hex_len = (int) strlen(key_hex);
        const int key_len = key_hex_len / 2;
        byte_t *key = ecc_malloc(key_len);
        ecc_hex2bin(key, key_hex, key_hex_len);

        const int data_hex_len = (int) strlen(data_hex);
        const int data_len = data_hex_len / 2;
        byte_t *data = ecc_malloc(data_len);
        ecc_hex2bin(data, data_hex, data_hex_len);

        {
            const char *sha256 = ecc_json_string(item, "sha256");

            byte_t digest[ecc_mac_hmac_sha256_HASHSIZE];
            ecc_mac_hmac_sha256(digest, data, data_len, key, key_len);

            char hex[2 * ecc_mac_hmac_sha256_HASHSIZE + 1];
            ecc_bin2hex(hex, digest, sizeof digest);
            assert_string_equal(hex, sha256);
        }

        {
            const char *sha512 = ecc_json_string(item, "sha512");

            byte_t digest[ecc_mac_hmac_sha512_HASHSIZE];
            ecc_mac_hmac_sha512(digest, data, data_len, key, key_len);

            char hex[2 * ecc_mac_hmac_sha512_HASHSIZE + 1];
            ecc_bin2hex(hex, digest, sizeof digest);
            assert_string_equal(hex, sha512);
        }

        ecc_free(key, key_len);
        ecc_free(data, data_len);
    }

    ecc_json_destroy(json);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_ecc_mac_hmac_sha2),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
