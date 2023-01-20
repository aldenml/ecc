/*
 * Copyright (c) 2022-2023, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#include "ecc_test.h"

// https://datatracker.ietf.org/doc/html/rfc4231#section-4
static void test_ecc_mac_hmac_sha2(void **state) {
    ECC_UNUSED(state);

    ecc_json_t json = ecc_json_load("../test/data/mac/hmac_sha2.json");

    const int n = ecc_json_array_size(json, "vectors");

    for (int i = 0; i < n; i++) {
        ecc_json_t item = ecc_json_array_item(json, "vectors", i);

        byte_t key[2000];
        int key_len;
        ecc_json_hex(key, &key_len, item, "key");
        ecc_log("key", key, key_len);

        byte_t data[2000];
        int data_len;
        ecc_json_hex(data, &data_len, item, "data");
        ecc_log("data", data, data_len);

        {
            byte_t mac[ecc_mac_hmac_sha256_HASHSIZE];
            int mac_len;
            ecc_json_hex(mac, &mac_len, item, "sha256");
            ecc_log("HMAC-SHA-256 Value", mac, mac_len);

            byte_t digest[ecc_mac_hmac_sha256_HASHSIZE];
            ecc_mac_hmac_sha256(digest, data, data_len, key, key_len);
            ecc_log("HMAC-SHA-256 Digest", mac, mac_len);

            assert_memory_equal(digest, mac, (size_t) mac_len);
        }

        {
            byte_t mac[ecc_mac_hmac_sha512_HASHSIZE];
            int mac_len;
            ecc_json_hex(mac, &mac_len, item, "sha512");
            ecc_log("HMAC-SHA-512 Value", mac, mac_len);

            byte_t digest[ecc_mac_hmac_sha512_HASHSIZE];
            ecc_mac_hmac_sha512(digest, data, data_len, key, key_len);
            ecc_log("HMAC-SHA-512 Digest", mac, mac_len);

            assert_memory_equal(digest, mac, (size_t) mac_len);
        }
    }

    ecc_json_destroy(json);
}

// https://datatracker.ietf.org/doc/html/rfc4231#section-4.2
static void test_ecc_mac_hmac_sha256_input1(void **state) {
    ECC_UNUSED(state);

    byte_t key[20];
    ecc_hex2bin(key, "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", 40);

    byte_t data[8];
    ecc_hex2bin(data, "4869205468657265", 16);

    byte_t digest[ecc_mac_hmac_sha256_HASHSIZE];
    ecc_mac_hmac_sha256(digest, data, sizeof data, key, sizeof key);

    char digest_hex[2 * ecc_mac_hmac_sha256_HASHSIZE + 1];
    ecc_bin2hex(digest_hex, digest, sizeof digest);
    assert_string_equal(digest_hex, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
}

// https://datatracker.ietf.org/doc/html/rfc4231#section-4.3
static void test_ecc_mac_hmac_sha256_input2(void **state) {
    ECC_UNUSED(state);

    byte_t key[4];
    ecc_hex2bin(key, "4a656665", 8);

    byte_t data[28];
    ecc_hex2bin(data, "7768617420646f2079612077616e7420666f72206e6f7468696e673f", 56);

    byte_t digest[ecc_mac_hmac_sha256_HASHSIZE];
    ecc_mac_hmac_sha256(digest, data, sizeof data, key, sizeof key);

    char digest_hex[2 * ecc_mac_hmac_sha256_HASHSIZE + 1];
    ecc_bin2hex(digest_hex, digest, sizeof digest);
    assert_string_equal(digest_hex, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_ecc_mac_hmac_sha2),
        cmocka_unit_test(test_ecc_mac_hmac_sha256_input1),
        cmocka_unit_test(test_ecc_mac_hmac_sha256_input2),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
