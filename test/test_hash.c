/*
 * Copyright (c) 2022, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#include "ecc_test.h"

static void test_ecc_hash_sha256(void **state) {
    ECC_UNUSED(state);

    ecc_json_t *json = ecc_json_load("../test/data/hash/sha256.json");

    const int n = ecc_json_array_size(json, "vectors");

    for (int i = 0; i < n; i++) {
        ecc_json_t *item = ecc_json_array_item(json, "vectors", 0);
        const char *input = ecc_json_string(item, "input");
        const char *output = ecc_json_string(item, "output");

        byte_t digest[ecc_hash_sha256_HASHSIZE];
        ecc_hash_sha256(digest, (const byte_t *) input, (int) strlen(input));

        char hex[2 * ecc_hash_sha256_HASHSIZE + 1];
        ecc_bin2hex(hex, digest, sizeof digest);
        assert_string_equal(hex, output);
    }

    ecc_json_destroy(json);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_ecc_hash_sha256),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
