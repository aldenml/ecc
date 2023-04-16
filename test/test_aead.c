/*
 * Copyright (c) 2023, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#include "ecc_test.h"

// https://datatracker.ietf.org/doc/html/rfc8439#appendix-A.5
static void test_ecc_aead_chacha20poly1305(void **state) {
    ECC_UNUSED(state);

    ecc_json_t json = ecc_json_load("../test/data/aead/chacha20poly1305.json");

    const int n = ecc_json_array_size(json, "vectors");

    for (int i = 0; i < n; i++) {
        ecc_json_t item = ecc_json_array_item(json, "vectors", i);

        byte_t key[2000];
        int key_len;
        ecc_json_hex(key, &key_len, item, "key");
        ecc_log("key", key, key_len);

        byte_t nonce[2000];
        int nonce_len;
        ecc_json_hex(nonce, &nonce_len, item, "nonce");
        ecc_log("nonce", nonce, nonce_len);

        byte_t aad[2000];
        int aad_len;
        ecc_json_hex(aad, &aad_len, item, "aad");
        ecc_log("aad", aad, aad_len);

        byte_t plaintext[2000];
        int plaintext_len;
        ecc_json_hex(plaintext, &plaintext_len, item, "plaintext");
        ecc_log("plaintext", plaintext, plaintext_len);

        byte_t ciphertext[2000];
        int ciphertext_len;
        ecc_json_hex(ciphertext, &ciphertext_len, item, "ciphertext");
        ecc_log("ciphertext", ciphertext, ciphertext_len);

        byte_t plaintext_encrypted[2000];

        ecc_aead_chacha20poly1305_encrypt(
            plaintext_encrypted,
            plaintext, plaintext_len,
            aad, aad_len,
            nonce,
            key
        );
        ecc_log("plaintext_encrypted", plaintext_encrypted, plaintext_len + ecc_aead_chacha20poly1305_MACSIZE);

        byte_t ciphertext_decrypted[2000];

        int r = ecc_aead_chacha20poly1305_decrypt(
            ciphertext_decrypted,
            ciphertext, ciphertext_len,
            aad, aad_len,
            nonce,
            key
        );

        assert_int_equal(r, 0);

        assert_memory_equal(plaintext, ciphertext_decrypted, (size_t) plaintext_len);
        assert_memory_equal(ciphertext, plaintext_encrypted, (size_t) ciphertext_len);
    }

    ecc_json_destroy(json);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_ecc_aead_chacha20poly1305),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
