/*
 * Copyright (c) 2023, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#include "aead.h"
#include <assert.h>
#include <sodium.h>

static_assert(ecc_aead_chacha20poly1305_NONCESIZE == crypto_aead_chacha20poly1305_IETF_NPUBBYTES, "");
static_assert(ecc_aead_chacha20poly1305_KEYSIZE == crypto_aead_chacha20poly1305_IETF_KEYBYTES, "");
static_assert(ecc_aead_chacha20poly1305_MACSIZE == crypto_aead_chacha20poly1305_IETF_ABYTES, "");

void ecc_aead_chacha20poly1305_encrypt(
    byte_t *ciphertext,
    const byte_t *plaintext, int plaintext_len,
    const byte_t *ad, int ad_len,
    const byte_t *nonce,
    const byte_t *key
) {
    crypto_aead_chacha20poly1305_ietf_encrypt(
        ciphertext, NULL,
        plaintext, (unsigned long long) plaintext_len,
        ad, (unsigned long long) ad_len,
        NULL,
        nonce,
        key
    );
}

int ecc_aead_chacha20poly1305_decrypt(
    byte_t *plaintext,
    const byte_t *ciphertext, int ciphertext_len,
    const byte_t *ad, int ad_len,
    const byte_t *nonce,
    const byte_t *key
) {
    return crypto_aead_chacha20poly1305_ietf_decrypt(
        plaintext, NULL,
        NULL,
        ciphertext, (unsigned long long) ciphertext_len,
        ad, (unsigned long long) ad_len,
        nonce,
        key
    );
}
