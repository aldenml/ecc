/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#include "mac.h"
#include <sodium.h>

void ecc_mac_hmac_sha256(byte_t *digest, const byte_t *text, int text_len, const byte_t *key) {
    crypto_auth_hmacsha256(digest, text, text_len, key);
}

int ecc_mac_hmac_sha256_verify(const byte_t *digest, const byte_t *text, int text_len, const byte_t *key) {
    return crypto_auth_hmacsha256_verify(digest, text, text_len, key);
}

void ecc_mac_hmac_sha512(byte_t *digest, const byte_t *text, int text_len, const byte_t *key) {
    crypto_auth_hmacsha512(digest, text, text_len, key);
}

int ecc_mac_hmac_sha512_verify(const byte_t *digest, const byte_t *text, int text_len, const byte_t *key) {
    return crypto_auth_hmacsha512_verify(digest, text, text_len, key);
}
