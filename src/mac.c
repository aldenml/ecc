/*
 * Copyright (c) 2021-2023, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#include "mac.h"
#include <sodium.h>
#include "util.h"

void ecc_mac_hmac_sha256(
    byte_t *digest,
    const byte_t *text, const int text_len,
    const byte_t *key, const int key_len
) {
    crypto_auth_hmacsha256_state st;

    crypto_auth_hmacsha256_init(&st, key, (size_t) key_len);
    crypto_auth_hmacsha256_update(&st, text, (unsigned long long) text_len);
    crypto_auth_hmacsha256_final(&st, digest);

    // stack memory cleanup
    ecc_memzero((byte_t *) &st, sizeof st);
}

void ecc_mac_hmac_sha512(
    byte_t *digest,
    const byte_t *text, const int text_len,
    const byte_t *key, const int key_len
) {
    crypto_auth_hmacsha512_state st;

    crypto_auth_hmacsha512_init(&st, key, (size_t) key_len);
    crypto_auth_hmacsha512_update(&st, text, (unsigned long long) text_len);
    crypto_auth_hmacsha512_final(&st, digest);

    // stack memory cleanup
    ecc_memzero((byte_t *) &st, sizeof st);
}
