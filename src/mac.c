/*
 * Copyright (c) 2021-2022, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#include "mac.h"
#include "util.h"

#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcpp"
#endif

#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wcpp"
#endif

#include <sodium.h>

#ifdef __clang__
#pragma clang diagnostic pop
#endif

#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

void ecc_mac_hmac_sha256(byte_t *digest, const byte_t *text, const int text_len, const byte_t *key) {
    crypto_auth_hmacsha256(digest, text, (unsigned long long) text_len, key);
}

void ecc_mac_hmac_sha512(byte_t *digest, const byte_t *text, const int text_len, const byte_t *key) {
    crypto_auth_hmacsha512_state st;

    crypto_auth_hmacsha512_init(&st, key, 64);
    crypto_auth_hmacsha512_update(&st, text, (unsigned long long) text_len);
    crypto_auth_hmacsha512_final(&st, digest);

    // stack memory cleanup
    ecc_memzero((byte_t *) &st, sizeof st);
}
