/*
 * Copyright (c) 2021-2022, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#include "hash.h"
#include <assert.h>

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

static_assert(ecc_hash_sha256_HASHSIZE == crypto_hash_sha256_BYTES, "");
static_assert(ecc_hash_sha512_HASHSIZE == crypto_hash_sha512_BYTES, "");

void ecc_hash_sha256(byte_t *digest, const byte_t *input, const int input_len) {
    crypto_hash_sha256(digest, input, (unsigned long long) input_len);
}

void ecc_hash_sha512(byte_t *digest, const byte_t *input, const int input_len) {
    crypto_hash_sha512(digest, input, (unsigned long long) input_len);
}
