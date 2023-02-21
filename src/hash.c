/*
 * Copyright (c) 2021-2023, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#include "hash.h"
#include <assert.h>
#include <sodium.h>

static_assert(ecc_hash_sha256_HASHSIZE == crypto_hash_sha256_BYTES, "");
static_assert(ecc_hash_sha512_HASHSIZE == crypto_hash_sha512_BYTES, "");

void ecc_hash_sha256(byte_t *digest, const byte_t *input, const int input_len) {
    crypto_hash_sha256(digest, input, (unsigned long long) input_len);
}

void ecc_hash_sha512(byte_t *digest, const byte_t *input, const int input_len) {
    crypto_hash_sha512(digest, input, (unsigned long long) input_len);
}
