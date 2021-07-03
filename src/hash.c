/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#include "hash.h"
#include <sodium.h>

void ecc_hash_sha256(byte_t *digest, const byte_t *input, int input_len) {
    crypto_hash_sha256(digest, input, input_len);
}

void ecc_hash_sha512(byte_t *digest, const byte_t *input, int input_len) {
    crypto_hash_sha512(digest, input, input_len);
}
