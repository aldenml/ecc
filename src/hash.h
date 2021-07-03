/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#ifndef ECC_HASH_H
#define ECC_HASH_H

#include "export.h"

// https://en.wikipedia.org/wiki/SHA-2

#define ecc_hash_sha256_SIZE 32

ECC_EXPORT
void ecc_hash_sha256(byte_t *digest, const byte_t *input, int input_len);

#define ecc_hash_sha512_SIZE 64

ECC_OPRF_EXPORT
ECC_OPAQUE_EXPORT
ECC_EXPORT
void ecc_hash_sha512(byte_t *digest, const byte_t *input, int input_len);

#endif // ECC_HASH_H
