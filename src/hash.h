/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#ifndef ECC_HASH_H
#define ECC_HASH_H

#include "export.h"

/**
 * The size of a SHA-256 digest.
 */
#define ecc_hash_sha256_SIZE 32

/**
 * Computes the SHA-256 of a given input.
 *
 * See https://en.wikipedia.org/wiki/SHA-2
 *
 * @param digest (output) the SHA-256 of the input
 * @param input the input message
 * @param input_len the length of `input`
 */
ECC_EXPORT
void ecc_hash_sha256(byte_t *digest, const byte_t *input, int input_len);

/**
 * The size of a SHA-512 digest.
 */
#define ecc_hash_sha512_SIZE 64

/**
 * Computes the SHA-512 of a given input.
 *
 * See https://en.wikipedia.org/wiki/SHA-2
 *
 * @param digest (output) the SHA-512 of the input
 * @param input the input message
 * @param input_len the length of `input`
 */
ECC_EXPORT
void ecc_hash_sha512(byte_t *digest, const byte_t *input, int input_len);

#endif // ECC_HASH_H
