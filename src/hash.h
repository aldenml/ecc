/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#ifndef ECC_HASH_H
#define ECC_HASH_H

#include "export.h"

#define ecc_hash_sha256_SIZE_CONST 32
/**
 * The size of a SHA-256 digest.
 */
static const int ecc_hash_sha256_SIZE = ecc_hash_sha256_SIZE_CONST;

/**
 * Computes the SHA-256 of a given input.
 *
 * See https://en.wikipedia.org/wiki/SHA-2
 *
 * @param[out] digest the SHA-256 of the input, size:ecc_hash_sha256_SIZE
 * @param input the input message, size:input_len
 * @param input_len the length of `input`
 */
ECC_EXPORT
void ecc_hash_sha256(byte_t *digest, const byte_t *input, int input_len);

#define ecc_hash_sha512_SIZE_CONST 64
/**
 * The size of a SHA-512 digest.
 */
static const int ecc_hash_sha512_SIZE = ecc_hash_sha512_SIZE_CONST;

/**
 * Computes the SHA-512 of a given input.
 *
 * See https://en.wikipedia.org/wiki/SHA-2
 *
 * @param[out] digest the SHA-512 of the input, size:ecc_hash_sha512_SIZE
 * @param input the input message, size:input_len
 * @param input_len the length of `input`
 */
ECC_EXPORT
void ecc_hash_sha512(byte_t *digest, const byte_t *input, int input_len);

#endif // ECC_HASH_H
