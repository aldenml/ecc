/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#ifndef ECC_KDF_H
#define ECC_KDF_H

#include "export.h"

// const
/**
 * Key size for HKDF-SHA-256.
 */
#define ecc_kdf_hkdf_sha256_KEYSIZE 32

/**
 * Computes the HKDF-SHA-256 extract of the input using a key material.
 *
 * See https://datatracker.ietf.org/doc/html/rfc5869
 *
 * @param[out] prk a pseudorandom key, size:ecc_kdf_hkdf_sha256_KEYSIZE
 * @param salt optional salt value (a non-secret random value), size:salt_len
 * @param salt_len the length of `salt`
 * @param ikm input keying material, size:ikm_len
 * @param ikm_len the length of `ikm`
 */
ECC_EXPORT
void ecc_kdf_hkdf_sha256_extract(
    byte_t *prk,
    const byte_t *salt, int salt_len,
    const byte_t *ikm, int ikm_len
);

/**
 * Computes the HKDF-SHA-256 expand of the input using a key.
 *
 * See https://datatracker.ietf.org/doc/html/rfc5869
 *
 * @param okm[out] output keying material of length `len`, size:len
 * @param prk a pseudorandom key, size:ecc_kdf_hkdf_sha256_KEYSIZE
 * @param info optional context and application specific information, size:info_len
 * @param info_len length of `info`
 * @param len length of output keying material in octets
 */
ECC_EXPORT
void ecc_kdf_hkdf_sha256_expand(
    byte_t *okm,
    const byte_t *prk,
    const byte_t *info, int info_len,
    int len
);

// const
/**
 * Key size for HKDF-SHA-512.
 */
#define ecc_kdf_hkdf_sha512_KEYSIZE 64

/**
 * Computes the HKDF-SHA-512 extract of the input using a key material.
 *
 * See https://datatracker.ietf.org/doc/html/rfc5869
 *
 * @param[out] prk a pseudorandom key, size:ecc_kdf_hkdf_sha512_KEYSIZE
 * @param salt optional salt value (a non-secret random value), size:salt_len
 * @param salt_len the length of `salt`
 * @param ikm input keying material, size:ikm_len
 * @param ikm_len the length of `ikm`
 */
ECC_EXPORT
void ecc_kdf_hkdf_sha512_extract(
    byte_t *prk,
    const byte_t *salt, int salt_len,
    const byte_t *ikm, int ikm_len
);

/**
 * Computes the HKDF-SHA-512 expand of the input using a key.
 *
 * See https://datatracker.ietf.org/doc/html/rfc5869
 *
 * @param[out] okm output keying material of length `len`, size:len
 * @param prk a pseudorandom key, size:ecc_kdf_hkdf_sha512_KEYSIZE
 * @param info optional context and application specific information, size:info_len
 * @param info_len length of `info`
 * @param len length of output keying material in octets
 */
ECC_EXPORT
void ecc_kdf_hkdf_sha512_expand(
    byte_t *okm,
    const byte_t *prk,
    const byte_t *info, int info_len,
    int len
);

#endif // ECC_KDF_H
