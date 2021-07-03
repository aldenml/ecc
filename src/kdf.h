/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#ifndef ECC_KDF_H
#define ECC_KDF_H

#include "export.h"

// https://datatracker.ietf.org/doc/html/rfc5869

#define ecc_kdf_hkdf_sha256_KEYSIZE 32

ECC_EXPORT
void ecc_kdf_hkdf_sha256_extract(
    byte_t *prk,
    const byte_t *salt, int salt_len,
    const byte_t *ikm, int ikm_len
);

ECC_EXPORT
void ecc_kdf_hkdf_sha256_expand(
    byte_t *okm,
    const byte_t *info, int info_len,
    const byte_t *prk,
    int len
);

#define ecc_kdf_hkdf_sha512_KEYSIZE 64

ECC_OPAQUE_EXPORT
ECC_EXPORT
void ecc_kdf_hkdf_sha512_extract(
    byte_t *prk,
    const byte_t *salt, int salt_len,
    const byte_t *ikm, int ikm_len
);

ECC_OPAQUE_EXPORT
ECC_EXPORT
void ecc_kdf_hkdf_sha512_expand(
    byte_t *okm,
    const byte_t *prk,
    const byte_t *info, int info_len,
    int len
);

#endif // ECC_KDF_H
