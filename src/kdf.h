/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#ifndef ECC_KDF_H
#define ECC_KDF_H

#include "export.h"

#define ecc_kdf_hkdf_sha256_KEYSIZE 32U
#define ecc_kdf_hkdf_sha256_SIZE_MIN 0U
#define ecc_kdf_hkdf_sha256_SIZE_MAX (0xff * 32U)

ECC_EXPORT
int ecc_kdf_hkdf_sha256_extract(BYTE *prk, const BYTE *salt, int salt_len, const BYTE *ikm, int ikm_len);

ECC_EXPORT
void ecc_kdf_hkdf_sha256_keygen(BYTE *prk);

ECC_EXPORT
int ecc_kdf_hkdf_sha256_expand(BYTE *out, int out_len, const BYTE *ctx, int ctx_len, const BYTE *prk);

#define ecc_kdf_hkdf_sha512_KEYSIZE 64U
#define ecc_kdf_hkdf_sha512_SIZE_MIN 0U
#define ecc_kdf_hkdf_sha512_SIZE_MAX (0xff * 64U)

ECC_OPAQUE_EXPORT
ECC_EXPORT
int ecc_kdf_hkdf_sha512_extract(BYTE *prk, const BYTE *salt, int salt_len, const BYTE *ikm, int ikm_len);

ECC_OPAQUE_EXPORT
ECC_EXPORT
void ecc_kdf_hkdf_sha512_keygen(BYTE *prk);

ECC_OPAQUE_EXPORT
ECC_EXPORT
int ecc_kdf_hkdf_sha512_expand(BYTE *out, int out_len, const BYTE *ctx, int ctx_len, const BYTE *prk);

#endif // ECC_KDF_H
