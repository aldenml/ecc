/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#ifndef ECC_MAC_H
#define ECC_MAC_H

#include "export.h"

#define ecc_mac_hmac_sha256_KEYSIZE 32U
#define ecc_mac_hmac_sha256_SIZE 32U

ECC_EXPORT
void ecc_mac_hmac_sha256_keygen(BYTE *k);

ECC_EXPORT
int ecc_mac_hmac_sha256(BYTE *out, const BYTE *in, int inlen, const BYTE *k);

ECC_EXPORT
int ecc_mac_hmac_sha256_verify(const BYTE *h, const BYTE *in, int inlen, const BYTE *k);

#define ecc_mac_hmac_sha512_KEYSIZE 32U
#define ecc_mac_hmac_sha512_SIZE 64U

ECC_OPAQUE_EXPORT
ECC_EXPORT
void ecc_mac_hmac_sha512_keygen(BYTE *k);

ECC_OPAQUE_EXPORT
ECC_EXPORT
int ecc_mac_hmac_sha512(BYTE *out, const BYTE *in, int inlen, const BYTE *k);

ECC_OPAQUE_EXPORT
ECC_EXPORT
int ecc_mac_hmac_sha512_verify(const BYTE *h, const BYTE *in, int inlen, const BYTE *k);

#define ecc_mac_hmac_sha512256_KEYSIZE 32U
#define ecc_mac_hmac_sha512256_SIZE 32U

ECC_EXPORT
void ecc_mac_hmac_sha512256_keygen(BYTE *k);

ECC_EXPORT
int ecc_mac_hmac_sha512256(BYTE *out, const BYTE *in, int inlen, const BYTE *k);

ECC_EXPORT
int ecc_mac_hmac_sha512256_verify(const BYTE *h, const BYTE *in, int inlen, const BYTE *k);

#endif // ECC_MAC_H
