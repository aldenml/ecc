/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#ifndef ECC_MAC_H
#define ECC_MAC_H

#include "export.h"

#define ecc_mac_hmac_sha256_SIZE 32
#define ecc_mac_hmac_sha256_KEYSIZE 32

ECC_EXPORT
void ecc_mac_hmac_sha256(byte_t *digest, const byte_t *text, int text_len, const byte_t *key);

ECC_EXPORT
int ecc_mac_hmac_sha256_verify(const byte_t *digest, const byte_t *text, int text_len, const byte_t *key);

#define ecc_mac_hmac_sha512_SIZE 64
#define ecc_mac_hmac_sha256_KEYBYTES 32

ECC_OPAQUE_EXPORT
ECC_EXPORT
void ecc_mac_hmac_sha512(byte_t *digest, const byte_t *text, int text_len, const byte_t *key);

ECC_EXPORT
int ecc_mac_hmac_sha512_verify(const byte_t *digest, const byte_t *text, int text_len, const byte_t *key);

#endif // ECC_MAC_H
