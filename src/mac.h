/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#ifndef ECC_MAC_H
#define ECC_MAC_H

#include "export.h"

/**
 * Size of the HMAC-SHA-256 digest.
 */
#define ecc_mac_hmac_sha256_SIZE 32
/**
 * Size of a HMAC-SHA-256 key.
 */
#define ecc_mac_hmac_sha256_KEYSIZE 32

/**
 * Computes the HMAC-SHA-256 of the input stream.
 *
 * See https://datatracker.ietf.org/doc/html/rfc2104
 * See https://datatracker.ietf.org/doc/html/rfc4868
 *
 * @param digest (output) the HMAC-SHA-256 of the input
 * @param text the input message
 * @param text_len the length of `input`
 * @param key authentication key
 */
ECC_EXPORT
void ecc_mac_hmac_sha256(
    byte_t *digest,
    const byte_t *text, int text_len,
    const byte_t *key
);

/**
 * Size of the HMAC-SHA-512 digest.
 */
#define ecc_mac_hmac_sha512_SIZE 64
/**
 * Size of a HMAC-SHA-512 key.
 */
#define ecc_mac_hmac_sha256_KEYBYTES 32

/**
 * Computes the HMAC-SHA-512 of the input stream.
 *
 * See https://datatracker.ietf.org/doc/html/rfc2104
 * See https://datatracker.ietf.org/doc/html/rfc4868
 *
 * @param digest (output) the HMAC-SHA-512 of the input
 * @param text the input message
 * @param text_len the length of `input`
 * @param key authentication key
 */
ECC_EXPORT
void ecc_mac_hmac_sha512(
    byte_t *digest,
    const byte_t *text, int text_len,
    const byte_t *key
);

#endif // ECC_MAC_H
