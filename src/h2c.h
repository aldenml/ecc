/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#ifndef ECC_H2C_H
#define ECC_H2C_H

#include "export.h"

// Hashing to Elliptic Curves
// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-11

#define ecc_h2c_expand_message_xmd_sha512_MAXSIZE 256
#define ecc_h2c_expand_message_xmd_sha512_DSTMAXSIZE 256

// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-11#section-5.4.1
/**
 * In order to make this method to use only the stack, len should be <= 256.
 *
 * @param out
 * @param msg
 * @param msg_len
 * @param dst
 * @param dst_len should be <= 256
 * @param len should be <= 256
 */
ECC_OPRF_EXPORT
ECC_OPAQUE_EXPORT
ECC_EXPORT
void ecc_h2c_expand_message_xmd_sha512(
    byte_t *out,
    const byte_t *msg, int msg_len,
    const byte_t *dst, int dst_len,
    int len
);

#endif // ECC_H2C_H