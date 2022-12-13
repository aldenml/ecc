/*
 * Copyright (c) 2021-2022, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#ifndef ECC_H2C_H
#define ECC_H2C_H

#include "export.h"

// Hashing to Elliptic Curves
// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-16

// const
/**
 *
 */
#define ecc_h2c_expand_message_xmd_sha256_MAXSIZE 8160

// const
/**
 *
 */
#define ecc_h2c_expand_message_xmd_sha256_DSTMAXSIZE 255

/**
 * Produces a uniformly random byte string using SHA-256.
 *
 * @param[out] out a byte string, should be at least of size `len`, size:len
 * @param msg a byte string, size:msg_len
 * @param msg_len the length of `msg`
 * @param dst a byte string of at most 255 bytes, size:dst_len
 * @param dst_len the length of `dst`, should be <= ecc_h2c_expand_message_xmd_sha256_DSTMAXSIZE
 * @param len the length of the requested output in bytes, should be <= ecc_h2c_expand_message_xmd_sha256_MAXSIZE
 * @return 0 on success or -1 if arguments are out of range
 */
ECC_EXPORT
int ecc_h2c_expand_message_xmd_sha256(
    byte_t *out,
    const byte_t *msg, int msg_len,
    const byte_t *dst, int dst_len,
    int len
);

// const
/**
 *
 */
#define ecc_h2c_expand_message_xmd_sha512_MAXSIZE 16320

// const
/**
 *
 */
#define ecc_h2c_expand_message_xmd_sha512_DSTMAXSIZE 255

/**
 * Produces a uniformly random byte string using SHA-512.
 *
 * @param[out] out a byte string, should be at least of size `len`, size:len
 * @param msg a byte string, size:msg_len
 * @param msg_len the length of `msg`
 * @param dst a byte string of at most 255 bytes, size:dst_len
 * @param dst_len the length of `dst`, should be <= ecc_h2c_expand_message_xmd_sha512_DSTMAXSIZE
 * @param len the length of the requested output in bytes, should be <= ecc_h2c_expand_message_xmd_sha512_MAXSIZE
 * @return 0 on success or -1 if arguments are out of range
 */
ECC_EXPORT
int ecc_h2c_expand_message_xmd_sha512(
    byte_t *out,
    const byte_t *msg, int msg_len,
    const byte_t *dst, int dst_len,
    int len
);

#endif // ECC_H2C_H
