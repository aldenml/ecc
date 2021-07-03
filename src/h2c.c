/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#include "h2c.h"
#include <math.h>
#include <string.h>
#include <sodium.h>
#include "util.h"

void ecc_h2c_expand_message_xmd_sha512(
    byte_t *out,
    const byte_t *msg, const int msg_len,
    const byte_t *dst, const int dst_len,
    const int len
) {
    // from the irtf
    //
    // Parameters:
    // - H, a hash function (see requirements above).
    // - b_in_bytes, b / 8 for b the output size of H in bits.
    //   For example, for b = 256, b_in_bytes = 32.
    // - r_in_bytes, the input block size of H, measured in bytes (see
    //   discussion above). For example, for SHA-256, r_in_bytes = 64.
    //
    // in our case
    // - H = SHA-512
    // - b_in_bytes = 64
    // - r_in_bytes = 128

    const int b_in_bytes = 64;
    const int r_in_bytes = 128;

    const int len_in_bytes = len; // to keep the irtf naming convention

    // Steps:
    // 1.  ell = ceil(len_in_bytes / b_in_bytes)
    // 2.  ABORT if ell > 255
    // 3.  DST_prime = DST || I2OSP(len(DST), 1)
    // 4.  Z_pad = I2OSP(0, r_in_bytes)
    // 5.  l_i_b_str = I2OSP(len_in_bytes, 2)
    // 6.  msg_prime = Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime
    // 7.  b_0 = H(msg_prime)
    // 8.  b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
    // 9.  for i in (2, ..., ell):
    // 10.    b_i = H(strxor(b_0, b_(i - 1)) || I2OSP(i, 1) || DST_prime)
    // 11. uniform_bytes = b_1 || ... || b_ell
    // 12. return substr(uniform_bytes, 0, len_in_bytes)

    // step by step

    // 1.  ell = ceil(len_in_bytes / b_in_bytes)
    const int ell = ceil((double) len_in_bytes / b_in_bytes);

    // 2.  ABORT if ell > 255
    // never happens because len_in_bytes is required to be <= 256

    crypto_hash_sha512_state st;
    // the idea is to pass to the hash all the elements in the right order
    // in order to avoid dynamic memory allocation and string concatenation

    // 3.  DST_prime = DST || I2OSP(len(DST), 1)
    // 4.  Z_pad = I2OSP(0, r_in_bytes)
    // 5.  l_i_b_str = I2OSP(len_in_bytes, 2)
    // 6.  msg_prime = Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime
    // 7.  b_0 = H(msg_prime)
    crypto_hash_sha512_init(&st);
    byte_t Z_pad[128] = {0}; // r_in_bytes = 128
    // Z_pad = I2OSP(0, r_in_bytes)
    crypto_hash_sha512_update(&st, Z_pad, r_in_bytes);
    // msg
    crypto_hash_sha512_update(&st, msg, msg_len);
    // l_i_b_str = I2OSP(len_in_bytes, 2)
    byte_t l_i_b_str[2] = {0};
    ecc_I2OSP(l_i_b_str, len_in_bytes, 2);
    crypto_hash_sha512_update(&st, l_i_b_str, 2);
    // I2OSP(0, 1)
    byte_t tmp[1] = {0};
    ecc_I2OSP(tmp, 0, 1);
    crypto_hash_sha512_update(&st, tmp, 1);
    // DST_prime
    //  - DST
    crypto_hash_sha512_update(&st, dst, dst_len);
    //  - I2OSP(len(DST), 1)
    ecc_I2OSP(tmp, dst_len, 1);
    crypto_hash_sha512_update(&st, tmp, 1);
    // b_0 = H(msg_prime)
    byte_t b_0[64];
    crypto_hash_sha512_final(&st, b_0);

    // 8.  b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
    crypto_hash_sha512_init(&st);
    // b_0
    crypto_hash_sha512_update(&st, b_0, 64);
    // I2OSP(1, 1)
    ecc_I2OSP(tmp, 1, 1);
    crypto_hash_sha512_update(&st, tmp, 1);
    // DST_prime
    //  - DST
    crypto_hash_sha512_update(&st, dst, dst_len);
    //  - I2OSP(len(DST), 1)
    ecc_I2OSP(tmp, dst_len, 1);
    crypto_hash_sha512_update(&st, tmp, 1);
    // b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
    byte_t b_1[64];
    crypto_hash_sha512_final(&st, b_1);

    // 9.  for i in (2, ..., ell):
    // 10.    b_i = H(strxor(b_0, b_(i - 1)) || I2OSP(i, 1) || DST_prime)
    // 11. uniform_bytes = b_1 || ... || b_ell
    byte_t uniform_bytes[256] = {0};
    // 256 is the max, I'm using memory tricks here to work directly
    // on uniform_bytes and avoid temporary variables
    memcpy(uniform_bytes, b_1, 64);
    for (int i = 2; i <= ell; i++) {
        byte_t *b_prev = &uniform_bytes[(i - 2) * 64]; // b_(i - 1)
        byte_t *b_curr = &uniform_bytes[(i - 1) * 64]; // b_i
        crypto_hash_sha512_init(&st);
        // strxor(b_0, b_(i - 1))
        byte_t bxor[64];
        ecc_strxor(bxor, b_0, b_prev, 64);
        crypto_hash_sha512_update(&st, bxor, 64);
        // I2OSP(i, 1)
        ecc_I2OSP(tmp, i, 1);
        crypto_hash_sha512_update(&st, tmp, 1);
        // DST_prime
        //  - DST
        crypto_hash_sha512_update(&st, dst, dst_len);
        //  - I2OSP(len(DST), 1)
        ecc_I2OSP(tmp, dst_len, 1);
        crypto_hash_sha512_update(&st, tmp, 1);
        // b_i = H(strxor(b_0, b_(i - 1)) || I2OSP(i, 1) || DST_prime)
        crypto_hash_sha512_final(&st, b_curr);
    }

    // 12. return substr(uniform_bytes, 0, len_in_bytes)
    memcpy(out, uniform_bytes, len_in_bytes);

    // stack memory cleanup
    ecc_memzero((byte_t *) &st, sizeof st);
    ecc_memzero(uniform_bytes, sizeof uniform_bytes);
}
