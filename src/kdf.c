/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#include "kdf.h"
#include <sodium.h>
#include <string.h>

// This code is a copy from:
//
// https://github.com/jedisct1/libsodium/blob/master/src/libsodium/crypto_kdf/hkdf/kdf_hkdf_sha256.c
// https://github.com/jedisct1/libsodium/blob/master/src/libsodium/crypto_kdf/hkdf/kdf_hkdf_sha512.c
//
// Can be replaced with a direct call once libsodium release the next stable version with the code
// in master.

void ecc_kdf_hkdf_sha256_extract(
    byte_t *prk,
    const byte_t *salt, int salt_len,
    const byte_t *ikm, int ikm_len
) {
    crypto_auth_hmacsha256_state st;

    crypto_auth_hmacsha256_init(&st, salt, salt_len);
    crypto_auth_hmacsha256_update(&st, ikm, ikm_len);
    crypto_auth_hmacsha256_final(&st, prk);
    sodium_memzero(&st, sizeof st);

//    return 0;
}

void ecc_kdf_hkdf_sha256_expand(
    byte_t *okm,
    const byte_t *info, int info_len,
    const byte_t *prk,
    int len
) {
    crypto_auth_hmacsha256_state st;
    unsigned char tmp[crypto_auth_hmacsha256_BYTES];
    size_t i;
    size_t left;
    unsigned char counter = 1U;

//    if (out_len > ecc_kdf_hkdf_sha256_SIZE_MAX) {
//        errno = EINVAL;
//        return -1;
//    }
    for (i = (size_t) 0U; i + crypto_auth_hmacsha256_BYTES <= len;
         i += crypto_auth_hmacsha256_BYTES) {
        crypto_auth_hmacsha256_init(&st, prk, ecc_kdf_hkdf_sha256_KEYSIZE);
        if (i != (size_t) 0U) {
            crypto_auth_hmacsha256_update(&st,
                                          &okm[i - crypto_auth_hmacsha256_BYTES],
                                          crypto_auth_hmacsha256_BYTES);
        }
        crypto_auth_hmacsha256_update(&st,
                                      (const unsigned char *) info, info_len);
        crypto_auth_hmacsha256_update(&st, &counter, (size_t) 1U);
        crypto_auth_hmacsha256_final(&st, &okm[i]);
        counter++;
    }
    if ((left = len & (crypto_auth_hmacsha256_BYTES - 1U)) != (size_t) 0U) {
        crypto_auth_hmacsha256_init(&st, prk, ecc_kdf_hkdf_sha256_KEYSIZE);
        if (i != (size_t) 0U) {
            crypto_auth_hmacsha256_update(&st,
                                          &okm[i - crypto_auth_hmacsha256_BYTES],
                                          crypto_auth_hmacsha256_BYTES);
        }
        crypto_auth_hmacsha256_update(&st,
                                      (const unsigned char *) info, info_len);
        crypto_auth_hmacsha256_update(&st, &counter, (size_t) 1U);
        crypto_auth_hmacsha256_final(&st, tmp);
        memcpy(&okm[i], tmp, left);
        sodium_memzero(tmp, sizeof tmp);
    }
    sodium_memzero(&st, sizeof st);

//    return 0;
}

void ecc_kdf_hkdf_sha512_extract(
    byte_t *prk,
    const byte_t *salt, int salt_len,
    const byte_t *ikm, int ikm_len
) {
    crypto_auth_hmacsha512_state st;

    crypto_auth_hmacsha512_init(&st, salt, salt_len);
    crypto_auth_hmacsha512_update(&st, ikm, ikm_len);
    crypto_auth_hmacsha512_final(&st, prk);
    sodium_memzero(&st, sizeof st);

//    return 0;
}

void ecc_kdf_hkdf_sha512_expand(
    byte_t *okm,
    const byte_t *prk,
    const byte_t *info, const int info_len,
    const int len
) {
    crypto_auth_hmacsha512_state st;
    unsigned char tmp[crypto_auth_hmacsha512_BYTES];
    size_t i;
    size_t left;
    unsigned char counter = 1U;

//    if (len > ecc_kdf_hkdf_sha512_SIZE_MAX) {
//        errno = EINVAL;
//        return -1;
//    }
    for (i = (size_t) 0U; i + crypto_auth_hmacsha512_BYTES <= len;
         i += crypto_auth_hmacsha512_BYTES) {
        crypto_auth_hmacsha512_init(&st, prk, ecc_kdf_hkdf_sha512_KEYSIZE);
        if (i != (size_t) 0U) {
            crypto_auth_hmacsha512_update(&st,
                                          &okm[i - crypto_auth_hmacsha512_BYTES],
                                          crypto_auth_hmacsha512_BYTES);
        }
        crypto_auth_hmacsha512_update(&st,
                                      (const unsigned char *) info, info_len);
        crypto_auth_hmacsha512_update(&st, &counter, (size_t) 1U);
        crypto_auth_hmacsha512_final(&st, &okm[i]);
        counter++;
    }
    if ((left = len & (crypto_auth_hmacsha512_BYTES - 1U)) != (size_t) 0U) {
        crypto_auth_hmacsha512_init(&st, prk, ecc_kdf_hkdf_sha512_KEYSIZE);
        if (i != (size_t) 0U) {
            crypto_auth_hmacsha512_update(&st,
                                          &okm[i - crypto_auth_hmacsha512_BYTES],
                                          crypto_auth_hmacsha512_BYTES);
        }
        crypto_auth_hmacsha512_update(&st,
                                      (const unsigned char *) info, info_len);
        crypto_auth_hmacsha512_update(&st, &counter, (size_t) 1U);
        crypto_auth_hmacsha512_final(&st, tmp);
        memcpy(&okm[i], tmp, left);
        sodium_memzero(tmp, sizeof tmp);
    }
    sodium_memzero(&st, sizeof st);

//    return 0;
}
