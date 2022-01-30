/*
 * Copyright (c) 2021-2022, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#include "kdf.h"
#include <sodium.h>
#include <string.h>
#include <assert.h>

static_assert(ecc_kdf_hkdf_sha256_KEYSIZE == crypto_kdf_hkdf_sha256_KEYBYTES, "");
static_assert(ecc_kdf_hkdf_sha512_KEYSIZE == crypto_kdf_hkdf_sha512_KEYBYTES, "");

void ecc_kdf_hkdf_sha256_extract(
    byte_t *prk,
    const byte_t *salt, const int salt_len,
    const byte_t *ikm, const int ikm_len
) {
    crypto_kdf_hkdf_sha256_extract(
        prk,
        salt, (size_t) salt_len,
        ikm, (size_t) ikm_len
    );
}

void ecc_kdf_hkdf_sha256_expand(
    byte_t *okm,
    const byte_t *prk,
    const byte_t *info, const int info_len,
    int len
) {
    crypto_kdf_hkdf_sha256_expand(
        okm, (size_t) len,
        (const char *) info, (size_t) info_len,
        prk
    );
}

void ecc_kdf_hkdf_sha512_extract(
    byte_t *prk,
    const byte_t *salt, const int salt_len,
    const byte_t *ikm, const int ikm_len
) {
    crypto_kdf_hkdf_sha512_extract(
        prk,
        salt, (size_t) salt_len,
        ikm, (size_t) ikm_len
    );
}

void ecc_kdf_hkdf_sha512_expand(
    byte_t *okm,
    const byte_t *prk,
    const byte_t *info, const int info_len,
    const int len
) {
    crypto_kdf_hkdf_sha512_expand(
        okm, (size_t) len,
        (const char *) info, (size_t) info_len,
        prk
    );
}

int ecc_kdf_scrypt(
    byte_t *out,
    const byte_t *passphrase, const int passphrase_len,
    const byte_t *salt, const int salt_len,
    const int cost,
    const int block_size,
    const int parallelization,
    const int len
) {
    return crypto_pwhash_scryptsalsa208sha256_ll(
        passphrase, (size_t) passphrase_len,
        salt, (size_t) salt_len,
        (uint64_t) cost,
        (uint32_t) block_size,
        (uint32_t) parallelization,
        out, (size_t) len
    );
}
