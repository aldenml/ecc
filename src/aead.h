/*
 * Copyright (c) 2023, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#ifndef ECC_AEAD_H
#define ECC_AEAD_H

#include "export.h"

// const
/**
 * Size of the ChaCha20-Poly1305 nonce.
 */
#define ecc_aead_chacha20poly1305_NONCESIZE 12

// const
/**
 * Size of the ChaCha20-Poly1305 private key.
 */
#define ecc_aead_chacha20poly1305_KEYSIZE 32

// const
/**
 * Size of the ChaCha20-Poly1305 authentication tag.
 */
#define ecc_aead_chacha20poly1305_MACSIZE 16

/**
 * Encrypt a plaintext message using ChaCha20-Poly1305.
 *
 * See https://datatracker.ietf.org/doc/html/rfc8439
 *
 * @param[out] ciphertext the encrypted form of the input, size:plaintext_len+ecc_aead_chacha20poly1305_MACSIZE
 * @param plaintext the input message, size:plaintext_len
 * @param plaintext_len the length of `plaintext`
 * @param aad the associated additional authenticated data, size:aad_len
 * @param aad_len the length of `aad`
 * @param nonce public nonce, should never ever be reused with the same key, size:ecc_aead_chacha20poly1305_NONCESIZE
 * @param key the secret key, size:ecc_aead_chacha20poly1305_KEYSIZE
 */
ECC_EXPORT
void ecc_aead_chacha20poly1305_encrypt(
    byte_t *ciphertext,
    const byte_t *plaintext, int plaintext_len,
    const byte_t *aad, int aad_len,
    const byte_t *nonce,
    const byte_t *key
);

/**
 * Decrypt a ciphertext message using ChaCha20-Poly1305.
 *
 * See https://datatracker.ietf.org/doc/html/rfc8439
 *
 * @param[out] plaintext the decrypted form of the input, size:ciphertext_len-ecc_aead_chacha20poly1305_MACSIZE
 * @param ciphertext the input encrypted message, size:ciphertext_len
 * @param ciphertext_len the length of `ciphertext`
 * @param aad the associated additional authenticated data, size:aad_len
 * @param aad_len the length of `aad`
 * @param nonce public nonce, should never ever be reused with the same key, size:ecc_aead_chacha20poly1305_NONCESIZE
 * @param key the secret key, size:ecc_aead_chacha20poly1305_KEYSIZE
 * @return 0 on success, or -1 if the verification fails.
 */
ECC_EXPORT
int ecc_aead_chacha20poly1305_decrypt(
    byte_t *plaintext,
    const byte_t *ciphertext, int ciphertext_len,
    const byte_t *aad, int aad_len,
    const byte_t *nonce,
    const byte_t *key
);

#endif // ECC_AEAD_H
