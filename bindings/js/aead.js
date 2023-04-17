/*
 * Copyright (c) 2023, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

import {
    libecc,
} from "./util.js";

/**
 * Encrypt a plaintext message using ChaCha20-Poly1305.
 *
 * See https://datatracker.ietf.org/doc/html/rfc8439
 *
 * @param {Uint8Array} plaintext the input message
 * @param {Uint8Array} aad the associated additional authenticated data
 * @param {Uint8Array} nonce public nonce, should never ever be reused with the same key, size:ecc_aead_chacha20poly1305_NONCESIZE
 * @param {Uint8Array} key the secret key, size:ecc_aead_chacha20poly1305_KEYSIZE
 * @return {Uint8Array} the encrypted form of the input
 */
export function aead_chacha20poly1305_encrypt(
    plaintext,
    aad,
    nonce,
    key,
) {

    let out = new Uint8Array(plaintext.length + libecc.ecc_aead_chacha20poly1305_MACSIZE);
    libecc.ecc_aead_chacha20poly1305_encrypt(
        out,
        plaintext, plaintext.length,
        aad, aad.length,
        nonce,
        key,
    );

    return out;
}

/**
 * Decrypt a ciphertext message using ChaCha20-Poly1305.
 *
 * See https://datatracker.ietf.org/doc/html/rfc8439
 *
 * @param {Uint8Array} ciphertext the input encrypted message
 * @param {Uint8Array}  aad the associated additional authenticated data
 * @param {Uint8Array} nonce public nonce, should never ever be reused with the same key, size:ecc_aead_chacha20poly1305_NONCESIZE
 * @param {Uint8Array} key the secret key, size:ecc_aead_chacha20poly1305_KEYSIZE
 * @return {Uint8Array} the decrypted form of the input or null if the verification fails.
 */
export function aead_chacha20poly1305_decrypt(
    ciphertext,
    aad,
    nonce,
    key,
) {

    let out = new Uint8Array(ciphertext.length - libecc.ecc_aead_chacha20poly1305_MACSIZE);
    const r = libecc.ecc_aead_chacha20poly1305_decrypt(
        out,
        ciphertext, ciphertext.length,
        aad, aad.length,
        nonce,
        key,
    );

    return r === 0 ? out : null;
}
