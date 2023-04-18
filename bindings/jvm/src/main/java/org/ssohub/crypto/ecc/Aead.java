/*
 * Copyright (c) 2023, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

package org.ssohub.crypto.ecc;

import static org.ssohub.crypto.ecc.libecc.*;

/**
 * Authenticated Encryption (AE) with additional authenticated data (AAD) or
 * associated data (AD) primitives.
 *
 * @author aldenml
 */
public final class Aead {

    private Aead() {
    }

    /**
     * Encrypt a plaintext message using ChaCha20-Poly1305.
     * <p>
     * See <a href="https://datatracker.ietf.org/doc/html/rfc8439">8439</a>
     *
     * @param plaintext the input message
     * @param aad       the associated additional authenticated data
     * @param nonce     public nonce, should never ever be reused with the same key, size:ecc_aead_chacha20poly1305_NONCESIZE
     * @param key       number of passes, size:ecc_aead_chacha20poly1305_KEYSIZE
     * @return the encrypted form of the input
     */
    public static Data chacha20poly1305Encrypt(
        Data plaintext,
        Data aad,
        Data nonce,
        Data key
    ) {
        if (nonce.size() != ecc_aead_chacha20poly1305_NONCESIZE)
            throw new IllegalArgumentException("nonce length should be ecc_aead_chacha20poly1305_NONCESIZE");
        if (key.size() != ecc_aead_chacha20poly1305_KEYSIZE)
            throw new IllegalArgumentException("key length should be ecc_aead_chacha20poly1305_KEYSIZE");

        byte[] plaintextBytes = plaintext.toBytes();
        byte[] aadBytes = aad.toBytes();
        byte[] nonceBytes = nonce.toBytes();
        byte[] keyBytes = key.toBytes();

        byte[] out = new byte[plaintextBytes.length + ecc_aead_chacha20poly1305_MACSIZE];

        ecc_aead_chacha20poly1305_encrypt(
            out,
            plaintextBytes, plaintextBytes.length,
            aadBytes, aadBytes.length,
            nonceBytes,
            keyBytes
        );

        return new Data(out);
    }

    /**
     * Decrypt a ciphertext message using ChaCha20-Poly1305.
     * <p>
     * See <a href="https://datatracker.ietf.org/doc/html/rfc8439">8439</a>
     *
     * @param ciphertext the input encrypted message
     * @param aad       the associated additional authenticated data
     * @param nonce     public nonce, should never ever be reused with the same key, size:ecc_aead_chacha20poly1305_NONCESIZE
     * @param key       number of passes, size:ecc_aead_chacha20poly1305_KEYSIZE
     * @return the decrypted form of the input or null if the verification fails.
     */
    public static Data chacha20poly1305Decrypt(
        Data ciphertext,
        Data aad,
        Data nonce,
        Data key
    ) {
        if (nonce.size() != ecc_aead_chacha20poly1305_NONCESIZE)
            throw new IllegalArgumentException("nonce length should be ecc_aead_chacha20poly1305_NONCESIZE");
        if (key.size() != ecc_aead_chacha20poly1305_KEYSIZE)
            throw new IllegalArgumentException("key length should be ecc_aead_chacha20poly1305_KEYSIZE");

        byte[] ciphertextBytes = ciphertext.toBytes();
        byte[] aadBytes = aad.toBytes();
        byte[] nonceBytes = nonce.toBytes();
        byte[] keyBytes = key.toBytes();

        byte[] out = new byte[ciphertextBytes.length - ecc_aead_chacha20poly1305_MACSIZE];

        int r = ecc_aead_chacha20poly1305_decrypt(
            out,
            ciphertextBytes, ciphertextBytes.length,
            aadBytes, aadBytes.length,
            nonceBytes,
            keyBytes
        );

        return r == 0 ? new Data(out) : null;
    }
}
