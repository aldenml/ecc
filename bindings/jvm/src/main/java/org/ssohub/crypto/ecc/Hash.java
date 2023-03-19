/*
 * Copyright (c) 2023, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

package org.ssohub.crypto.ecc;

import static org.ssohub.crypto.ecc.libecc.*;

/**
 * Hash SHA-2 functions.
 *
 * @author aldenml
 */
public final class Hash {

    private Hash() {
    }

    /**
     * Computes the SHA-256 of a given input.
     * <p>
     * See <a href="https://en.wikipedia.org/wiki/SHA-2">SHA-2</a>
     *
     * @param input the input message
     * @return the SHA-256 of the input
     */
    public static Data sha256(Data input) {
        byte[] inputBytes = input.toBytes();

        byte[] digest = new byte[ecc_hash_sha256_HASHSIZE];

        ecc_hash_sha256(
            digest,
            inputBytes, inputBytes.length
        );

        return new Data(digest);
    }

    /**
     * Computes the SHA-512 of a given input.
     * <p>
     * See <a href="https://en.wikipedia.org/wiki/SHA-2">SHA-2</a>
     *
     * @param input the input message
     * @return the SHA-512 of the input
     */
    public static Data sha512(Data input) {
        byte[] inputBytes = input.toBytes();

        byte[] digest = new byte[ecc_hash_sha512_HASHSIZE];

        ecc_hash_sha512(
            digest,
            inputBytes, inputBytes.length
        );

        return new Data(digest);
    }
}
