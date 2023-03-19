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
 * Computes the SHA-256 of a given input.
 *
 * See https://en.wikipedia.org/wiki/SHA-2
 *
 * @param {Uint8Array} input the input message
 * @return {Uint8Array} the SHA-256 of the input
 */
export function hash_sha256(
    input,
) {

    let digest = new Uint8Array(libecc.ecc_hash_sha256_HASHSIZE);
    libecc.ecc_hash_sha256(
        digest,
        input, input.length,
    );

    return digest;
}

/**
 * Computes the SHA-512 of a given input.
 *
 * See https://en.wikipedia.org/wiki/SHA-2
 *
 * @param {Uint8Array} input the input message
 * @return {Uint8Array} the SHA-512 of the input
 */
export function hash_sha512(
    input,
) {

    let digest = new Uint8Array(libecc.ecc_hash_sha512_HASHSIZE);
    libecc.ecc_hash_sha512(
        digest,
        input, input.length,
    );

    return digest;
}
