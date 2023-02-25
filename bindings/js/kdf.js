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
 * See https://datatracker.ietf.org/doc/html/rfc9106
 *
 * @param {Uint8Array} passphrase
 * @param {Uint8Array} salt, must be of size ecc_kdf_argon2id_SALTIZE
 * @param {number} memorySize amount of memory (in kibibytes) to use
 * @param {number} iterations number of passes
 * @param {number} len intended output length
 * @return {Uint8Array} the result or null if the computation didn't complete
 */
export function kdf_argon2id(
    passphrase,
    salt,
    memorySize,
    iterations,
    len,
) {

    let out = new Uint8Array(32);
    const r = libecc.ecc_kdf_argon2id(
        out,
        passphrase, passphrase.length,
        salt,
        memorySize,
        iterations,
        out.length,
    );

    return r === 0 ? out : null;
}
