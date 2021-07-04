/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

import libopaque_module from "./libopaque.js";

const libecc_module = libopaque_module;

/**
 * Converts a string into a byte array using UTF-8 encoding.
 *
 * @param {string} s the input string
 * @return {Uint8Array} the UTF-8 encoding bytes
 */
export function str2bin(s) {
    const encoder = new TextEncoder();
    return encoder.encode(s);
}

/**
 * Converts a byte array to the hex string.
 *
 * @param {Uint8Array} bin the input byte array
 * @return {string} the hex encoded string
 */
export function bin2hex(bin) {
    return bin.reduce((s, b) => s + b.toString(16).padStart(2, '0'), '');
}

/**
 * Converts an hex string to a byte array.
 *
 * @param {string} hex
 * @returns {Uint8Array}
 */
export function hex2bin(hex) {
    return new Uint8Array(hex.match(/.{1,2}/g).map(b => parseInt(b, 16)));
}

/**
 * Returns a buffer of length `n` with an unpredictable sequence of bytes.
 *
 * @param {number} n the length of the buffer to return
 * @return {Promise<Uint8Array>} the buffer with random elements
 */
export async function randombytes(n) {
    const libecc = await libecc_module();

    const buf = new Uint8Array(n);
    await libecc.ecc_randombytes(buf, n);

    return buf;
}
