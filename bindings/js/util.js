/*
 * Copyright (c) 2021-2023, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

import libecc_module from "./libecc.js";

export const libecc_promise = libecc_module();

export var libecc = null;

libecc_promise.then((module) => {
    libecc = module;
});

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
 * @param {string} hex the input hex string
 * @return {Uint8Array} the byte array
 */
export function hex2bin(hex) {
    if (hex.length === 0)
        return new Uint8Array(0);
    return new Uint8Array(hex.match(/.{1,2}/g).map(b => parseInt(b, 16)));
}

/**
 * Converts a hex string to a byte array.
 *
 * @param {Uint8Array} buf
 * @returns {number}
 */
export function len(buf) {
    return buf.length;
}

/**
 * Concatenates two byte arrays. Sames as a || b.
 *
 * a || b: denotes the concatenation of byte strings a and b. For
 * example, "ABC" || "DEF" == "ABCDEF".
 *
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-11#section-4
 *
 * @param {Uint8Array} a
 * @param {Uint8Array} b
 * @returns {Uint8Array}
 */
export function concat(a, b) {
    let buf = new Uint8Array(a.length + b.length);
    buf.set(a);
    buf.set(b, a.length);
    return buf;
}

// https://datatracker.ietf.org/doc/html/rfc8017

/**
 * I2OSP - Integer-to-Octet-String primitive.
 *
 * I2OSP converts a nonnegative integer to an octet string of a
 * specified length.
 * See https://datatracker.ietf.org/doc/html/rfc8017#section-4.1
 *
 * @param {number} x nonnegative integer to be converted
 * @param {number} xLen intended length of the resulting octet string
 * @returns {Uint8Array} corresponding octet string of length xLen
 */
export function I2OSP(x, xLen) {
    if (x < 0) throw "Integer must be positive";
    if (x >= 256 ** xLen) throw "Integer too large";

    let buf = new Uint8Array(xLen);
    for (let i = xLen - 1; i >= 0; i--) {
        buf[i] = x & 0xff;
        x = x >>> 8;
    }

    return buf;
}

/**
 * OS2IP - Octet-String-to-Integer primitive.
 *
 * OS2IP converts an octet string to a nonnegative integer.
 * See https://datatracker.ietf.org/doc/html/rfc8017#section-4.2
 *
 * @param {Uint8Array} X octet string to be converted
 * @returns {number} corresponding nonnegative integer
 */
export function OS2IP(X) {
    if (X.length > 4) throw "Invalid input length";

    let r = 0;
    for (let i = 0; i < X.length; i++) {
        r |= (X[i] & 0xff) << (8 * (X.length - 1 - i));
    }

    return r;
}

// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-11

/**
 * For byte strings str1 and str2, strxor(str1, str2) returns
 * the bitwise XOR of the two strings. For example,
 * strxor("abc", "XYZ") == "9;9" (the strings in this example are
 * ASCII literals, but strxor is defined for arbitrary byte strings).
 *
 * strxor is only applied to inputs of equal length.
 *
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-11#section-4
 *
 * @param {Uint8Array} str1
 * @param {Uint8Array} str2
 */
export function strxor(str1, str2) {
    if (str1.length !== str2.length) throw "Inputs should be of equal length";

    const len = str1.length;
    let buf = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        buf[i] = str1[i] ^ str2[i];
    }

    return buf;
}

/**
 * Returns a buffer of length `n` with an unpredictable sequence of bytes.
 *
 * @param {number} n the length of the buffer to return
 * @return {Uint8Array} the buffer with random elements
 */
export function randombytes(n) {
    const buf = new Uint8Array(n);
    libecc.ecc_randombytes(buf, n);
    return buf;
}
