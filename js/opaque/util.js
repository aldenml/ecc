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
 * @param {string} s
 * @returns {Uint8Array}
 */
export function str2buf(s) {
    const encoder = new TextEncoder();
    return encoder.encode(s);
}

/**
 * Converts a byte array to the hex string.
 *
 * @param {Uint8Array} buffer
 * @returns {string}
 */
export function buf2hex(buffer) {
    return buffer.reduce((s, b) => s + b.toString(16).padStart(2, '0'), '');
}

/**
 * Converts an hex string to a byte array.
 *
 * @param {string} hex
 * @returns {Uint8Array}
 */
export function hex2buf(hex) {
    return new Uint8Array(hex.match(/.{1,2}/g).map(b => parseInt(b, 16)));
}

/**
 * Converts an hex string to a byte array.
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
 * The expand_message_xmd function produces a uniformly random byte
 * string using SHA-512.
 *
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-11#section-5.4.1
 *
 * @param {Uint8Array} msg a byte string
 * @param {Uint8Array} DST a byte string of at most 255 bytes
 * @param {number} len_in_bytes the length of the requested output in bytes
 * @return {Uint8Array} a byte string
 */
export async function expand_message_xmd_sha512(msg, DST, len_in_bytes) {
    const libecc = await libecc_module();

    let uniform_bytes = new Uint8Array(len_in_bytes);
    libecc.ecc_h2c_expand_message_xmd_sha512(uniform_bytes, msg, DST);
    return uniform_bytes;
}
