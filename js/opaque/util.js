/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

/**
 * Converts a string into a byte array using UTF-8 encoding.
 *
 * @param {string} s
 * @return {Uint8Array}
 */
export function str2bin(s) {
    const encoder = new TextEncoder();
    return encoder.encode(s);
}

/**
 * Converts a byte array to the hex string.
 *
 * @param {Uint8Array} bin
 * @return {string}
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
