/**
 * Converts a string into a byte array using UTF-8 encoding.
 *
 * @param {string} s the input string
 * @return {Uint8Array} the UTF-8 encoding bytes
 */
export function str2bin(s: string): Uint8Array;
/**
 * Converts a byte array to the hex string.
 *
 * @param {Uint8Array} bin the input byte array
 * @return {string} the hex encoded string
 */
export function bin2hex(bin: Uint8Array): string;
/**
 * Converts an hex string to a byte array.
 *
 * @param {string} hex
 * @returns {Uint8Array}
 */
export function hex2bin(hex: string): Uint8Array;
/**
 * Returns a buffer of length `n` with an unpredictable sequence of bytes.
 *
 * @param {number} n the length of the buffer to return
 * @return {Promise<Uint8Array>} the buffer with random elements
 */
export function randombytes(n: number): Promise<Uint8Array>;
