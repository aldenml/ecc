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
 * @param {string} hex the input hex string
 * @return {Uint8Array} the byte array
 */
export function hex2bin(hex: string): Uint8Array;
/**
 * Converts a hex string to a byte array.
 *
 * @param {Uint8Array} buf
 * @returns {number}
 */
export function len(buf: Uint8Array): number;
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
export function concat(a: Uint8Array, b: Uint8Array): Uint8Array;
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
export function I2OSP(x: number, xLen: number): Uint8Array;
/**
 * OS2IP - Octet-String-to-Integer primitive.
 *
 * OS2IP converts an octet string to a nonnegative integer.
 * See https://datatracker.ietf.org/doc/html/rfc8017#section-4.2
 *
 * @param {Uint8Array} X octet string to be converted
 * @returns {number} corresponding nonnegative integer
 */
export function OS2IP(X: Uint8Array): number;
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
export function strxor(str1: Uint8Array, str2: Uint8Array): Uint8Array;
/**
 * Returns a buffer of length `n` with an unpredictable sequence of bytes.
 *
 * @param {number} n the length of the buffer to return
 * @return {Promise<Uint8Array>} the buffer with random elements
 */
export function randombytes(n: number): Promise<Uint8Array>;
