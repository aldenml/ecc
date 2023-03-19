/**
 * Computes the SHA-256 of a given input.
 *
 * See https://en.wikipedia.org/wiki/SHA-2
 *
 * @param {Uint8Array} input the input message
 * @return {Uint8Array} the SHA-256 of the input
 */
export function hash_sha256(input: Uint8Array): Uint8Array;
/**
 * Computes the SHA-512 of a given input.
 *
 * See https://en.wikipedia.org/wiki/SHA-2
 *
 * @param {Uint8Array} input the input message
 * @return {Uint8Array} the SHA-512 of the input
 */
export function hash_sha512(input: Uint8Array): Uint8Array;
