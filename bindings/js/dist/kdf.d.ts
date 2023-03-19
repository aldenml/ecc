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
export function kdf_argon2id(passphrase: Uint8Array, salt: Uint8Array, memorySize: number, iterations: number, len: number): Uint8Array;
