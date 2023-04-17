/**
 * Encrypt a plaintext message using ChaCha20-Poly1305.
 *
 * See https://datatracker.ietf.org/doc/html/rfc8439
 *
 * @param {Uint8Array} plaintext the input message
 * @param {Uint8Array} aad the associated additional authenticated data
 * @param {Uint8Array} nonce public nonce, should never ever be reused with the same key, size:ecc_aead_chacha20poly1305_NONCESIZE
 * @param {Uint8Array} key the secret key, size:ecc_aead_chacha20poly1305_KEYSIZE
 * @return {Uint8Array} the encrypted form of the input
 */
export function aead_chacha20poly1305_encrypt(plaintext: Uint8Array, aad: Uint8Array, nonce: Uint8Array, key: Uint8Array): Uint8Array;
/**
 * Decrypt a ciphertext message using ChaCha20-Poly1305.
 *
 * See https://datatracker.ietf.org/doc/html/rfc8439
 *
 * @param {Uint8Array} ciphertext the input encrypted message
 * @param {Uint8Array}  aad the associated additional authenticated data
 * @param {Uint8Array} nonce public nonce, should never ever be reused with the same key, size:ecc_aead_chacha20poly1305_NONCESIZE
 * @param {Uint8Array} key the secret key, size:ecc_aead_chacha20poly1305_KEYSIZE
 * @return {Uint8Array} the decrypted form of the input or null if the verification fails.
 */
export function aead_chacha20poly1305_decrypt(ciphertext: Uint8Array, aad: Uint8Array, nonce: Uint8Array, key: Uint8Array): Uint8Array;
