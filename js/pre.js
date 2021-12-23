/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

import libecc_module from "./libecc.js";

/**
 * Generates a random message suitable to use in the protocol.
 *
 * The output can be used in other key derivation algorithms for other
 * symmetric encryption protocols.
 *
 * @return {Uint8Array} a random plaintext message
 */
export async function pre_schema1_MessageGen() {
    const libecc = await libecc_module();

    let m = new Uint8Array(libecc.ecc_pre_schema1_MESSAGESIZE);
    await libecc.ecc_pre_schema1_MessageGen(m);
    return m;
}

/**
 * Generate a public/private key pair.
 *
 * @return {object} a random public/private key pair
 */
export async function pre_schema1_KeyGen() {
    const libecc = await libecc_module();

    let pk = new Uint8Array(libecc.ecc_pre_schema1_PUBLICKEYSIZE);
    let sk = new Uint8Array(libecc.ecc_pre_schema1_PRIVATEKEYSIZE);
    await libecc.ecc_pre_schema1_KeyGen(pk, sk);
    return {pk: pk, sk: sk};
}

/**
 * Generate a signing public/private key pair.
 *
 * @return {object} a random signing public/private key pair
 */
export async function pre_schema1_SigningKeyGen() {
    const libecc = await libecc_module();

    let spk = new Uint8Array(libecc.ecc_pre_schema1_SIGNINGPUBLICKEYSIZE);
    let ssk = new Uint8Array(libecc.ecc_pre_schema1_SIGNINGPRIVATEKEYSIZE);
    await libecc.ecc_pre_schema1_SigningKeyGen(spk, ssk);
    return {spk: spk, ssk: ssk};
}

/**
 * Encrypt a message `m` to delegatee j, given j’s public key (pk_j) and the
 * sender i’s signing key pair (signing_i). Produces a ciphertext C_j.
 *
 * This is also called encryption of level 1, since it's used to encrypt to
 * itself (i.e j == i), in order to have later the ciphertext re-encrypted
 * by the proxy with the re-encryption key (level 2).
 *
 * @param {Uint8Array} m         the plaintext message
 * @param {Uint8Array} pk_j      delegatee's public key
 * @param {object} signing_i sender signing public/private key
 * @return a CiphertextLevel1_t structure
 */
export async function pre_schema1_Encrypt(
    m,
    pk_j,
    signing_i
) {
    const libecc = await libecc_module();

    let C_j_raw = new Uint8Array(libecc.ecc_pre_schema1_CIPHERTEXTLEVEL1SIZE);
    await libecc.ecc_pre_schema1_Encrypt(
        C_j_raw,
        m,
        pk_j,
        signing_i.spk,
        signing_i.ssk
    );
    return C_j_raw;
}

/**
 * Generate a re-encryption key from user i (the delegator) to user j (the delegatee).
 *
 * Requires the delegator’s private key (sk_i), the delegatee’s public key (pk_j), and
 * the delegator’s signing key pair (signing_i).
 *
 * @param {Uint8Array} sk_i      delegator’s private key
 * @param {Uint8Array} pk_j      delegatee’s public key
 * @param {object} signing_i delegator’s signing public/private key
 * @return a ReKey_t structure
 */
export async function pre_schema1_ReKeyGen(
    sk_i,
    pk_j,
    signing_i
) {
    const libecc = await libecc_module();

    let tk_i_j_raw = new Uint8Array(libecc.ecc_pre_schema1_REKEYSIZE);
    await libecc.ecc_pre_schema1_ReKeyGen(
        tk_i_j_raw,
        sk_i,
        pk_j,
        signing_i.spk,
        signing_i.ssk
    );
    return tk_i_j_raw;
}

/**
 * Re-encrypt a ciphertext encrypted to i (C_i) into a ciphertext encrypted
 * to j (C_j), given a re-encryption key (tk_i_j) and the proxy’s signing key
 * pair (spk, ssk).
 *
 * This operation is performed by the proxy and is also called encryption of
 * level 2, since it takes a ciphertext from a level 1 and re-encrypt it.
 *
 * It also validate the signature on the encrypted ciphertext and re-encryption key.
 *
 * @param {Uint8Array} C_i_raw    a CiphertextLevel1_t structure
 * @param {Uint8Array} tk_i_j_raw a ReKey_t structure
 * @param {Uint8Array} spk_i      delegator’s signing public key
 * @param {Uint8Array} pk_j       delegatee’s public key
 * @param {object} signing    proxy’s signing public/private key
 * @return {Uint8Array} a CiphertextLevel2_t structure if all the signatures are
 * valid, null if there is an error
 */
export async function pre_schema1_ReEncrypt(
    C_i_raw,
    tk_i_j_raw,
    spk_i,
    pk_j,
    signing
) {
    const libecc = await libecc_module();

    let C_j_raw = new Uint8Array(libecc.ecc_pre_schema1_CIPHERTEXTLEVEL2SIZE);
    const r = await libecc.ecc_pre_schema1_ReEncrypt(
        C_j_raw,
        C_i_raw,
        tk_i_j_raw,
        spk_i,
        pk_j,
        signing.spk,
        signing.ssk
    );
    return r === 0 ? C_j_raw : null;
}

/**
 * Decrypt a signed ciphertext (C_i) given the private key of the recipient
 * i (sk_i). Returns the original message that was encrypted, m.
 *
 * This operations is usually performed by the delegator, since it encrypted
 * the message just to be stored and later be re-encrypted by the proxy.
 *
 * It also validate the signature on the encrypted ciphertext.
 *
 * @param {Uint8Array} C_i_raw a CiphertextLevel1_t structure
 * @param {Uint8Array} sk_i    recipient private key
 * @param {Uint8Array} spk_i   recipient signing public key
 * @return {Uint8Array} the original plaintext message if all the signatures are
 * valid, null if there is an error
 */
export async function pre_schema1_DecryptLevel1(
    C_i_raw,
    sk_i,
    spk_i
) {
    const libecc = await libecc_module();

    let m = new Uint8Array(libecc.ecc_pre_schema1_MESSAGESIZE);
    const r = await libecc.ecc_pre_schema1_DecryptLevel1(
        m,
        C_i_raw,
        sk_i,
        spk_i
    );
    return r === 0 ? m : null;
}

/**
 * Decrypt a signed ciphertext (C_j) given the private key of the recipient
 * j (sk_j). Returns the original message that was encrypted, m.
 *
 * This operations is usually performed by the delegatee, since it is the proxy
 * that re-encrypt the message and send the ciphertext to the final recipient.
 *
 * It also validate the signature on the encrypted ciphertext.
 *
 * @param {Uint8Array} C_j_raw a CiphertextLevel2_t structure
 * @param {Uint8Array} sk_j    recipient private key
 * @param {Uint8Array} spk     proxy’s signing public key
 * @return {Uint8Array} the original plaintext message if all the signatures are
 * valid, null if there is an error
 */
export async function pre_schema1_DecryptLevel2(
    C_j_raw,
    sk_j,
    spk
) {
    const libecc = await libecc_module();

    let m = new Uint8Array(libecc.ecc_pre_schema1_MESSAGESIZE);
    const r = await libecc.ecc_pre_schema1_DecryptLevel2(
        m,
        C_j_raw,
        sk_j,
        spk
    );
    return r === 0 ? m : null;
}
