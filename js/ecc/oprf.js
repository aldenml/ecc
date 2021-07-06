/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

import libecc_module from "./libecc.js";
import {
    I2OSP,
    str2bin,
    len,
    concat,
} from "./util.js";

// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-06#section-5.1

/**
 * @param {Uint8Array} input
 * @returns {Uint8Array}
 */
export async function oprf_ristretto255_sha512_HashToGroup(input) {

    const libecc = await libecc_module();

    // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-06#section-3.2
    // contextString = I2OSP(modeBase, 1) || I2OSP(suite.ID, 2)
    // modeBase = 0x00
    // suite id = 0x0001
    const contextString = concat(I2OSP(0x00, 1), I2OSP(0x0001, 2));

    // domain separation tag (DST)
    const DST = concat(str2bin("VOPRF06-HashToGroup-"), contextString);

    const expand_message = await expand_message_xmd_sha512(input, DST, 64);

    let buf = new Uint8Array(32);
    libecc.ecc_ristretto255_from_hash(buf, expand_message);

    return buf;
}

/**
 * Same as calling `oprf_ristretto255_sha512_Blind` with an
 * specified scalar blind.
 *
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-06#section-3.4.3.1
 *
 * @param {Uint8Array} input message to blind
 * @param {Uint8Array} blind scalar to use in the blind operation
 * @return {Uint8Array} blinded element
 */
export async function oprf_ristretto255_sha512_BlindWithScalar(input, blind) {
    const libecc = await libecc_module();

    let blindedElement = new Uint8Array(32);

    await libecc.ecc_oprf_ristretto255_sha512_BlindWithScalar(
        blindedElement,
        input, input.length,
        blind,
    );

    return blindedElement;
}

/**
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-06#section-3.4.3.1
 *
 * @param {Uint8Array} input message to blind
 * @return object {blind, blindedElement}
 */
export async function oprf_ristretto255_sha512_Blind(input) {
    const libecc = await libecc_module();

    let blindedElement = new Uint8Array(32);
    let blind = new Uint8Array(32);

    await libecc.ecc_oprf_ristretto255_sha512_BlindWithScalar(
        blindedElement,
        blind,
        input, input.length,
    );

    return {blind: blind, blindedElement: blindedElement};
}

/**
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-06#section-3.4.3.2
 *
 * @param {Uint8Array} blind
 * @param {Uint8Array} evaluatedElement
 * @returns {Uint8Array} unblindedElement
 */
export async function oprf_ristretto255_sha512_Unblind(blind, evaluatedElement) {
    const libecc = await libecc_module();

    // Z = GG.DeserializeElement(evaluatedElement)
    // N = (blind^(-1)) * Z
    // unblindedElement = GG.SerializeElement(N)
    let invertedBlind = new Uint8Array(32);
    libecc.ecc_ristretto255_scalar_invert(invertedBlind, blind);
    let unblindedElement = new Uint8Array(32);
    libecc.ecc_ristretto255_scalarmult(unblindedElement, invertedBlind, evaluatedElement);

    return unblindedElement;
}

/**
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-06#section-3.4.3.3
 *
 * @param {Uint8Array} input
 * @param {Uint8Array} blind
 * @param {Uint8Array} evaluatedElement
 * @returns {Uint8Array} opaque output
 */
export async function oprf_ristretto255_sha512_Finalize(input, blind, evaluatedElement) {
    const libecc = await libecc_module();

    // unblindedElement = Unblind(blind, evaluatedElement)
    //
    // finalizeDST = "VOPRF06-Finalize-" || self.contextString
    // hashInput = I2OSP(len(input), 2) || input ||
    //             I2OSP(len(unblindedElement), 2) || unblindedElement ||
    //             I2OSP(len(finalizeDST), 2) || finalizeDST
    // return Hash(hashInput)

    const unblindedElement = await oprf_ristretto255_sha512_Unblind(blind, evaluatedElement);

    // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-06#section-3.2
    // contextString = I2OSP(modeBase, 1) || I2OSP(suite.ID, 2)
    // modeBase = 0x00
    // suite id = 0x0001
    const contextString = concat(I2OSP(0x00, 1), I2OSP(0x0001, 2));

    // domain separation tag (DST)
    const finalizeDST = concat(str2bin("VOPRF06-Finalize-"), contextString);
    const hashInput = concat(I2OSP(len(input), 2), concat(input,
        concat(I2OSP(len(unblindedElement), 2), concat(unblindedElement,
            concat(I2OSP(len(finalizeDST), 2), finalizeDST)))));

    let output = new Uint8Array(64);
    libecc.ecc_hash_sha512(output, hashInput);
    return output;
}

/**
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-06#section-3.4.1.1
 *
 * @param {Uint8Array} skS
 * @param {Uint8Array} blindedElement
 * @returns {Uint8Array}
 */
export async function oprf_ristretto255_sha512_Evaluate(skS, blindedElement) {
    const libecc = await libecc_module();

    // R = GG.DeserializeElement(blindedElement)
    // Z = skS * R
    // evaluatedElement = GG.SerializeElement(Z)
    let evaluatedElement = new Uint8Array(32);
    libecc.ecc_ristretto255_scalarmult(evaluatedElement, skS, blindedElement);

    return evaluatedElement;
}
