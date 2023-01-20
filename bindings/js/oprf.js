/*
 * Copyright (c) 2021-2023, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

import libecc_module from "./libecc.js";

/**
 * Evaluates serialized representations of blinded group elements from the
 * client as inputs.
 *
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-08#section-3.3.1.1
 *
 * @param {Uint8Array} skS private key
 * @param {Uint8Array} blindedElement blinded element
 * @param {Uint8Array} info
 * @return {Promise<Uint8Array>} evaluated element
 */
export async function oprf_ristretto255_sha512_Evaluate(skS, blindedElement, info) {
    const libecc = await libecc_module();

    let evaluatedElement = new Uint8Array(32);
    libecc.ecc_voprf_ristretto255_sha512_BlindEvaluate(
        evaluatedElement,
        skS,
        blindedElement,
    );

    return evaluatedElement;
}

/**
 * Same as calling `oprf_ristretto255_sha512_Blind` with an
 * specified scalar blind.
 *
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-08#section-3.3.3.1
 *
 * @param {Uint8Array} input message to blind
 * @param {Uint8Array} blind scalar to use in the blind operation
 * @return {Uint8Array} blinded element
 */
export async function oprf_ristretto255_sha512_BlindWithScalar(input, blind) {
    const libecc = await libecc_module();

    let blindedElement = new Uint8Array(32);

    await libecc.ecc_voprf_ristretto255_sha512_BlindWithScalar(
        blindedElement,
        input, input.length,
        blind,
        libecc.ecc_voprf_ristretto255_sha512_MODE_OPRF,
    );

    return blindedElement;
}

/**
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-08#section-3.3.3.1
 *
 * @param {Uint8Array} input message to blind
 * @return object {blind, blindedElement}
 */
export async function oprf_ristretto255_sha512_Blind(input) {
    const libecc = await libecc_module();

    let blindedElement = new Uint8Array(32);
    let blind = new Uint8Array(32);

    await libecc.ecc_voprf_ristretto255_sha512_Blind(
        blindedElement,
        blind,
        input, input.length,
        libecc.ecc_voprf_ristretto255_sha512_MODE_OPRF,
    );

    return {blind: blind, blindedElement: blindedElement};
}

/**
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-08#section-3.3.3.2
 *
 * @param input the input message
 * @param blind
 * @param evaluatedElement
 * @param {Uint8Array} info
 */
export async function oprf_ristretto255_sha512_Finalize(input, blind, evaluatedElement, info) {
    const libecc = await libecc_module();

    let output = new Uint8Array(64);
    libecc.ecc_voprf_ristretto255_sha512_Finalize(
        output,
        input, input.length,
        blind,
        evaluatedElement,
        info, info.length,
    );

    return output;
}
