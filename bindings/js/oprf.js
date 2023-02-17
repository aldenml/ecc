/*
 * Copyright (c) 2021-2023, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

import {
    libecc,
} from "./util.js";

/**
 * Evaluates serialized representations of blinded group elements from the
 * client as inputs.
 *
 * @param {Uint8Array} skS private key
 * @param {Uint8Array} blindedElement blinded element
 * @param {Uint8Array} info
 * @return {Uint8Array} evaluated element
 */
export function oprf_Evaluate(skS, blindedElement, info) {

    let evaluatedElement = new Uint8Array(32);
    libecc.ecc_voprf_ristretto255_sha512_BlindEvaluate(
        evaluatedElement,
        skS,
        blindedElement,
    );

    return evaluatedElement;
}

/**
 * Same as calling `oprf_Blind` with a
 * specified scalar blind.
 *
 * @param {Uint8Array} input message to blind
 * @param {Uint8Array} blind scalar to use in the blind operation
 * @return {Uint8Array} blinded element
 */
export function oprf_BlindWithScalar(input, blind) {

    let blindedElement = new Uint8Array(32);

    libecc.ecc_voprf_ristretto255_sha512_BlindWithScalar(
        blindedElement,
        input, input.length,
        blind,
        libecc.ecc_voprf_ristretto255_sha512_MODE_OPRF,
    );

    return blindedElement;
}

/**
 *
 * @param {Uint8Array} input message to blind
 * @return object {blind, blindedElement}
 */
export function oprf_Blind(input) {

    let blindedElement = new Uint8Array(32);
    let blind = new Uint8Array(32);

    libecc.ecc_voprf_ristretto255_sha512_Blind(
        blindedElement,
        blind,
        input, input.length,
        libecc.ecc_voprf_ristretto255_sha512_MODE_OPRF,
    );

    return {blind: blind, blindedElement: blindedElement};
}

/**
 *
 * @param input the input message
 * @param blind
 * @param evaluatedElement
 * @param {Uint8Array} info
 */
export function oprf_Finalize(input, blind, evaluatedElement, info) {

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
