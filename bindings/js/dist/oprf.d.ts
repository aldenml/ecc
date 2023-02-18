/**
 * Evaluates serialized representations of blinded group elements from the
 * client as inputs.
 *
 * @param {Uint8Array} skS private key
 * @param {Uint8Array} blindedElement blinded element
 * @param {Uint8Array} info
 * @return {Uint8Array} evaluated element
 */
export function oprf_Evaluate(skS: Uint8Array, blindedElement: Uint8Array, info: Uint8Array): Uint8Array;
/**
 * Same as calling `oprf_Blind` with a
 * specified scalar blind.
 *
 * @param {Uint8Array} input message to blind
 * @param {Uint8Array} blind scalar to use in the blind operation
 * @return {Uint8Array} blinded element
 */
export function oprf_BlindWithScalar(input: Uint8Array, blind: Uint8Array): Uint8Array;
/**
 *
 * @param {Uint8Array} input message to blind
 * @return object {blind, blindedElement}
 */
export function oprf_Blind(input: Uint8Array): {
    blind: Uint8Array;
    blindedElement: Uint8Array;
};
/**
 *
 * @param input the input message
 * @param blind
 * @param evaluatedElement
 * @param {Uint8Array} info
 */
export function oprf_Finalize(input: any, blind: any, evaluatedElement: any, info: Uint8Array): Uint8Array;
