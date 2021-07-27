/**
 * Evaluates serialized representations of blinded group elements from the
 * client as inputs.
 *
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-07#section-3.3.1.1
 *
 * @param {Uint8Array} skS private key
 * @param {Uint8Array} blindedElement blinded element
 * @return {Promise<Uint8Array>} evaluated element
 */
export function oprf_ristretto255_sha512_Evaluate(skS: Uint8Array, blindedElement: Uint8Array): Promise<Uint8Array>;
/**
 * Same as calling `oprf_ristretto255_sha512_Blind` with an
 * specified scalar blind.
 *
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-07#section-3.3.3.1
 *
 * @param {Uint8Array} input message to blind
 * @param {Uint8Array} blind scalar to use in the blind operation
 * @return {Uint8Array} blinded element
 */
export function oprf_ristretto255_sha512_BlindWithScalar(input: Uint8Array, blind: Uint8Array): Uint8Array;
/**
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-07#section-3.3.3.1
 *
 * @param {Uint8Array} input message to blind
 * @return object {blind, blindedElement}
 */
export function oprf_ristretto255_sha512_Blind(input: Uint8Array): Promise<{
    blind: Uint8Array;
    blindedElement: Uint8Array;
}>;
/**
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-07#section-3.3.3.2
 *
 * @param input the input message
 * @param blind
 * @param evaluatedElement
 */
export function oprf_ristretto255_sha512_Finalize(input: any, blind: any, evaluatedElement: any): Promise<Uint8Array>;
