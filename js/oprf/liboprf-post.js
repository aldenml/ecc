
/**
 * @param {Uint8Array} src
 * @param {number} srcPos
 * @param {Uint8Array} dest
 * @param {number} destPos
 * @param {number} length
 */
function arraycopy(src, srcPos, dest, destPos, length) {
    dest.set(src.subarray(srcPos, srcPos + length), destPos);
}

/**
 * @param {Uint8Array} src
 * @param {number} pos
 * @param {number} length
 * @return {number}
 */
function mput(src, pos, length) {
    arraycopy(src, 0, HEAPU8, pos, length);
    return pos;
}

/**
 * @param {number} pos
 * @param {Uint8Array} dest
 * @param {number} length
 */
function mget(pos, dest, length) {
    arraycopy(HEAPU8, pos, dest, 0, length);
}

/**
 * @param {number} length
 */
function mzero(length) {
    _ecc_memzero(0, length);
}

// util

/**
 * Fills `n` bytes at buf with an unpredictable sequence of bytes.
 *
 * @param {Uint8Array} buf (output) the byte array to fill
 * @param {number} n the number of bytes to fill
 */
Module.ecc_randombytes = (buf, n) => {
    const pBuf = 0;
    _ecc_randombytes(pBuf, n);
    mget(pBuf, buf, n);
    mzero(n);
}

// oprf

/**
 * Evaluates serialized representations of blinded group elements from the
 * client as inputs.
 *
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-06#section-3.4.1.1
 *
 * @param {Uint8Array} evaluatedElement (output) evaluated element
 * @param {Uint8Array} skS private key
 * @param {Uint8Array} blindedElement blinded element
 */
Module.ecc_oprf_ristretto255_sha512_Evaluate = (
    evaluatedElement, // 32
    skS, // 32
    blindedElement // 32
) => {
    const pSkS = mput(skS, 0, 32);
    const pBlindedElement = mput(blindedElement, pSkS + 32, 32);
    const pEvaluatedElement = pBlindedElement + 32;

    _ecc_oprf_ristretto255_sha512_Evaluate(
        pEvaluatedElement,
        pSkS,
        pBlindedElement
    );

    mget(pEvaluatedElement, evaluatedElement, 32);
    mzero(32 + 32 + 32);
}

/**
 * Same as calling `ecc_oprf_ristretto255_sha512_Blind` with an
 * specified scalar blind.
 *
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-06#section-3.4.3.1
 *
 * @param {Uint8Array} blindedElement (output) blinded element
 * @param {Uint8Array} input message to blind
 * @param {number} input_len length of `input`
 * @param {Uint8Array} blind scalar to use in the blind operation
 */
Module.ecc_oprf_ristretto255_sha512_BlindWithScalar = (
    blindedElement, // 32
    input, input_len,
    blind // 32
) => {
    const pInput = mput(input, 0, input_len);
    const pBlind = mput(blind, pInput + input_len, 32);
    const pBlindedElement = pBlind + 32;

    _ecc_oprf_ristretto255_sha512_BlindWithScalar(
        pBlindedElement,
        pInput, input_len,
        pBlind
    );

    mget(pBlindedElement, blindedElement, 32);
    mzero(input_len + 32 + 32);
}

/**
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-06#section-3.4.3.1
 *
 * @param {Uint8Array} blindedElement (output) blinded element
 * @param {Uint8Array} blind (output) scalar used in the blind operation
 * @param {Uint8Array} input message to blind
 * @param {number} input_len length of `input`
 */
Module.ecc_oprf_ristretto255_sha512_Blind = (
    blindedElement, // 32
    blind, // 32
    input, input_len
) => {
    const pInput = mput(input, 0, input_len);
    const pBlindedElement = pInput + input_len;
    const pBlind = pBlindedElement + 32;

    _ecc_oprf_ristretto255_sha512_Blind(
        pBlindedElement,
        pBlind,
        pInput, input_len
    );

    mget(pBlindedElement, blindedElement, 32);
    mget(pBlind, blind, 32);
    mzero(input_len + 32 + 32);
}

/**
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-06#section-3.4.3.3
 *
 * @param {Uint8Array} output (output)
 * @param {Uint8Array} input the input message
 * @param {number} input_len the length of `blind`
 * @param {Uint8Array} blind
 * @param {Uint8Array} evaluatedElement
 * @param {number} mode mode to build the internal DST string (modeBase=0x00, modeVerifiable=0x01)
 */
Module.ecc_oprf_ristretto255_sha512_Finalize = (
    output,
    input, input_len,
    blind,
    evaluatedElement,
    mode
) => {
    const pInput = mput(input, 0, input_len);
    const pBlind = mput(blind, pInput + input_len, 32);
    const pEvaluatedElement = mput(evaluatedElement, pBlind + 32, 32);
    const pOutput = pEvaluatedElement + 32;

    _ecc_oprf_ristretto255_sha512_Finalize(
        pOutput,
        pInput, input_len,
        pBlind,
        pEvaluatedElement,
        mode
    );

    mget(pOutput, output, 64);
    mzero(input_len + 32 + 32 + 64);
}
