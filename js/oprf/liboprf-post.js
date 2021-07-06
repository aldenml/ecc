
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

// hash

/**
 * @param {Uint8Array} out
 * @param {Uint8Array} input
 */
Module.ecc_hash_sha512 = (out, input) => {
    arraycopy(input, 0, HEAPU8, 0, input.length);

    let pIn = 0;
    let len = input.length;
    let pOut = pIn + len;

    _ecc_hash_sha512(pOut, pIn, len);

    arraycopy(HEAPU8, pOut, out, 0, 64);
}

// ristretto255

/**
 * @param {Uint8Array} p
 * @param {Uint8Array} r
 * @returns {number}
 */
Module.ecc_ristretto255_from_hash = (p, r) => {
    arraycopy(r, 0, HEAPU8, 0, 64);
    const pR = 0;
    const pP = pR + 64;
    const op = _ecc_ristretto255_from_hash(pP, pR);
    arraycopy(HEAPU8, pP, p, 0, 32);
    return op;
}

/**
 * @param {Uint8Array} r
 */
Module.ecc_ristretto255_scalar_random = (r) => {
    const pR = 0;
    _ecc_ristretto255_scalar_random(pR);
    arraycopy(HEAPU8, 0, r, 0, 32);
}

/**
 * @param {Uint8Array} recip
 * @param {Uint8Array} s
 * @returns {number}
 */
Module.ecc_ristretto255_scalar_invert = (recip, s) => {
    arraycopy(s, 0, HEAPU8, 0, 32);
    const pS = 0;
    const pRecip = pS + 32;
    const op = _ecc_ristretto255_scalar_invert(pRecip, pS);
    arraycopy(HEAPU8, pRecip, recip, 0, 32);
    return op;
}

// scalarmult

/**
 * @param {Uint8Array} q
 * @param {Uint8Array} n
 * @param {Uint8Array} p
 * @returns {number}
 */
Module.ecc_ristretto255_scalarmult = (q, n, p) => {
    arraycopy(n, 0, HEAPU8, 0, 32);
    arraycopy(p, 0, HEAPU8, 32, 32);

    const pN = 0;
    const pP = pN + 32;
    const pQ = pP + 32;

    const op = _ecc_ristretto255_scalarmult(pQ, pN, pP);
    arraycopy(HEAPU8, pQ, q, 0, 32);
    return op;
}

// oprf

/**
 * Same as calling `ecc_oprf_ristretto255_sha512_Blind` with an
 * specified scalar blind.
 *
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-06#section-3.4.3.1
 *
 * @param {Uint8Array} blinded_element (output) blinded element
 * @param {Uint8Array} input message to blind
 * @param {number} input_len length of `input`
 * @param {Uint8Array} blind scalar to use in the blind operation
 */
Module.ecc_oprf_ristretto255_sha512_BlindWithScalar = (
    blinded_element, // 32
    input, input_len,
    blind // 32
) => {
    const pInput = mput(input, 0, input_len);
    const pBlind = mput(blind, pInput + input_len, 32);
    const pBlinded_element = pBlind + 32;

    _ecc_oprf_ristretto255_sha512_BlindWithScalar(
        pBlinded_element,
        pInput, input_len,
        pBlind
    );

    mget(pBlinded_element, blinded_element, 32);
    mzero(input_len + 32 + 32);
}

/**
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-06#section-3.4.3.1
 *
 * @param {Uint8Array} blinded_element (output) blinded element
 * @param {Uint8Array} blind (output) scalar used in the blind operation
 * @param {Uint8Array} input message to blind
 * @param {number} input_len length of `input`
 */
Module.ecc_oprf_ristretto255_sha512_Blind = (
    blinded_element, // 32
    blind, // 32
    input, input_len
) => {
    const pInput = mput(input, 0, input_len);
    const pBlinded_element = pInput + input_len;
    const pBlind = pBlinded_element + 32;

    _ecc_oprf_ristretto255_sha512_Blind(
        pBlinded_element,
        pBlind,
        pInput, input_len
    );

    mget(pBlinded_element, blinded_element, 32);
    mget(pBlind, blind, 32);
    mzero(input_len + 32 + 32);
}
