
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

// ecc

/**
 * @param {Uint8Array} buf
 */
Module.ecc_randombytes = (buf) => {
    let pBuf = 0;
    let n = buf.length;
    _ecc_randombytes(pBuf, n);
    arraycopy(HEAPU8, 0, buf, 0, n);
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
Module.ecc_scalarmult_ristretto255 = (q, n, p) => {
    arraycopy(n, 0, HEAPU8, 0, 32);
    arraycopy(p, 0, HEAPU8, 32, 32);

    const pN = 0;
    const pP = pN + 32;
    const pQ = pP + 32;

    const op = _ecc_scalarmult_ristretto255(pQ, pN, pP);
    arraycopy(HEAPU8, pQ, q, 0, 32);
    return op;
}
