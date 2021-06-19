
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

/**
 * @param {Uint8Array} a
 * @param {Uint8Array} b
 * @param {number} len
 * @returns {number}
 */
Module.ecc_compare = (a, b, len) => {
    arraycopy(a, 0, HEAPU8, 0, len);
    arraycopy(b, 0, HEAPU8, len, len);
    let pA = 0;
    let pB = len;
    return _ecc_compare(pA, pB, len);
}

/**
 * @param {Uint8Array} n
 * @param {number} len
 * @returns {number}
 */
Module.ecc_is_zero = (n, len) => {
    arraycopy(n, 0, HEAPU8, 0, len);
    let pN = 0;
    return _ecc_is_zero(pN, len);
}

/**
 * @param {Uint8Array} n
 * @param {number} len
 * @returns {number}
 */
Module.ecc_increment = (n, len) => {
    arraycopy(n, 0, HEAPU8, 0, len);
    let pN = 0;
    _ecc_increment(pN, len);
    arraycopy(HEAPU8, pN, n, 0, len);
}

/**
 * @param {Uint8Array} a
 * @param {Uint8Array} b
 * @param {number} len
 */
Module.ecc_add = (a, b, len) => {
    arraycopy(a, 0, HEAPU8, 0, len);
    arraycopy(b, 0, HEAPU8, len, len);
    let pA = 0;
    let pB = len;
    _ecc_add(pA, pB, len);
    arraycopy(HEAPU8, pA, a, 0, len);
}

/**
 * @param {Uint8Array} a
 * @param {Uint8Array} b
 * @param {number} len
 */
Module.ecc_sub = (a, b, len) => {
    arraycopy(a, 0, HEAPU8, 0, len);
    arraycopy(b, 0, HEAPU8, len, len);
    let pA = 0;
    let pB = len;
    _ecc_sub(pA, pB, len);
    arraycopy(HEAPU8, pA, a, 0, len);
}

// hash

/**
 * @param {Uint8Array} out
 * @param {Uint8Array} input
 */
Module.ecc_hash_sha256 = (out, input) => {
    arraycopy(input, 0, HEAPU8, 0, input.length);

    let pIn = 0;
    let len = input.length;
    let pOut = pIn + len;

    _ecc_hash_sha256(pOut, pIn, len);

    arraycopy(HEAPU8, pOut, out, 0, 32);
}

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

// ed25519

/**
 * @param {Uint8Array} p
 * @returns {number}
 */
Module.ecc_ed25519_is_valid_point = (p) => {
    arraycopy(p, 0, HEAPU8, 0, 32);
    const pP = 0;
    return _ecc_ed25519_is_valid_point(pP);
}

/**
 * @param {Uint8Array} p
 */
Module.ecc_ed25519_random = (p) => {
    const pP = 0;
    _ecc_ed25519_random(pP);
    arraycopy(HEAPU8, 0, p, 0, 32);
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
    arraycopy(HEAPU8, 0, r, 0, 64);
}

// scalarmult

/**
 * @param {Uint8Array} q
 * @param {Uint8Array} n
 * @param {Uint8Array} p
 * @returns {number}
 */
Module.ecc_scalarmult_ristretto255 = (q, n, p) => {
    arraycopy(n, 0, HEAPU8, 0, 64);
    arraycopy(p, 0, HEAPU8, 64, 32);

    const pN = 0;
    const pP = pN + 64;
    const pQ = pP + 32;

    const op = _ecc_scalarmult_ristretto255(pQ, pN, pP);
    arraycopy(HEAPU8, pQ, q, 0, 32);
    return op;
}
