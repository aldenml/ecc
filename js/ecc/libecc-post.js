
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
    arraycopy(HEAPU8, pP, p, 0, 32);
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

// sign

/**
 * @param {Uint8Array} pk 32 bytes
 * @param {Uint8Array} sk 64 bytes
 * @returns {number}
 */
Module.ecc_sign_ed25519_keypair = (pk, sk) => {
    const pPk = 0;
    const pSk = pPk + 32;

    const op = _ecc_sign_ed25519_keypair(pPk, pSk);
    arraycopy(HEAPU8, pPk, pk, 0, 32);
    arraycopy(HEAPU8, pSk, sk, 0, 64);
    return op;
}

/**
 * @param {Uint8Array} pk 32 bytes
 * @param {Uint8Array} sk 64 bytes
 * @param {Uint8Array} seed 32 bytes
 * @returns {number}
 */
Module.ecc_sign_ed25519_seed_keypair = (pk, sk, seed) => {
    arraycopy(seed, 0, HEAPU8, 0, 32);

    const pSeed = 0;
    const pPk = pSeed + 32;
    const pSk = pPk + 32;

    const op = _ecc_sign_ed25519_seed_keypair(pPk, pSk, pSeed);
    arraycopy(HEAPU8, pPk, pk, 0, 32);
    arraycopy(HEAPU8, pSk, sk, 0, 64);
    return op;
}

/**
 * @param {Uint8Array} curve25519_sk 32 bytes
 * @param {Uint8Array} ed25519_sk 32 bytes
 * @returns {number}
 */
Module.ecc_sign_ed25519_sk_to_curve25519 = (curve25519_sk, ed25519_sk) => {
    arraycopy(ed25519_sk, 0, HEAPU8, 0, 32);

    const pEd25519_sk = 0;
    const pCurve25519_sk = pEd25519_sk + 32;

    const op = _ecc_sign_ed25519_seed_keypair(pCurve25519_sk, pEd25519_sk);
    arraycopy(HEAPU8, pCurve25519_sk, curve25519_sk, 0, 32);
    return op;
}

// bls12_381

/**
 * @param {Uint8Array} out_SK 32 bytes
 * @param {Uint8Array} IKM
 * * @param {Uint8Array} IKM_len >= 32
 * @returns {number}
 */
Module.ecc_bls12_381_keygen = (out_SK, IKM, IKM_len) => {
    arraycopy(IKM, 0, HEAPU8, 0, IKM_len);

    const pIKM = 0;
    const pOut_SK = pIKM + IKM_len;

    _ecc_bls12_381_keygen(pOut_SK, pIKM, IKM_len);
    arraycopy(HEAPU8, pOut_SK, out_SK, 0, 32);
}
