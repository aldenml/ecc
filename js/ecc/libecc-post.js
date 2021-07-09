
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
 * Zero the array `buf` up to `len` elements.
 *
 * @param {Uint8Array} buf the byte array
 * @param {number} n the amount of elements to zero
 */
Module.ecc_memzero = (buf, n) => {
    for (let i = 0; i < n; i++)
        buf[i] = 0;
}

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

/**
 * Concatenates two byte arrays. Sames as a || b.
 *
 * a || b: denotes the concatenation of byte strings a and b. For
 * example, "ABC" || "DEF" == "ABCDEF".
 *
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-11#section-4
 *
 * @param {Uint8Array} out (output) result of the concatenation
 * @param {Uint8Array} a1 first byte array
 * @param {number} a1_len the length of `a1`
 * @param {Uint8Array} a2 second byte array
 * @param {number} a2_len the length of `a2`
 */
Module.ecc_concat2 = (
    out,
    a1, a1_len,
    a2, a2_len
) => {
    const pA1 = mput(a1, 0, a1_len);
    const pA2 = mput(a2, pA1 + a1_len, a2_len);
    const pOut = pA2 + a2_len;

    _ecc_concat2(pOut,
        pA1, a1_len,
        pA2, a2_len
    );

    mget(pOut, out, a1_len + a2_len);
    mzero(2 * (a1_len + a2_len));
}

/**
 * Same as calling ecc_concat2 but with three byte arrays.
 *
 * @param {Uint8Array} out (output) result of the concatenation
 * @param {Uint8Array} a1 first byte array
 * @param {number} a1_len the length of `a1`
 * @param {Uint8Array} a2 second byte array
 * @param {number} a2_len the length of `a2`
 * @param {Uint8Array} a3 third byte array
 * @param {number} a3_len the length of `a3`
 */
Module.ecc_concat3 = (
    out,
    a1, a1_len,
    a2, a2_len,
    a3, a3_len
) => {
    const pA1 = mput(a1, 0, a1_len);
    const pA2 = mput(a2, pA1 + a1_len, a2_len);
    const pA3 = mput(a3, pA2 + a2_len, a3_len);
    const pOut = pA3 + a3_len;

    _ecc_concat3(pOut,
        pA1, a1_len,
        pA2, a2_len,
        pA3, a3_len
    );

    mget(pOut, out, a1_len + a2_len + a3_len);
    mzero(2 * (a1_len + a2_len + a3_len));
}

/**
 * Same as calling ecc_concat2 but with four byte arrays.
 *
 * @param {Uint8Array} out (output) result of the concatenation
 * @param {Uint8Array} a1 first byte array
 * @param {number} a1_len the length of `a1`
 * @param {Uint8Array} a2 second byte array
 * @param {number} a2_len the length of `a2`
 * @param {Uint8Array} a3 third byte array
 * @param {number} a3_len the length of `a3`
 * @param {Uint8Array} a4 third byte array
 * @param {number} a4_len the length of `a3`
 */
Module.ecc_concat4 = (
    out,
    a1, a1_len,
    a2, a2_len,
    a3, a3_len,
    a4, a4_len
) => {
    const pA1 = mput(a1, 0, a1_len);
    const pA2 = mput(a2, pA1 + a1_len, a2_len);
    const pA3 = mput(a3, pA2 + a2_len, a3_len);
    const pA4 = mput(a4, pA3 + a3_len, a4_len);
    const pOut = pA4 + a4_len;

    _ecc_concat4(pOut,
        pA1, a1_len,
        pA2, a2_len,
        pA3, a3_len,
        pA4, a4_len
    );

    mget(pOut, out, a1_len + a2_len);
    mzero(2 * (a1_len + a2_len));
}

/**
 * For byte strings a and b, ecc_strxor(a, b) returns the bitwise XOR of
 * the two byte strings. For example, ecc_strxor("abc", "XYZ") == "9;9" (the
 * strings in this example are ASCII literals, but ecc_strxor is defined for
 * arbitrary byte strings).
 *
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-11#section-4
 *
 * @param {Uint8Array} out (output) result of the operation
 * @param {Uint8Array} a first byte array
 * @param {Uint8Array} b second byte array
 * @param {number} len length of both `a` and `b`
 */
Module.ecc_strxor = (out, a, b, len) => {
    const pA = mput(a, 0, len);
    const pB = mput(a, pA + len, len);
    const pOut = pB + len;

    _ecc_strxor(pOut, pA, pB, len);

    mget(pOut, out, len);
    mzero(len + len + len);
}

/**
 * I2OSP converts a nonnegative integer to an octet string of a
 * specified length.
 *
 * See https://datatracker.ietf.org/doc/html/rfc8017#section-4.1
 *
 * @param {Uint8Array} out (output) corresponding octet string of length xLen
 * @param {number} x nonnegative integer to be converted
 * @param {number} xLen intended length of the resulting octet string
 */
Module.ecc_I2OSP = (out, x, xLen) => {
    const pOut = 0;

    _ecc_I2OSP(pOut, x, xLen);

    mget(pOut, out, xLen);
    mzero(xLen);
}

/**
 * Takes two pointers to unsigned numbers encoded in little-endian
 * format and returns:
 *
 * -1 if a < b
 * 0 if a == b
 * 1 if a > b
 *
 * The comparison is done in constant time
 *
 * @param {Uint8Array} a first unsigned integer argument
 * @param {Uint8Array} b second unsigned integer argument
 * @param {number} len the length of both `a` and `b`
 */
Module.ecc_compare = (a, b, len) => {
    const pA = mput(a, 0, len);
    const pB = mput(b, pA + len, len);

    const r = _ecc_compare(pA, pB, len);

    mzero(len + len);
    return r;
}

/**
 * Takes a byte array and test if it contains only zeros. It runs
 * in constant-time.
 *
 * @param {Uint8Array} n the byte array
 * @param {number} len the length of `n`
 * @return 0 if non-zero bits are found
 */
Module.ecc_is_zero = (n, len) => {
    const pN = mput(n, 0, len);

    const r = _ecc_is_zero(pN, len);

    mzero(len);
    return r;
}

/**
 * Takes a pointer to an arbitrary-long unsigned integer encoded in
 * little-endian format, and increments it. It runs in constant-time.
 *
 * Can be used to increment nonces in constant time.
 *
 * @param {Uint8Array} n (input/output) unsigned integer
 * @param {number} len length of `n`
 */
Module.ecc_increment = (n, len) => {
    const pN = mput(n, 0, len);

    _ecc_increment(pN, len);

    mget(pN, n, len);
    mzero(len);
}

/**
 * Takes two pointers to unsigned numbers encoded in little-endian
 * format, computes (a + b) mod 2^(8*len) and store the result in `a`.
 * It runs in constant-time.
 *
 * @param {Uint8Array} a (input/output) first unsigned integer argument
 * @param {Uint8Array} b second unsigned integer argument
 * @param {number} len the length of both `a` and `b`
 */
Module.ecc_add = (a, b, len) => {
    const pA = mput(a, 0, len);
    const pB = mput(b, pA + len, len);

    _ecc_add(pA, pB, len);

    mget(pA, a, len);
    mzero(len + len);
}

/**
 * Takes two pointers to unsigned numbers encoded in little-endian
 * format, computes (a - b) mod 2^(8*len) and store the result in `a`.
 * It runs in constant-time.
 *
 * @param {Uint8Array} a (input/output) first unsigned integer argument
 * @param {Uint8Array} b second unsigned integer argument
 * @param {number} len the length of both `a` and `b`
 */
Module.ecc_sub = (a, b, len) => {
    const pA = mput(a, 0, len);
    const pB = mput(b, pA + len, len);

    _ecc_sub(pA, pB, len);

    mget(pA, a, len);
    mzero(len + len);
}

// hash

/**
 * Computes the SHA-256 of a given input.
 *
 * See https://en.wikipedia.org/wiki/SHA-2
 *
 * @param {Uint8Array} digest (output) the SHA-256 of the input
 * @param {Uint8Array} input the input message
 * @param {number} input_len the length of `input`
 */
Module.ecc_hash_sha256 = (digest, input, input_len) => {
    const pInput = mput(input, 0, input_len);
    const pDigest = pInput + input_len;

    _ecc_hash_sha256(pDigest, pInput, input_len);

    mget(pDigest, digest, 32);
    mzero(input_len + 32);
}

/**
 * Computes the SHA-512 of a given input.
 *
 * See https://en.wikipedia.org/wiki/SHA-2
 *
 * @param {Uint8Array} digest (output) the SHA-512 of the input
 * @param {Uint8Array} input the input message
 * @param {number} input_len the length of `input`
 */
Module.ecc_hash_sha512 = (digest, input, input_len) => {
    const pInput = mput(input, 0, input_len);
    const pDigest = pInput + input_len;

    _ecc_hash_sha512(pDigest, pInput, input_len);

    mget(pDigest, digest, 64);
    mzero(input_len + 64);
}

// mac

/**
 * Computes the HMAC-SHA-256 of the input stream.
 *
 * See https://datatracker.ietf.org/doc/html/rfc2104
 * See https://datatracker.ietf.org/doc/html/rfc4868
 *
 * @param {Uint8Array} digest (output) the HMAC-SHA-256 of the input
 * @param {Uint8Array} text the input message
 * @param {number} text_len the length of `input`
 * @param {Uint8Array} key authentication key
 */
Module.ecc_mac_hmac_sha256 = (
    digest,
    text, text_len,
    key
) => {
    const pText = mput(text, 0, text_len);
    const pKey = mput(key, pText + text_len, 32);
    const pDigest = pKey + 32;

    _ecc_mac_hmac_sha256(pDigest, pText, text_len, pKey);

    mget(pDigest, digest, 32);
    mzero(text_len + 32 + 32);
}

/**
 * Computes the HMAC-SHA-512 of the input stream.
 *
 * See https://datatracker.ietf.org/doc/html/rfc2104
 * See https://datatracker.ietf.org/doc/html/rfc4868
 *
 * @param {Uint8Array} digest (output) the HMAC-SHA-512 of the input
 * @param {Uint8Array} text the input message
 * @param {number} text_len the length of `input`
 * @param {Uint8Array} key authentication key
 */
Module.ecc_mac_hmac_sha512 = (
    digest,
    text, text_len,
    key
) => {
    const pText = mput(text, 0, text_len);
    const pKey = mput(key, pText + text_len, 32);
    const pDigest = pKey + 32;

    _ecc_mac_hmac_sha512(pDigest, pText, text_len, pKey);

    mget(pDigest, digest, 64);
    mzero(text_len + 32 + 64);
}

// kdf

/**
 * Computes the HKDF-SHA-256 extract of the input using a key material.
 *
 * See https://datatracker.ietf.org/doc/html/rfc5869
 *
 * @param {Uint8Array} prk (output) a pseudorandom key
 * @param {Uint8Array} salt optional salt value (a non-secret random value)
 * @param {number} salt_len the length of `salt`
 * @param {Uint8Array} ikm input keying material
 * @param {number} ikm_len the length of `ikm`
 */
Module.ecc_kdf_hkdf_sha256_extract = (
    prk,
    salt, salt_len,
    ikm, ikm_len
) => {
    const pSalt = mput(salt, 0, salt_len);
    const pIkm = mput(ikm, pSalt + salt_len, ikm_len);
    const pPrk = pIkm + ikm_len;

    const r = _ecc_kdf_hkdf_sha256_extract(pPrk, pSalt, salt_len, pIkm, ikm_len);

    mget(pPrk, prk, 32);
    mzero(salt_len + ikm_len + 32);
    return r;
}

/**
 * Computes the HKDF-SHA-256 expand of the input using a key.
 *
 * See https://datatracker.ietf.org/doc/html/rfc5869
 *
 * @param {Uint8Array} okm (output) output keying material of length `len`
 * @param {Uint8Array} prk a pseudorandom key
 * @param {Uint8Array} info optional context and application specific information
 * @param {number} info_len length of `info`
 * @param {number} len length of output keying material in octets
 */
Module.ecc_kdf_hkdf_sha256_expand = (
    okm,
    prk,
    info, info_len,
    len
) => {
    const pPrk = mput(prk, 0, 32);
    const pInfo = mput(info, pPrk + 32, info_len);
    const pOkm = pInfo + info_len;

    const r = _ecc_kdf_hkdf_sha256_expand(
        pOkm,
        pPrk,
        pInfo, info_len,
        len
    );

    mget(pOkm, okm, len);
    mzero(32 + info_len + len);
    return r;
}

/**
 * Computes the HKDF-SHA-512 extract of the input using a key material.
 *
 * See https://datatracker.ietf.org/doc/html/rfc5869
 *
 * @param {Uint8Array} prk (output) a pseudorandom key
 * @param {Uint8Array} salt optional salt value (a non-secret random value)
 * @param {number} salt_len the length of `salt`
 * @param {Uint8Array} ikm input keying material
 * @param {number} ikm_len the length of `ikm`
 */
Module.ecc_kdf_hkdf_sha512_extract = (
    prk,
    salt, salt_len,
    ikm, ikm_len
) => {
    const pSalt = mput(salt, 0, salt_len);
    const pIkm = mput(ikm, pSalt + salt_len, ikm_len);
    const pPrk = pIkm + ikm_len;

    const r = _ecc_kdf_hkdf_sha512_extract(pPrk, pSalt, salt_len, pIkm, ikm_len);

    mget(pPrk, prk, 64);
    mzero(salt_len + ikm_len + 64);
    return r;
}

/**
 * Computes the HKDF-SHA-512 expand of the input using a key.
 *
 * See https://datatracker.ietf.org/doc/html/rfc5869
 *
 * @param {Uint8Array} okm (output) output keying material of length `len`
 * @param {Uint8Array} prk a pseudorandom key
 * @param {Uint8Array} info optional context and application specific information
 * @param {number} info_len length of `info`
 * @param {number} len length of output keying material in octets
 */
Module.ecc_kdf_hkdf_sha512_expand = (
    okm,
    prk,
    info, info_len,
    len
) => {
    const pPrk = mput(prk, 0, 64);
    const pInfo = mput(info, pPrk + 64, info_len);
    const pOkm = pInfo + info_len;

    const r = _ecc_kdf_hkdf_sha512_expand(
        pOkm,
        pPrk,
        pInfo, info_len,
        len
    );

    mget(pOkm, okm, len);
    mzero(64 + info_len + len);
    return r;
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

/**
 * @param {Uint8Array} pk 32 bytes
 * @param {Uint8Array} sk 64 bytes
 * @returns {number}
 */
Module.ecc_ed25519_sign_keypair = (pk, sk) => {
    const pPk = 0;
    const pSk = pPk + 32;

    const op = _ecc_ed25519_sign_keypair(pPk, pSk);
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
Module.ecc_ed25519_sign_seed_keypair = (pk, sk, seed) => {
    arraycopy(seed, 0, HEAPU8, 0, 32);

    const pSeed = 0;
    const pPk = pSeed + 32;
    const pSk = pPk + 32;

    const op = _ecc_ed25519_sign_seed_keypair(pPk, pSk, pSeed);
    arraycopy(HEAPU8, pPk, pk, 0, 32);
    arraycopy(HEAPU8, pSk, sk, 0, 64);
    return op;
}

/**
 * @param {Uint8Array} curve25519_sk 32 bytes
 * @param {Uint8Array} ed25519_sk 32 bytes
 * @returns {number}
 */
Module.ecc_ed25519_sign_sk_to_curve25519 = (curve25519_sk, ed25519_sk) => {
    arraycopy(ed25519_sk, 0, HEAPU8, 0, 32);

    const pEd25519_sk = 0;
    const pCurve25519_sk = pEd25519_sk + 32;

    const op = _ecc_ed25519_sign_seed_keypair(pCurve25519_sk, pEd25519_sk);
    arraycopy(HEAPU8, pCurve25519_sk, curve25519_sk, 0, 32);
    return op;
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

// bls12_381

/**
 * @param {Uint8Array} out_SK 32 bytes
 * @param {Uint8Array} IKM
 * @param {Uint8Array} IKM_len >= 32
 * @returns {number}
 */
Module.ecc_bls12_381_keygen = (out_SK, IKM, IKM_len) => {
    arraycopy(IKM, 0, HEAPU8, 0, IKM_len);

    const pIKM = 0;
    const pOut_SK = pIKM + IKM_len;

    _ecc_bls12_381_keygen(pOut_SK, pIKM, IKM_len);
    arraycopy(HEAPU8, pOut_SK, out_SK, 0, 32);
}

// h2c

/**
 * Produces a uniformly random byte string using SHA-512.
 *
 * In order to make this method to use only the stack, len should be <= 256.
 *
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-11#section-5.4.1
 *
 * @param {Uint8Array} out (output) a byte string, should be at least of size `len`
 * @param {Uint8Array} msg a byte string
 * @param {number} msg_len the length of `msg`
 * @param {Uint8Array} dst a byte string of at most 255 bytes
 * @param {number} dst_len the length of `dst`, should be <= 256
 * @param {number} len the length of the requested output in bytes, should be <= 256
 */
Module.ecc_h2c_expand_message_xmd_sha512 = (
    out,
    msg, msg_len,
    dst, dst_len,
    len
) => {
    const pMsg = mput(msg, 0, msg_len);
    const pDst = mput(dst, pMsg + msg_len, dst_len);
    const pOut = pDst + dst_len;

    _ecc_h2c_expand_message_xmd_sha512(
        pOut,
        pMsg, msg_len,
        pDst, dst_len,
        len
    );

    mget(pOut, out, len);
    mzero(msg_len + dst_len + len);
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

// opaque

/**
 * Returns a randomly generated private and public key pair.
 *
 * This is implemented by generating a random "seed", then
 * calling internally DeriveAuthKeyPair.
 *
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-05#section-2
 *
 * @param {Uint8Array} private_key (output) a private key
 * @param {Uint8Array} public_key (output) the associated public key
 */
Module.ecc_opaque_ristretto255_sha512_GenerateAuthKeyPair = (
    private_key,
    public_key
) => {
    const pPrivate_key = 0;
    const pPublic_key = 32;

    _ecc_opaque_ristretto255_sha512_GenerateAuthKeyPair(pPrivate_key, pPublic_key);

    mget(pPrivate_key, private_key, 32);
    mget(pPublic_key, public_key, 32);
    mzero(32 + 32);
}

/**
 * Same as calling CreateRegistrationRequest with a specified blind.
 *
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-05#section-5.1.1.1
 *
 * @param {Uint8Array} request_raw (output) a RegistrationRequest structure
 * @param {Uint8Array} password an opaque byte string containing the client's password
 * @param {number} password_len the length of `password`
 * @param {Uint8Array} blind the OPRF scalar value to use
 */
Module.ecc_opaque_ristretto255_sha512_CreateRegistrationRequestWithBlind = (
    request_raw,
    password, password_len,
    blind,
) => {
    const pPassword = mput(password, 0, password_len);
    const pBlind = mput(blind, pPassword + password_len, 32);
    const pRequest = pBlind + 32;

    _ecc_opaque_ristretto255_sha512_CreateRegistrationRequestWithBlind(
        pRequest,
        pPassword, password_len,
        pBlind,
    );

    mget(pRequest, request_raw, 32);
    mget(pBlind, blind, 32);
    mzero(password_len + 32 + 32);
}

/**
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-05#section-5.1.1.1
 *
 * @param {Uint8Array} request_raw (output) a RegistrationRequest structure
 * @param {Uint8Array} blind (output) an OPRF scalar value
 * @param {Uint8Array} password an opaque byte string containing the client's password
 * @param {number} password_len the length of `password`
 */
Module.ecc_opaque_ristretto255_sha512_CreateRegistrationRequest = (
    request_raw,
    blind,
    password, password_len
) => {
    const pPassword = mput(password, 0, password_len);
    const pRequest = pPassword + password_len;
    const pBlind = pRequest + 32;

    _ecc_opaque_ristretto255_sha512_CreateRegistrationRequest(
        pRequest,
        pBlind,
        pPassword, password_len
    );

    mget(pRequest, request_raw, 32);
    mget(pBlind, blind, 32);
    mzero(password_len + 32 + 32);
}

/**
 * In order to make this method not to use dynamic memory allocation, there is a
 * limit of credential_identifier_len <= 200.
 *
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-05#section-5.1.1.2
 *
 * @param {Uint8Array} response_raw (output) a RegistrationResponse structure
 * @param {Uint8Array} oprf_key (output) the per-client OPRF key known only to the server
 * @param {Uint8Array} request_raw a RegistrationRequest structure
 * @param {Uint8Array} server_public_key the server's public key
 * @param {Uint8Array} credential_identifier an identifier that uniquely represents the credential being registered
 * @param {number} credential_identifier_len the length of `credential_identifier`
 * @param {Uint8Array} oprf_seed the server-side seed of Nh bytes used to generate an oprf_key
 */
Module.ecc_opaque_ristretto255_sha512_CreateRegistrationResponse = (
    response_raw,
    oprf_key,
    request_raw,
    server_public_key,
    credential_identifier, credential_identifier_len,
    oprf_seed
) => {
    const pRequest = mput(request_raw, 0, 32);
    const pServer_public_key = mput(server_public_key, pRequest + 32, 32);
    const pCredential_identifier = mput(credential_identifier, pServer_public_key + 32, credential_identifier_len);
    const pOprf_seed = mput(oprf_seed, pCredential_identifier + credential_identifier_len, 64);
    const pResponse = pOprf_seed + 64;
    const pOprf_key = pResponse + 64;

    _ecc_opaque_ristretto255_sha512_CreateRegistrationResponse(
        pResponse,
        pOprf_key,
        pRequest,
        pServer_public_key,
        pCredential_identifier, credential_identifier_len,
        pOprf_seed
    );

    mget(pResponse, response_raw, 64);
    mget(pOprf_key, oprf_key, 32);
    mzero(32 + 32 + credential_identifier_len + 64 + 64 + 32);
}

/**
 * To create the user record used for further authentication, the client
 * executes the following function. Since this works in the internal key mode, the
 * "client_private_key" is null.
 *
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-05#section-5.1.1.3
 *
 * @param {Uint8Array} record_raw (output) a RegistrationUpload structure
 * @param {Uint8Array} export_key (output) an additional client key
 * @param {Uint8Array} client_private_key the client's private key (always null, internal mode)
 * @param {Uint8Array} password an opaque byte string containing the client's password
 * @param {number} password_len the length of `password`
 * @param {Uint8Array} blind the OPRF scalar value used for blinding
 * @param {Uint8Array} response_raw a RegistrationResponse structure
 * @param {Uint8Array} server_identity the optional encoded server identity
 * @param {number} server_identity_len the length of `server_identity`
 * @param {Uint8Array} client_identity the optional encoded client identity
 * @param {number} client_identity_len the length of `client_identity`
 */
Module.ecc_opaque_ristretto255_sha512_FinalizeRequest =(
    record_raw, // RegistrationUpload_t
    export_key,
    client_private_key,
    password, password_len,
    blind,
    response_raw, // RegistrationResponse_t
    server_identity, server_identity_len,
    client_identity, client_identity_len
) => {
    const pClient_private_key = mput(client_private_key, 0, 32);
    const pPassword = mput(password, pClient_private_key + 32, password_len);
    const pBlind = mput(blind, pPassword + password_len, 32);
    const pResponse = mput(response_raw, pBlind + 32, 64);
    const pServer_identity = mput(server_identity, pResponse + 64, server_identity_len);
    const pClient_identity = mput(client_identity, pServer_identity + server_identity_len, client_identity_len);
    const pRecord = pClient_identity + client_identity_len;
    const pExport_key = pRecord + 192;

    _ecc_opaque_ristretto255_sha512_FinalizeRequest(
        pRecord,
        pExport_key,
        pClient_private_key,
        pPassword, password_len,
        pBlind,
        pResponse,
        pServer_identity, server_identity_len,
        pClient_identity, client_identity_len
    );

    mget(pRecord, record_raw, 192);
    mget(pExport_key, export_key, 64);
    mzero(32 + password_len + 32 + 64 + server_identity_len + client_identity_len + 192 + 64);
}

/**
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-05#section-6.2.3
 *
 * @param {Uint8Array} ke1_raw (output) a KE1 message structure
 * @param {Uint8Array} state_raw a ClientState structure
 * @param {Uint8Array} client_identity the optional encoded client identity, which is null if not specified
 * @param {number} client_identity_len the length of `client_identity`
 * @param {Uint8Array} password an opaque byte string containing the client's password
 * @param {number} password_len the length of `password`
 */
Module.ecc_opaque_ristretto255_sha512_3DH_ClientInit = (
    ke1_raw,
    state_raw,
    client_identity, client_identity_len,
    password, password_len
) => {
    const pSate = mput(state_raw, 0, 160);
    const pClient_identity = mput(client_identity, pSate + 160, client_identity_len);
    const pPassword = mput(password, pClient_identity + client_identity_len, password_len);
    const pKe1 = pPassword + password_len;

    _ecc_opaque_ristretto255_sha512_3DH_ClientInit(
        pKe1,
        pSate,
        pClient_identity, client_identity_len,
        pPassword, password_len
    );

    mget(pSate, state_raw, 160);
    mget(pKe1, ke1_raw, 96);
    mzero(160 + client_identity_len + password_len + 96);
}

/**
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-05#section-6.2.3
 *
 * @param {Uint8Array} ke3_raw (output) a KE3 message structure
 * @param {Uint8Array} session_key (output) the session's shared secret
 * @param {Uint8Array} export_key (output) an additional client key
 * @param {Uint8Array} state_raw a ClientState structure
 * @param {Uint8Array} password an opaque byte string containing the client's password
 * @param {number} password_len the length of `password`
 * @param {Uint8Array} client_identity the optional encoded client identity, which is set
 * to client_public_key if not specified
 * @param {number} client_identity_len the length of `client_identity`
 * @param {Uint8Array} server_identity the optional encoded server identity, which is set
 * to server_public_key if not specified
 * @param {number} server_identity_len the length of `server_identity`
 * @param {Uint8Array} ke2_raw a KE2 message structure
 * @return {number} 0 if is able to recover credentials and authenticate with the
 * server, else -1
 */
Module.ecc_opaque_ristretto255_sha512_3DH_ClientFinish = (
    ke3_raw,
    session_key,
    export_key,
    state_raw,
    password, password_len,
    client_identity, client_identity_len,
    server_identity, server_identity_len,
    ke2_raw
) => {
    const pSate = mput(state_raw, 0, 160);
    const pPassword = mput(password, pSate + 160, password_len);
    const pClient_identity = mput(client_identity, pPassword + password_len, client_identity_len);
    const pServer_identity = mput(server_identity, pClient_identity + client_identity_len, server_identity_len);
    const pKe2 = mput(ke2_raw, pServer_identity + server_identity_len, 320);
    const pKe3 = pKe2 + 320;
    const pSession_key = pKe3 + 64;
    const pExport_key = pSession_key + 64;

    const r = _ecc_opaque_ristretto255_sha512_3DH_ClientFinish(
        pKe3,
        pSession_key,
        pExport_key,
        pSate,
        pPassword, password_len,
        pClient_identity, client_identity_len,
        pServer_identity, server_identity_len,
        pKe2
    );

    mget(pSate, state_raw, 160);
    mget(pKe3, ke3_raw, 64);
    mget(pSession_key, session_key, 64);
    mget(pExport_key, export_key, 64);
    mzero(160 + password_len + client_identity_len + server_identity_len + 320 + 64 + 64 + 64);
    return r;
}

/**
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-05#section-6.2.4
 *
 * @param {Uint8Array} ke2_raw (output) a KE2 structure
 * @param {Uint8Array} state_raw a ServerState structure
 * @param {Uint8Array} server_identity the optional encoded server identity, which is set to
 * server_public_key if null
 * @param {number} server_identity_len the length of `server_identity`
 * @param {Uint8Array} server_private_key the server's private key
 * @param {Uint8Array} server_public_key the server's public key
 * @param {Uint8Array} record_raw the client's RegistrationUpload structure
 * @param {Uint8Array} credential_identifier an identifier that uniquely represents the credential
 * being registered
 * @param {number} credential_identifier_len the length of `credential_identifier`
 * @param {Uint8Array} oprf_seed the server-side seed of Nh bytes used to generate an oprf_key
 * @param {Uint8Array} ke1_raw a KE1 message structure
 * @param {Uint8Array} context the application specific context
 * @param {number} context_len the length of `context_len`
 */
Module.ecc_opaque_ristretto255_sha512_3DH_ServerInit = (
    ke2_raw,
    state_raw,
    server_identity, server_identity_len,
    server_private_key,
    server_public_key,
    record_raw,
    credential_identifier, credential_identifier_len,
    oprf_seed,
    ke1_raw,
    context, context_len
) => {
    const pSate = mput(state_raw, 0, 128);
    const pServer_identity = mput(server_identity, pSate + 128, server_identity_len);
    const pServer_private_key = mput(server_private_key, pServer_identity + server_identity_len, 32);
    const pServer_public_key = mput(server_public_key, pServer_private_key + 32, 32);
    const pRecord = mput(record_raw, pServer_public_key + 32, 192);
    const pCredential_identifier = mput(credential_identifier, pRecord + 192, credential_identifier_len);
    const pOprf_seed = mput(oprf_seed, pCredential_identifier + credential_identifier_len, 64);
    const pKe1 = mput(ke1_raw, pOprf_seed + 64, 96);
    const pContext = mput(context, pKe1 + 96, context_len);
    const pKe2 = pContext + context_len;

    _ecc_opaque_ristretto255_sha512_3DH_ServerInit(
        pKe2,
        pSate,
        pServer_identity, server_identity_len,
        pServer_private_key,
        pServer_public_key,
        pRecord,
        pCredential_identifier, credential_identifier_len,
        pOprf_seed,
        pKe1,
        pContext, context_len
    );

    mget(pSate, state_raw, 128);
    mget(pKe2, ke2_raw, 320);
    mzero(128 + server_identity_len + 32 + 32 + 192 + credential_identifier_len + 64 + 96 + context_len + 320);
}

/**
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-05#section-6.2.4
 *
 * @param {Uint8Array} session_key (output) the shared session secret if and only if KE3 is valid
 * @param {Uint8Array} state_raw a ServerState structure
 * @param {Uint8Array} ke3_raw a KE3 structure
 * @return {number} 0 if the user was authenticated, else -1
 */
Module.ecc_opaque_ristretto255_sha512_3DH_ServerFinish = (
    session_key,
    state_raw,
    ke3_raw
) => {
    const pSate = mput(state_raw, 0, 128);
    const pKe3 = mput(ke3_raw, pSate + 128, 64);
    const pSession_key = pKe3 + 64;

    const r = _ecc_opaque_ristretto255_sha512_3DH_ServerFinish(
        pSession_key,
        pSate,
        pKe3
    );

    mget(pSate, state_raw, 128);
    mget(pSession_key, session_key, 64);
    mzero(128 + 64 + 64);
    return r;
}
