
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
 * @returns {number}
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

// ecc

/**
 * @param {Uint8Array} buf
 * @param {number} n
 */
Module.ecc_randombytes = (buf, n) => {
    const pBuf = 0;
    _ecc_randombytes(pBuf, n);
    mget(pBuf, buf, n);
    mzero(n);
}

// opaque

/**
 *
 * @param {Uint8Array} request_raw
 * @param {Uint8Array} blind
 * @param {Uint8Array} password
 * @param {number} password_len
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
 *
 * @param {Uint8Array} response_raw
 * @param {Uint8Array} oprf_key
 * @param {Uint8Array} request_raw
 * @param {Uint8Array} server_public_key
 * @param {Uint8Array} credential_identifier
 * @param {number} credential_identifier_len
 * @param {Uint8Array} oprf_seed
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

    ecc_opaque_ristretto255_sha512_CreateRegistrationResponse(
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
