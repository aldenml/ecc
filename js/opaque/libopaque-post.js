
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
 *
 * @param {Uint8Array} record_raw
 * @param {Uint8Array} export_key
 * @param {Uint8Array} client_private_key
 * @param {Uint8Array} password
 * @param {number} password_len
 * @param {Uint8Array} blind
 * @param {Uint8Array} response_raw
 * @param {Uint8Array} server_identity
 * @param {number} server_identity_len
 * @param {Uint8Array} client_identity
 * @param {number} client_identity_len
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
 *
 * @param {Uint8Array} ke1_raw
 * @param {Uint8Array} state_raw
 * @param {Uint8Array} client_identity
 * @param {number} client_identity_len
 * @param {Uint8Array} password
 * @param {number} password_len
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
 *
 * @param {Uint8Array} ke2_raw
 * @param {Uint8Array} state_raw
 * @param {Uint8Array} server_identity
 * @param {number} server_identity_len
 * @param {Uint8Array} server_private_key
 * @param {Uint8Array} server_public_key
 * @param {Uint8Array} record_raw
 * @param {Uint8Array} credential_identifier
 * @param {number} credential_identifier_len
 * @param {Uint8Array} oprf_seed
 * @param {Uint8Array} ke1_raw
 * @param {Uint8Array} context
 * @param {number} context_len
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
 *
 * @param {Uint8Array} ke3_raw
 * @param {Uint8Array} session_key
 * @param {Uint8Array} export_key
 * @param {Uint8Array} state_raw
 * @param {Uint8Array} password
 * @param {number} password_len
 * @param {Uint8Array} client_identity
 * @param {number} client_identity_len
 * @param {Uint8Array} server_identity
 * @param {number} server_identity_len
 * @param {Uint8Array} ke2_raw
 * @return {number}
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
 *
 * @param {Uint8Array} session_key
 * @param {Uint8Array} state_raw
 * @param {Uint8Array} ke3_raw
 * @return {number}
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
