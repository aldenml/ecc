
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
    const heap_size = n;
    const heap = _ecc_malloc(heap_size);

    const pBuf = heap;

    _ecc_randombytes(pBuf, n);

    mget(pBuf, buf, n);

    _ecc_free(heap, heap_size);
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
