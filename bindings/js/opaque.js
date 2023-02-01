/*
 * Copyright (c) 2021-2023, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

import {
    libecc,
} from "./util.js";

/**
 * Recover the public key related to the input "private_key".
 *
 * @param {Uint8Array} privateKey
 * @return {Uint8Array}
 */
export function opaque_RecoverPublicKey(
    privateKey,
) {

    let publicKey = new Uint8Array(libecc.ecc_opaque_ristretto255_sha512_Npk);

    libecc.ecc_opaque_ristretto255_sha512_RecoverPublicKey(
        publicKey,
        privateKey,
    );

    return publicKey;
}

/**
 * Returns a randomly generated private and public key pair.
 *
 * This is implemented by generating a random "seed", then
 * calling internally DeriveAuthKeyPair.
 *
 * @return object {private_key, public_key}
 */
export function opaque_GenerateAuthKeyPair() {

    let private_key = new Uint8Array(libecc.ecc_opaque_ristretto255_sha512_Nsk);
    let public_key = new Uint8Array(libecc.ecc_opaque_ristretto255_sha512_Npk);

    libecc.ecc_opaque_ristretto255_sha512_GenerateAuthKeyPair(
        private_key,
        public_key,
    );

    return {
        privateKey: private_key,
        publicKey: public_key,
    };
}

/**
 * @param {Uint8Array} password an opaque byte string containing the client's password
 * @param {Uint8Array} blind the OPRF scalar value to use, size:ecc_opaque_ristretto255_sha512_Ns
 * @return object {request, blind}
 */
export function opaque_CreateRegistrationRequestWithBlind(
    password,
    blind,
) {
    let request = new Uint8Array(libecc.ecc_opaque_ristretto255_sha512_REGISTRATIONREQUESTSIZE);

    libecc.ecc_opaque_ristretto255_sha512_CreateRegistrationRequestWithBlind(
        request,
        password, password.length,
        blind,
    );

    return {
        registrationRequest: request,
        blind: blind,
    };
}

/**
 * @param {Uint8Array} password an opaque byte string containing the client's password
 * @return object {request, blind}
 */
export function opaque_CreateRegistrationRequest(
    password
) {
    let request = new Uint8Array(libecc.ecc_opaque_ristretto255_sha512_REGISTRATIONREQUESTSIZE);
    let blind = new Uint8Array(libecc.ecc_opaque_ristretto255_sha512_Ns);

    libecc.ecc_opaque_ristretto255_sha512_CreateRegistrationRequest(
        request,
        blind,
        password, password.length
    );

    return {
        registrationRequest: request,
        blind: blind,
    };
}

/**
 * In order to make this method not to use dynamic memory allocation, there is a
 * limit of credential_identifier to length <= 200.
 *
 * @param {Uint8Array} request a RegistrationRequest structure
 * @param {Uint8Array} server_public_key the server's public key
 * @param {Uint8Array} credential_identifier an identifier that uniquely represents the credential being registered
 * @param {Uint8Array} oprf_seed the server-side seed of Nh bytes used to generate an oprf_key
 * @return {Uint8Array}
 */
export function opaque_CreateRegistrationResponse(
    request,
    server_public_key,
    credential_identifier,
    oprf_seed,
) {
    let response = new Uint8Array(libecc.ecc_opaque_ristretto255_sha512_REGISTRATIONRESPONSESIZE);

    libecc.ecc_opaque_ristretto255_sha512_CreateRegistrationResponse(
        response,
        request,
        server_public_key,
        credential_identifier, credential_identifier.length,
        oprf_seed,
    );

    return response;
}

/**
 * To create the user record used for further authentication, the client
 * executes the following function.
 *
 * @param {Uint8Array} password an opaque byte string containing the client's password
 * @param {Uint8Array} blind the OPRF scalar value used for blinding
 * @param {Uint8Array} response_raw a RegistrationResponse structure
 * @param {Uint8Array} server_identity the optional encoded server identity
 * @param {Uint8Array} client_identity the optional encoded client identity
 * @param {number} mhf the memory hard function to use
 * @param {Uint8Array} nonce size:ecc_opaque_ristretto255_sha512_Nn
 * @return object {record, exportKey}
 */
export function opaque_FinalizeRegistrationRequestWithNonce(
    password,
    blind,
    response_raw,
    server_identity,
    client_identity,
    mhf,
    nonce,
) {
    server_identity = server_identity || new Uint8Array(0);
    client_identity = client_identity || new Uint8Array(0);

    let record_raw = new Uint8Array(libecc.ecc_opaque_ristretto255_sha512_REGISTRATIONRECORDSIZE);
    let export_key = new Uint8Array(64);

    libecc.ecc_opaque_ristretto255_sha512_FinalizeRegistrationRequestWithNonce(
        record_raw,
        export_key,
        password, password.length,
        blind,
        response_raw,
        server_identity, server_identity.length,
        client_identity, client_identity.length,
        mhf,
        nonce,
    );

    return {
        registrationRecord: record_raw,
        exportKey: export_key,
    };
}

/**
 * To create the user record used for further authentication, the client
 * executes the following function.
 *
 * @param {Uint8Array} password an opaque byte string containing the client's password
 * @param {Uint8Array} blind the OPRF scalar value used for blinding
 * @param {Uint8Array} response_raw a RegistrationResponse structure
 * @param {Uint8Array} server_identity the optional encoded server identity
 * @param {Uint8Array} client_identity the optional encoded client identity
 * @param {number} mhf the memory hard function to use
 * @return object {record, exportKey}
 */
export function opaque_FinalizeRegistrationRequest(
    password,
    blind,
    response_raw,
    server_identity,
    client_identity,
    mhf,
) {
    server_identity = server_identity || new Uint8Array(0);
    client_identity = client_identity || new Uint8Array(0);

    let record_raw = new Uint8Array(libecc.ecc_opaque_ristretto255_sha512_REGISTRATIONRECORDSIZE);
    let export_key = new Uint8Array(64);

    libecc.ecc_opaque_ristretto255_sha512_FinalizeRegistrationRequest(
        record_raw,
        export_key,
        password, password.length,
        blind,
        response_raw,
        server_identity, server_identity.length,
        client_identity, client_identity.length,
        mhf,
    );

    return {
        registrationRecord: record_raw,
        exportKey: export_key,
    };
}

/**
 *
 * @param {Uint8Array} state a ClientState structure
 * @param {Uint8Array} password an opaque byte string containing the client's password
 * @param {Uint8Array} blind
 * @param {Uint8Array} clientNonce
 * @param {Uint8Array} clientSecret
 * @param {Uint8Array} clientKeyshare
 * @return {Uint8Array} a KE1 message structure
 */
export function opaque_ClientInitWithSecrets(
    state,
    password,
    blind,
    clientNonce,
    clientSecret,
    clientKeyshare
) {
    let ke1 = new Uint8Array(libecc.ecc_opaque_ristretto255_sha512_KE1SIZE);

    libecc.ecc_opaque_ristretto255_sha512_ClientInitWithSecrets(
        ke1,
        state,
        password, password.length,
        blind,
        clientNonce,
        clientSecret,
        clientKeyshare,
    );

    return ke1;
}

/**
 *
 * @param {Uint8Array} state a ClientState structure
 * @param {Uint8Array} password an opaque byte string containing the client's password
 * @return {Uint8Array} a KE1 message structure
 */
export function opaque_ClientInit(
    state,
    password,
) {
    let ke1 = new Uint8Array(libecc.ecc_opaque_ristretto255_sha512_KE1SIZE);

    libecc.ecc_opaque_ristretto255_sha512_ClientInit(
        ke1,
        state,
        password, password.length,
    );

    return ke1;
}

/**
 *
 * @param {Uint8Array} state_raw a ClientState structure
 * @param {Uint8Array} client_identity the optional encoded client identity, which is set
 * to client_public_key if not specified
 * @param {Uint8Array} server_identity the optional encoded server identity, which is set
 * to server_public_key if not specified
 * @param {Uint8Array} ke2_raw a KE2 message structure
 * @param {number} mhf
 * @param {Uint8Array} context
 * @return object {ke3, sessionKey, exportKey, finishRet}
 */
export function opaque_ClientFinish(
    state_raw,
    client_identity,
    server_identity,
    ke2_raw,
    mhf,
    context,
) {
    client_identity = client_identity || new Uint8Array(0);
    server_identity = server_identity || new Uint8Array(0);

    let ke3_raw = new Uint8Array(libecc.ecc_opaque_ristretto255_sha512_KE3SIZE);
    let session_key = new Uint8Array(64);
    let export_key = new Uint8Array(64);

    const ret = libecc.ecc_opaque_ristretto255_sha512_ClientFinish(
        ke3_raw,
        session_key,
        export_key,
        state_raw,
        client_identity, client_identity.length,
        server_identity, server_identity.length,
        ke2_raw,
        mhf,
        context, context.length,
    );

    return {
        ke3: ke3_raw,
        sessionKey: session_key,
        exportKey: export_key,
        result: ret,
    };
}

/**
 *
 * @param {Uint8Array} state_raw a ServerState structure
 * @param {Uint8Array} server_identity the optional encoded server identity, which is set to
 * server_public_key if null
 * @param {Uint8Array} server_private_key the server's private key
 * @param {Uint8Array} server_public_key the server's public key
 * @param {Uint8Array} record_raw the client's RegistrationUpload structure
 * @param {Uint8Array} credential_identifier an identifier that uniquely represents the credential
 * being registered
 * @param {Uint8Array} oprf_seed the server-side seed of Nh bytes used to generate an oprf_key
 * @param {Uint8Array} ke1_raw a KE1 message structure
 * @param {Uint8Array} client_identity
 * @param {Uint8Array} context the application specific context
 * @param {Uint8Array} maskingNonce
 * @param {Uint8Array} serverNonce
 * @param {Uint8Array} serverSecret
 * @param {Uint8Array} serverKeyshare
 * @return {Uint8Array} a KE2 structure
 */
export function opaque_ServerInitWithSecrets(
    state_raw,
    server_identity,
    server_private_key,
    server_public_key,
    record_raw,
    credential_identifier,
    oprf_seed,
    ke1_raw,
    client_identity,
    context,
    maskingNonce,
    serverNonce,
    serverSecret,
    serverKeyshare,
) {
    server_identity = server_identity || new Uint8Array(0);
    client_identity = client_identity || new Uint8Array(0);
    context = context || new Uint8Array(0);

    let ke2_raw = new Uint8Array(libecc.ecc_opaque_ristretto255_sha512_KE2SIZE);

    libecc.ecc_opaque_ristretto255_sha512_ServerInitWithSecrets(
        ke2_raw,
        state_raw,
        server_identity, server_identity.length,
        server_private_key,
        server_public_key,
        record_raw,
        credential_identifier, credential_identifier.length,
        oprf_seed,
        ke1_raw,
        client_identity, client_identity.length,
        context, context.length,
        maskingNonce,
        serverNonce,
        serverSecret,
        serverKeyshare,
    );

    return ke2_raw;
}

/**
 *
 * @param {Uint8Array} state_raw a ServerState structure
 * @param {Uint8Array} server_identity the optional encoded server identity, which is set to
 * server_public_key if null
 * @param {Uint8Array} server_private_key the server's private key
 * @param {Uint8Array} server_public_key the server's public key
 * @param {Uint8Array} record_raw the client's RegistrationUpload structure
 * @param {Uint8Array} credential_identifier an identifier that uniquely represents the credential
 * being registered
 * @param {Uint8Array} oprf_seed the server-side seed of Nh bytes used to generate an oprf_key
 * @param {Uint8Array} ke1_raw a KE1 message structure
 * @param {Uint8Array} client_identity
 * @param {Uint8Array} context the application specific context
 * @return {Uint8Array} a KE2 structure
 */
export function opaque_ServerInit(
    state_raw,
    server_identity,
    server_private_key,
    server_public_key,
    record_raw,
    credential_identifier,
    oprf_seed,
    ke1_raw,
    client_identity,
    context,
) {
    server_identity = server_identity || new Uint8Array(0);
    client_identity = client_identity || new Uint8Array(0);
    context = context || new Uint8Array(0);

    let ke2_raw = new Uint8Array(libecc.ecc_opaque_ristretto255_sha512_KE2SIZE);

    libecc.ecc_opaque_ristretto255_sha512_ServerInit(
        ke2_raw,
        state_raw,
        server_identity, server_identity.length,
        server_private_key,
        server_public_key,
        record_raw,
        credential_identifier, credential_identifier.length,
        oprf_seed,
        ke1_raw,
        client_identity, client_identity.length,
        context, context.length,
    );

    return ke2_raw;
}

/**
 * @param {Uint8Array} state_raw a ServerState structure
 * @param {Uint8Array} ke3_raw a KE3 structure
 * @return object {session_key, finish_ret}
 */
export function opaque_ServerFinish(
    state_raw,
    ke3_raw
) {
    let session_key = new Uint8Array(64);

    const ret = libecc.ecc_opaque_ristretto255_sha512_ServerFinish(
        session_key,
        state_raw,
        ke3_raw,
    );

    return {
        sessionKey: session_key,
        result: ret,
    };
}
