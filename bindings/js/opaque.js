/*
 * Copyright (c) 2021-2022, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

import libecc_module from "./libecc.js";

/**
 * Returns a randomly generated private and public key pair.
 *
 * This is implemented by generating a random "seed", then
 * calling internally DeriveAuthKeyPair.
 *
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-07#section-2
 *
 * @return object {private_key, public_key}
 */
export async function opaque_ristretto255_sha512_GenerateAuthKeyPair() {
    const libecc = await libecc_module();

    let private_key = new Uint8Array(32);
    let public_key = new Uint8Array(32);

    await libecc.ecc_opaque_ristretto255_sha512_GenerateAuthKeyPair(
        private_key,
        public_key,
    );

    return {
        private_key: private_key,
        public_key: public_key,
    };
}

/**
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-07#section-5.1.1.1
 *
 * @param {Uint8Array} password an opaque byte string containing the client's password
 * @return object {request, blind}
 */
export async function opaque_ristretto255_sha512_CreateRegistrationRequest(
    password
) {
    const libecc = await libecc_module();

    let request_raw = new Uint8Array(32);
    let blind = new Uint8Array(32);

    await libecc.ecc_opaque_ristretto255_sha512_CreateRegistrationRequest(
        request_raw,
        blind,
        password, password.length
    );

    return {
        request: request_raw,
        blind: blind,
    };
}

/**
 * In order to make this method not to use dynamic memory allocation, there is a
 * limit of credential_identifier to length <= 200.
 *
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-07#section-5.1.1.2
 *
 * @param {Uint8Array} request_raw a RegistrationRequest structure
 * @param {Uint8Array} server_public_key the server's public key
 * @param {Uint8Array} credential_identifier an identifier that uniquely represents the credential being registered
 * @param {Uint8Array} oprf_seed the server-side seed of Nh bytes used to generate an oprf_key
 * @return object {response, oprf_key}
 */
export async function opaque_ristretto255_sha512_CreateRegistrationResponse(
    request_raw,
    server_public_key,
    credential_identifier,
    oprf_seed,
) {
    const libecc = await libecc_module();

    let response_raw = new Uint8Array(64);
    let oprf_key = new Uint8Array(32);

    await libecc.ecc_opaque_ristretto255_sha512_CreateRegistrationResponse(
        response_raw,
        oprf_key,
        request_raw,
        server_public_key,
        credential_identifier, credential_identifier.length,
        oprf_seed,
    );

    return {
        response: response_raw,
        oprf_key: oprf_key,
    };
}

/**
 * To create the user record used for further authentication, the client
 * executes the following function. Since this works in the internal key mode, the
 * "client_private_key" is null.
 *
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-07#section-5.1.1.3
 *
 * @param {Uint8Array} password an opaque byte string containing the client's password
 * @param {Uint8Array} blind the OPRF scalar value used for blinding
 * @param {Uint8Array} response_raw a RegistrationResponse structure
 * @param {Uint8Array} server_identity the optional encoded server identity
 * @param {Uint8Array} client_identity the optional encoded client identity
 * @return object {record, export_key}
 */
export async function opaque_ristretto255_sha512_FinalizeRequest(
    password,
    blind,
    response_raw,
    server_identity,
    client_identity,
) {
    const libecc = await libecc_module();

    server_identity = server_identity || new Uint8Array(0);
    client_identity = client_identity || new Uint8Array(0);

    let record_raw = new Uint8Array(192);
    let export_key = new Uint8Array(64);

    await libecc.ecc_opaque_ristretto255_sha512_FinalizeRequest(
        record_raw,
        export_key,
        password, password.length,
        blind,
        response_raw,
        server_identity, server_identity.length,
        client_identity, client_identity.length,
        libecc.ecc_opaque_ristretto255_sha512_MHF_IDENTITY,
    );

    return {
        record: record_raw,
        export_key: export_key,
    };
}

/**
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-07#section-6.2.3
 *
 * @param {Uint8Array} state_raw a ClientState structure
 * @param {Uint8Array} password an opaque byte string containing the client's password
 * @return {Promise<Uint8Array>} a KE1 message structure
 */
export async function opaque_ristretto255_sha512_3DH_ClientInit(
    state_raw,
    password,
) {
    const libecc = await libecc_module();

    let ke1_raw = new Uint8Array(96);

    await libecc.ecc_opaque_ristretto255_sha512_3DH_ClientInit(
        ke1_raw,
        state_raw,
        password, password.length,
    );

    return ke1_raw;
}

/**
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-07#section-6.2.3
 *
 * @param {Uint8Array} state_raw a ClientState structure
 * @param {Uint8Array} password an opaque byte string containing the client's password
 * @param {Uint8Array} client_identity the optional encoded client identity, which is set
 * to client_public_key if not specified
 * @param {Uint8Array} server_identity the optional encoded server identity, which is set
 * to server_public_key if not specified
 * @param {Uint8Array} ke2_raw a KE2 message structure
 * @return object {ke3, session_key, export_key, finish_ret}
 */
export async function opaque_ristretto255_sha512_3DH_ClientFinish(
    state_raw,
    password,
    client_identity,
    server_identity,
    ke2_raw,
) {
    const libecc = await libecc_module();

    client_identity = client_identity || new Uint8Array(0);
    server_identity = server_identity || new Uint8Array(0);

    let ke3_raw = new Uint8Array(64);
    let session_key = new Uint8Array(64);
    let export_key = new Uint8Array(64);

    const ret = await libecc.ecc_opaque_ristretto255_sha512_3DH_ClientFinish(
        ke3_raw,
        session_key,
        export_key,
        state_raw,
        password, password.length,
        client_identity, client_identity.length,
        server_identity, server_identity.length,
        ke2_raw,
        libecc.ecc_opaque_ristretto255_sha512_MHF_IDENTITY,
        new Uint8Array(0), 0,
    );

    return {
        ke3: ke3_raw,
        session_key: session_key,
        export_key: export_key,
        finish_ret: ret,
    };
}

/**
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-07#section-6.2.4
 *
 * @param {Uint8Array} state_raw a ServerState structure
 * @param {Uint8Array} server_identity the optional encoded server identity, which is set to
 * server_public_key if null
 * @param {Uint8Array} server_private_key the server's private key
 * @param {Uint8Array} server_public_key the server's public key
 * @param {Uint8Array} client_identity
 * @param {Uint8Array} record_raw the client's RegistrationUpload structure
 * @param {Uint8Array} credential_identifier an identifier that uniquely represents the credential
 * being registered
 * @param {Uint8Array} oprf_seed the server-side seed of Nh bytes used to generate an oprf_key
 * @param {Uint8Array} ke1_raw a KE1 message structure
 * @param {Uint8Array} context the application specific context
 * @return {Promise<Uint8Array>} a KE2 structure
 */
export async function opaque_ristretto255_sha512_3DH_ServerInit(
    state_raw,
    server_identity,
    server_private_key,
    server_public_key,
    client_identity,
    record_raw,
    credential_identifier,
    oprf_seed,
    ke1_raw,
    context,
) {
    const libecc = await libecc_module();

    server_identity = server_identity || new Uint8Array(0);
    client_identity = client_identity || new Uint8Array(0);
    context = context || new Uint8Array(0);

    let ke2_raw = new Uint8Array(320);

    await libecc.ecc_opaque_ristretto255_sha512_3DH_ServerInit(
        ke2_raw,
        state_raw,
        server_identity, server_identity.length,
        server_private_key,
        server_public_key,
        client_identity, client_identity.length,
        record_raw,
        credential_identifier, credential_identifier.length,
        oprf_seed,
        ke1_raw,
        context, context.length,
    );

    return ke2_raw;
}

/**
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-07#section-6.2.4
 *
 * @param {Uint8Array} state_raw a ServerState structure
 * @param {Uint8Array} ke3_raw a KE3 structure
 * @return object {session_key, finish_ret}
 */
export async function opaque_ristretto255_sha512_3DH_ServerFinish(
    state_raw,
    ke3_raw
) {
    const libecc = await libecc_module();

    let session_key = new Uint8Array(64);

    const ret = await libecc.ecc_opaque_ristretto255_sha512_3DH_ServerFinish(
        session_key,
        state_raw,
        ke3_raw,
    );

    return {
        session_key: session_key,
        finish_ret: ret,
    };
}
