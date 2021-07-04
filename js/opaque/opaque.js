/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

import libopaque_module from "./libopaque.js";

const libecc_module = libopaque_module;

/**
 *
 * @param {Uint8Array} password
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
 *
 * @param {Uint8Array} request_raw
 * @param {Uint8Array} server_public_key
 * @param {Uint8Array} credential_identifier
 * @param {Uint8Array} oprf_seed
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
 *
 * @param {Uint8Array} client_private_key
 * @param {Uint8Array} password
 * @param {Uint8Array} blind
 * @param {Uint8Array} response_raw
 * @param {Uint8Array} server_identity
 * @param {Uint8Array} client_identity
 */
export async function opaque_ristretto255_sha512_FinalizeRequest(
    client_private_key,
    password,
    blind,
    response_raw,
    server_identity,
    client_identity,
) {
    const libecc = await libecc_module();

    client_private_key = client_private_key || new Uint8Array(0);
    server_identity = server_identity || new Uint8Array(0);
    client_identity = client_identity || new Uint8Array(0);

    let record_raw = new Uint8Array(192);
    let export_key = new Uint8Array(64);

    await libecc.ecc_opaque_ristretto255_sha512_FinalizeRequest(
        record_raw,
        export_key,
        client_private_key,
        password, password.length,
        blind,
        response_raw,
        server_identity, server_identity.length,
        client_identity, client_identity.length,
    );

    return {
        record: record_raw,
        export_key: export_key,
    };
}

/**
 *
 * @param {Uint8Array} state_raw
 * @param {Uint8Array} client_identity
 * @param {Uint8Array} password
 * @return {Promise<Uint8Array>}
 */
export async function opaque_ristretto255_sha512_3DH_ClientInit(
    state_raw,
    client_identity,
    password,
) {
    const libecc = await libecc_module();

    client_identity = client_identity || new Uint8Array(0);

    let ke1_raw = new Uint8Array(96);

    await libecc.ecc_opaque_ristretto255_sha512_3DH_ClientInit(
        ke1_raw,
        state_raw,
        client_identity, client_identity.length,
        password, password.length,
    );

    return ke1_raw;
}

/**
 *
 * @param {Uint8Array} state_raw
 * @param {Uint8Array} server_identity
 * @param {Uint8Array} server_private_key
 * @param {Uint8Array} server_public_key
 * @param {Uint8Array} record_raw
 * @param {Uint8Array} credential_identifier
 * @param {Uint8Array} oprf_seed
 * @param {Uint8Array} ke1_raw
 * @param {Uint8Array} context
 */
export async function opaque_ristretto255_sha512_3DH_ServerInit(
    state_raw,
    server_identity,
    server_private_key,
    server_public_key,
    record_raw,
    credential_identifier,
    oprf_seed,
    ke1_raw,
    context,
) {
    const libecc = await libecc_module();

    server_identity = server_identity || new Uint8Array(0);
    context = context || new Uint8Array(0);

    let ke2_raw = new Uint8Array(320);

    await libecc.ecc_opaque_ristretto255_sha512_3DH_ServerInit(
        ke2_raw,
        state_raw,
        server_identity, server_identity.length,
        server_private_key,
        server_public_key,
        record_raw,
        credential_identifier, credential_identifier.length,
        oprf_seed,
        ke1_raw,
        context, context.length,
    );

    return ke2_raw;
}

/**
 *
 * @param {Uint8Array} state_raw
 * @param {Uint8Array} password
 * @param {Uint8Array} client_identity
 * @param {Uint8Array} server_identity
 * @param {Uint8Array} ke2_raw
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
    );

    return {
        ke3: ke3_raw,
        session_key: session_key,
        export_key: export_key,
        ret: ret,
    };
}

/**
 *
 * @param {Uint8Array} state_raw
 * @param {Uint8Array} ke3_raw
 * @return {number}
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
        ret: ret,
    };
}
