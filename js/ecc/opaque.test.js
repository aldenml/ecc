/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

import {
    hex2bin,
    randombytes,
} from "./util.js";
import {
    opaque_ristretto255_sha512_CreateRegistrationRequest,
    opaque_ristretto255_sha512_CreateRegistrationResponse,
    opaque_ristretto255_sha512_FinalizeRequest,
    opaque_ristretto255_sha512_3DH_ClientInit,
    opaque_ristretto255_sha512_3DH_ServerInit,
    opaque_ristretto255_sha512_3DH_ClientFinish,
    opaque_ristretto255_sha512_3DH_ServerFinish,
    opaque_ristretto255_sha512_GenerateAuthKeyPair,
} from "./opaque.js"
import assert from "assert";

describe("OPAQUE(ristretto255, SHA-512)", () => {

    it("Test 1 (random input)", async () => {
        // client
        const password = await randombytes(10);

        // server
        const oprf_seed = await randombytes(64);
        const keys = await opaque_ristretto255_sha512_GenerateAuthKeyPair();
        const server_private_key = keys.private_key;
        const server_public_key = keys.public_key;
        const credential_identifier = await randombytes(10);

        // registration flow
        const regReq = await opaque_ristretto255_sha512_CreateRegistrationRequest(password);

        const regRes = await opaque_ristretto255_sha512_CreateRegistrationResponse(
            regReq.request,
            server_public_key,
            credential_identifier,
            oprf_seed,
        );

        const regEnd = await opaque_ristretto255_sha512_FinalizeRequest(
            null,
            password,
            regReq.blind,
            regRes.response,
            null,
            null,
        );

        // tinker with the password
        //password[0] = 0;

        // authentication flow
        const client_state = new Uint8Array(160);
        const ke1 = await opaque_ristretto255_sha512_3DH_ClientInit(
            client_state,
            null,
            password,
        );

        const server_state = new Uint8Array(128);
        const ke2 = await opaque_ristretto255_sha512_3DH_ServerInit(
            server_state,
            null,
            server_private_key,
            server_public_key,
            regEnd.record,
            credential_identifier,
            oprf_seed,
            ke1,
            null,
        );

        const clientEnd = await opaque_ristretto255_sha512_3DH_ClientFinish(
            client_state,
            password,
            null,
            null,
            ke2,
        );
        assert.strictEqual(clientEnd.finish_ret, 0);

        const serverEnd = await opaque_ristretto255_sha512_3DH_ServerFinish(
            server_state,
            clientEnd.ke3,
        );
        assert.strictEqual(serverEnd.finish_ret, 0);

        assert.deepStrictEqual(clientEnd.session_key, serverEnd.session_key);

        assert.deepStrictEqual(regEnd.export_key, clientEnd.export_key);
    });
});
