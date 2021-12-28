/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

import {
    hex2bin,
    bin2hex,
    randombytes,
} from "./util.js";
import libecc_module from "./libecc.js";
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

    it("CreateRegistrationResponse", async () => {
        const libecc = await libecc_module();

        const registration_request = hex2bin("e61a3864330ae06a4fb67dd3710ef96e73ad0fc9f057feedee96307680081518");
        const server_public_key = hex2bin("18d5035fd0a9c1d6412226df037125901a43f4dff660c0549d402f672bcc0933");
        const credential_identifier = hex2bin("31323334");
        const oprf_seed = hex2bin("5c4f99877d253be5817b4b03f37b6da680b0d5671d1ec5351fa61c5d82eab28b9de4c4e170f27e433ba377c71c49aa62ad26391ee1cac17011d8a7e9406657c8");

        let registration_response = new Uint8Array(64);
        let oprf_key = new Uint8Array(32);

        libecc.ecc_opaque_ristretto255_sha512_CreateRegistrationResponse(
            registration_response,
            oprf_key,
            registration_request,
            server_public_key,
            credential_identifier, credential_identifier.length,
            oprf_seed,
        );

        assert.strictEqual(bin2hex(registration_response), "8e7f5534f0a2ff2e2c0bc9ac5952f870711f74e1547199425b79ca80c9656b0d18d5035fd0a9c1d6412226df037125901a43f4dff660c0549d402f672bcc0933");
        assert.strictEqual(bin2hex(oprf_key), "840f43a856a90968af35423ef4951133ba2fed30f7679ec1ee490fb257ef4f02");
    });

    it("FinalizeRequest", async () => {
        const libecc = await libecc_module();

        const password = hex2bin("436f7272656374486f72736542617474657279537461706c65");
        const blind = hex2bin("17f9d715dcc44faed5608f06d1106c623676206813756f9f888efb7989106c06");
        const registration_response = hex2bin("8e7f5534f0a2ff2e2c0bc9ac5952f870711f74e1547199425b79ca80c9656b0d18d5035fd0a9c1d6412226df037125901a43f4dff660c0549d402f672bcc0933");
        const nonce = hex2bin("88888888dcc44faed5608f06d1106c623676206813756f9f888efb7989106c06");

        let record = new Uint8Array(192);
        let export_key = new Uint8Array(64);
        libecc.ecc_opaque_ristretto255_sha512_FinalizeRequestWithNonce(
            record,
            export_key,
            new Uint8Array(0),
            password, password.length,
            blind,
            registration_response,
            new Uint8Array(0), 0,
            new Uint8Array(0), 0,
            nonce
        );

        assert.strictEqual(bin2hex(record), "0436d5abd24da98174f917663ccff94b70b93f81abaf9651539197345f857820d561753" +
            "b08f52c98a21b62df41366ff3f6f5853108f5a63c574acdd56db5885e8ff145ad6f100d" +
            "14763ca834b0d599d4bc8da03261dc2fb42b27ac495f0bb09588888888dcc44faed5608" +
            "f06d1106c623676206813756f9f888efb7989106c06e8d34f02855380ad30d71710833b" +
            "708330305cb5ced5d373b721ced517dd75d621b9d12ad9646a60dffd80b5ab98018d04e" +
            "a32677f29808d62de81aff22c0535");
        assert.strictEqual(bin2hex(export_key), "8a17e3b8fdbf042a36383a8be6479ce66fd5e916969266a45f7957f1bbd585d566c62f1" +
            "91c6ad70fd2ac5b784c79355b5e9ecd35bee4fe27b2ece31e1133ad06");
    });

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
