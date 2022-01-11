/*
 * Copyright (c) 2021-2022, Alden Torres
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
            password,
        );

        const server_state = new Uint8Array(128);
        const ke2 = await opaque_ristretto255_sha512_3DH_ServerInit(
            server_state,
            null,
            server_private_key,
            server_public_key,
            null,
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

    it("test vector 1", async () => {
        const libecc = await libecc_module();

        const context = hex2bin("4f50415155452d504f43");
        const oprf_seed = hex2bin("5c4f99877d253be5817b4b03f37b6da680b0d5671d1ec5351fa61c5d82eab28b9de4c4e170f27e433ba377c71c49aa62ad26391ee1cac17011d8a7e9406657c8");
        const credential_identifier = hex2bin("31323334");
        const password = hex2bin("436f7272656374486f72736542617474657279537461706c65");
        const envelope_nonce = hex2bin("71b8f14b7a1059cdadc414c409064a22cf9e970b0ffc6f1fc6fdd539c4676775");
        const masking_nonce = hex2bin("54f9341ca183700f6b6acf28dbfe4a86afad788805de49f2d680ab86ff39ed7f");
        const server_private_key = hex2bin("16eb9dc74a3df2033cd738bf2cfb7a3670c569d7749f284b2b241cb237e7d10f");
        const server_public_key = hex2bin("18d5035fd0a9c1d6412226df037125901a43f4dff660c0549d402f672bcc0933");
        const server_nonce = hex2bin("f9c5ec75a8cd571370add249e99cb8a8c43f6ef05610ac6e354642bf4fedbf69");
        const client_nonce = hex2bin("804133133e7ee6836c8515752e24bb44d323fef4ead34cde967798f2e9784f69");
        const server_keyshare = hex2bin("6e77d4749eb304c4d74be9457c597546bc22aed699225499910fc913b3e90712");
        const client_keyshare = hex2bin("f67926bd036c5dc4971816b9376e9f64737f361ef8269c18f69f1ab555e96d4a");
        const server_private_keyshare = hex2bin("f8e3e31543dd6fc86833296726773d51158291ab9afd666bb55dce83474c1101");
        const client_private_keyshare = hex2bin("4230d62ea740b13e178185fc517cf2c313e6908c4cd9fb42154870ff3490c608");
        const blind_registration = hex2bin("c62937d17dc9aa213c9038f84fe8c5bf3d953356db01c4d48acb7cae48e6a504");
        const blind_login = hex2bin("b5f458822ea11c900ad776e38e29d7be361f75b4d79b55ad74923299bf8d6503");

        let registration_request = new Uint8Array(libecc.ecc_opaque_ristretto255_sha512_REGISTRATIONREQUESTSIZE);
        libecc.ecc_opaque_ristretto255_sha512_CreateRegistrationRequestWithBlind(
            registration_request,
            password, password.length,
            blind_registration
        );
        assert.strictEqual(bin2hex(registration_request), "ac7a6330f91d1e5c87365630c7be58641885d59ffe4d3f8a49c094271993331d");

        let registration_response = new Uint8Array(libecc.ecc_opaque_ristretto255_sha512_REGISTRATIONRESPONSESIZE);
        let oprf_key = new Uint8Array(32);
        libecc.ecc_opaque_ristretto255_sha512_CreateRegistrationResponse(
            registration_response,
            oprf_key,
            registration_request,
            server_public_key,
            credential_identifier, credential_identifier.length,
            oprf_seed
        );
        assert.strictEqual(bin2hex(registration_response), "5c7d3c70cf7478ead859bb879b37cce78baef3b9d81e04f4c790ce25f2830e2e18d5035fd0a9c1d6412226df037125901a43f4dff660c0549d402f672bcc0933");
        assert.strictEqual(bin2hex(oprf_key), "3f76113135e6ca7e51ac5bb3e8774eb84709ad36b8907ec8f7bc353782871906");

        let record = new Uint8Array(libecc.ecc_opaque_ristretto255_sha512_REGISTRATIONUPLOADSIZE);
        let export_key = new Uint8Array(64);
        libecc.ecc_opaque_ristretto255_sha512_FinalizeRequestWithNonce(
            record,
            export_key,
            password, password.length,
            blind_registration,
            registration_response,
            new Uint8Array(0), 0,
            new Uint8Array(0), 0,
            libecc.ecc_opaque_ristretto255_sha512_MHF_IDENTITY,
            envelope_nonce
        );

        assert.strictEqual(bin2hex(record), "60c9b59f46e93a2dc8c5dd0dd101fad1838f4c4c026691e9" +
            "d18d3de8f2b3940d7981498360f8f276df1dfb852a93ec4f4a0189dec5a96363296a6" +
            "93fc8a51fb052ae8318dac48be7e3c3cd290f7b8c12b807617b7f9399417deed00158" +
            "281ac771b8f14b7a1059cdadc414c409064a22cf9e970b0ffc6f1fc6fdd539c467677" +
            "50a343dd3f683692f4ed987ff286a4ece0813a4942e23477920608f261e1ab6f8727f" +
            "532c9fd0cde8ec492cb76efdc855da76d0b6ccbe8a4dc0ba2709d63c4517");

        let client_state = new Uint8Array(libecc.ecc_opaque_ristretto255_sha512_CLIENTSTATESIZE);
        let ke1 = new Uint8Array(libecc.ecc_opaque_ristretto255_sha512_KE1SIZE);
        libecc.ecc_opaque_ristretto255_sha512_3DH_ClientInitWithSecrets(
            ke1,
            client_state,
            password, password.length,
            blind_login,
            client_nonce,
            client_private_keyshare,
            client_keyshare
        );

        assert.strictEqual(bin2hex(ke1), "e4e7ce5bf96ddb2924faf816774b26a0ec7a6dd9d3a5bced1f4a3675c3cfd14c" +
            "804133133e7ee6836c8515752e24bb44d323fef4ead34cde967798f2e9784f69f6792" +
            "6bd036c5dc4971816b9376e9f64737f361ef8269c18f69f1ab555e96d4a");

        let server_state = new Uint8Array(libecc.ecc_opaque_ristretto255_sha512_SERVERSTATESIZE);
        let ke2 = new Uint8Array(libecc.ecc_opaque_ristretto255_sha512_KE2SIZE);
        libecc.ecc_opaque_ristretto255_sha512_3DH_ServerInitWithSecrets(
            ke2,
            server_state,
            null, 0,
            server_private_key,
            server_public_key,
            null, 0,
            record,
            credential_identifier, credential_identifier.length,
            oprf_seed,
            ke1,
            context, context.length,
            masking_nonce,
            server_nonce,
            server_private_keyshare,
            server_keyshare
        );

        assert.strictEqual(bin2hex(ke2), "1af11be29a90322dc16462d0861b1eb617611fe2f05e5e9860c164592d4f7f62" +
            "54f9341ca183700f6b6acf28dbfe4a86afad788805de49f2d680ab86ff39ed7f76011" +
            "9ed2f12f6ec4983f2c598068057af146fd09133c75b229145b7580d53cac4ba581155" +
            "2e6786837a3e03d9f7971df0dad4a04fd6a6d4164101c91137a87f4afde7dae72daf2" +
            "620082f46413bbb3071767d549833bcc523acc645b571a66318b0b1f8bf4b23de3542" +
            "8373aa1d3a45c1e89eff88f03f9446e5dfc23b6f8394f9c5ec75a8cd571370add249e" +
            "99cb8a8c43f6ef05610ac6e354642bf4fedbf696e77d4749eb304c4d74be9457c5975" +
            "46bc22aed699225499910fc913b3e907120638f222a1a08460f4e40d0686830d3d608" +
            "ce89789489161438bf6809dbbce3a6ddb0ce8702576843b58465d6cedd4e965f3f81b" +
            "92992ecec0e2137b66eff0b4");

        let ke3 = new Uint8Array(libecc.ecc_opaque_ristretto255_sha512_KE3SIZE);
        let client_session_key = new Uint8Array(64);
        let export_key2 = new Uint8Array(64);
        const client_finish_ret = libecc.ecc_opaque_ristretto255_sha512_3DH_ClientFinish(
            ke3,
            client_session_key,
            export_key2,
            client_state,
            password, password.length,
            null, 0,
            null, 0,
            ke2,
            libecc.ecc_opaque_ristretto255_sha512_MHF_IDENTITY,
            context, context.length
        );
        assert.strictEqual(bin2hex(ke3), "1c0c743ff88f1a4ff07350eef61e899ae25d7fb23d555926b218bac4c1963071" +
            "5038c56cca247630be8a8e66f3ff18b89c1bc97e1e2192fd7f14f2f60ed084a3");
        assert.strictEqual(client_finish_ret, 0);

        let server_session_key = new Uint8Array(64);
        const server_finish_ret = libecc.ecc_opaque_ristretto255_sha512_3DH_ServerFinish(
            server_session_key,
            server_state,
            ke3
        );
        assert.strictEqual(server_finish_ret, 0);

        assert.deepStrictEqual(client_session_key, server_session_key);
        assert.deepStrictEqual(export_key, export_key2);

        assert.strictEqual(bin2hex(client_session_key), "05d03f4143e5866844f7ae921d3b48f3d611e930a6c4be0993a98290" +
            "085110c5a27a2e5f92aeed861b90de068a51a952aa75bf97589be7c7104a4c30cc357506");
        assert.strictEqual(bin2hex(export_key), "8408f92d282c7f4b0f5462e5206bd92937a4d53b0dcdef90afffd015c" +
            "5dee44dc4dc5ad35d1681c97e2b66de09203ac359a69f1d45f8c97dbc907589177ccc24");
    });
});
