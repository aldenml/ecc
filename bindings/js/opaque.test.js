/*
 * Copyright (c) 2021-2023, Alden Torres
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
        const client_state = new Uint8Array(361);
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
        assert.strictEqual(bin2hex(registration_request), "7e4f1ab9fbd6bd61d85d3ccc2170513bc574aac7da4ec4d9c3e336f82788f86e");

        let registration_response = new Uint8Array(libecc.ecc_opaque_ristretto255_sha512_REGISTRATIONRESPONSESIZE);
        libecc.ecc_opaque_ristretto255_sha512_CreateRegistrationResponse(
            registration_response,
            registration_request,
            server_public_key,
            credential_identifier, credential_identifier.length,
            oprf_seed
        );
        assert.strictEqual(bin2hex(registration_response), "2c5ee2986e4eeec3f2191d61292058cfb5b0d0cd6d356f19876fe5028ba6f74c18d5035fd0a9c1d6412226df037125901a43f4dff660c0549d402f672bcc0933");

        let record = new Uint8Array(libecc.ecc_opaque_ristretto255_sha512_REGISTRATIONRECORDSIZE);
        let export_key = new Uint8Array(64);
        libecc.ecc_opaque_ristretto255_sha512_FinalizeRegistrationRequestWithNonce(
            record,
            export_key,
            blind_registration,
            registration_response,
            new Uint8Array(0), 0,
            new Uint8Array(0), 0,
            libecc.ecc_opaque_ristretto255_sha512_MHF_IDENTITY,
            envelope_nonce
        );

        assert.strictEqual(bin2hex(record), "a2da2ce00092a40575c5b1e62e21ac85c11a59384bd712bf64dc6bd1736bfc5941ebbefe623599f5f9b0992ddb5af4ef7f0ca6f7f2d64683134e1eba7bcf4daae10f174a22a050b3cd60917b3b527e3d3758c399f16c4dbefbffb0afd790eb220000000000000000000000000000000000000000000000000000000000000000f949f9f0ecb8875ea148d402e33571f504cf2d7c84157aa4faed419bf557a53de14d69bc3988aa08e75a04c6b5cac9640c06233a79f7b20a0faa23ec534002d5");

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

        assert.strictEqual(bin2hex(ke1), "30380e85ebd3f712ecf3f3bb59505214c1fbabdeb98ea6f19d9ed499ac640c51804133133e7ee6836c8515752e24bb44d323fef4ead34cde967798f2e9784f69f67926bd036c5dc4971816b9376e9f64737f361ef8269c18f69f1ab555e96d4a");

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

        assert.strictEqual(bin2hex(ke2), "bcb6f228b24fccedb96a754f9531ec696079951ac7661a070e77739c5779f40754f9341ca183700f6b6acf28dbfe4a86afad788805de49f2d680ab86ff39ed7f0062edf06de0176d5ee8b22dee02f960ad1a28546b6722a9a1504a8715d7c8f6f6e30e875b24b346c3c3c3cd5bee8fa78cceebb795a26331e7319799d3990e75318df9ac592479ad4028e0164a9c6e26058b6df67eae674abffbcb0b455e0c73381dcd7cb6da63c4bc969a95f6881e5411b4ef9a2671073018d5f2159a05ab1df9c5ec75a8cd571370add249e99cb8a8c43f6ef05610ac6e354642bf4fedbf696e77d4749eb304c4d74be9457c597546bc22aed699225499910fc913b3e90712a5909a4c80a7ab569f9c30e16482ddfea0d3027c6ee721e740209bf91dec5c6bd37d62a899d7578b9e6d7587aa0d58f88c97c6efadc810f203269aa76ad3de33");

        let ke3 = new Uint8Array(libecc.ecc_opaque_ristretto255_sha512_KE3SIZE);
        let client_session_key = new Uint8Array(64);
        let export_key2 = new Uint8Array(64);
        const client_finish_ret = libecc.ecc_opaque_ristretto255_sha512_3DH_ClientFinish(
            ke3,
            client_session_key,
            export_key2,
            client_state,
            null, 0,
            null, 0,
            ke2,
            libecc.ecc_opaque_ristretto255_sha512_MHF_IDENTITY,
            context, context.length,
        );
        // assert.strictEqual(bin2hex(ke3), "93430894d8d91ac696b0573436e823ecc20e5e6771e6b8abd7a44a1a7c2709f50a9fc65ff5c1322b49b0dc8741d2e45da4fdf353b741ebd8adf5b9dcae02e42a");
        // assert.strictEqual(client_finish_ret, 0);

        let server_session_key = new Uint8Array(64);
        const server_finish_ret = libecc.ecc_opaque_ristretto255_sha512_3DH_ServerFinish(
            server_session_key,
            server_state,
            ke3
        );
        // assert.strictEqual(server_finish_ret, 0);
        //
        // assert.deepStrictEqual(client_session_key, server_session_key);
        // assert.deepStrictEqual(export_key, export_key2);
        //
        // assert.strictEqual(bin2hex(client_session_key), "baaa4ff93aaa7e195600f7b8d49956d6929c84b43573f7617a4c4bae96030b5b1c85fea55ae4984883e0e74f95c14bc8734da220647a1948f19a30e8fd923d24");
        // assert.strictEqual(bin2hex(export_key), "36596118f765de69bd6d5e9b8bf0e2c26dd2f64ea2a712e284614b6b90949d2ca1a647e9f0a131f88a9a28f54290b65bed006ae8d717c461ce9bddc109e44aed");
    });
});
