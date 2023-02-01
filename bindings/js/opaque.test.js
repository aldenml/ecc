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
    libecc_promise,
    libecc, str2bin,
} from "./util.js";
import {
    opaque_RecoverPublicKey,
    opaque_CreateRegistrationRequestWithBlind,
    opaque_CreateRegistrationRequest,
    opaque_CreateRegistrationResponse,
    opaque_FinalizeRegistrationRequestWithNonce,
    opaque_FinalizeRegistrationRequest,
    opaque_ClientInitWithSecrets,
    opaque_ClientInit,
    opaque_ServerInitWithSecrets,
    opaque_ServerInit,
    opaque_ClientFinish,
    opaque_ServerFinish,
    opaque_GenerateAuthKeyPair,
} from "./opaque.js"
import assert from "assert";

describe("OPAQUE(ristretto255, SHA-512)", () => {

    it("test protocol with known values", async () => {
        await libecc_promise;

        const context = hex2bin("4f50415155452d504f43");

        const clientInputs = {
            serverIdentity: null,
            clientIdentity: null,
            password: hex2bin("436f7272656374486f72736542617474657279537461706c65"),
        };

        const serverInputs = {
            serverPrivateKey: hex2bin("47451a85372f8b3537e249d7b54188091fb18edde78094b43e2ba42b5eb89f0d"),
            serverPublicKey: hex2bin("b2fe7af9f48cc502d016729d2fe25cdd433f2c4bc904660b2a382c9b79df1a78"),
            credentialIdentifier: hex2bin("31323334"),
            serverIdentity: null,
            clientIdentity: null,
            oprfSeed: hex2bin("f433d0227b0b9dd54f7c4422b600e764e47fb503f1f9a0f0a47c6606b054a7fdc65347f1a08f277e22358bbabe26f823fca82c7848e9a75661f4ec5d5c1989ef"),

        };

        assert.deepStrictEqual(serverInputs.serverPublicKey, opaque_RecoverPublicKey(serverInputs.serverPrivateKey));

        const blindRegistration = hex2bin("76cfbfe758db884bebb33582331ba9f159720ca8784a2a070a265d9c2d6abe01");
        const request = opaque_CreateRegistrationRequestWithBlind(clientInputs.password, blindRegistration);
        const registrationRequest = request.registrationRequest;

        assert.strictEqual(bin2hex(registrationRequest), "62235332ae15911d69812e9eeb6ac8fe4fa0ffc7590831d5c5e1631e01049276");

        const registrationResponse = opaque_CreateRegistrationResponse(
            registrationRequest,
            serverInputs.serverPublicKey,
            serverInputs.credentialIdentifier,
            serverInputs.oprfSeed,
        );

        assert.strictEqual(bin2hex(registrationResponse), "6268d13fea98ebc8e6b88d0b3cc8a78d2ac8fa8efc741cd2e966940c52c31c71b2fe7af9f48cc502d016729d2fe25cdd433f2c4bc904660b2a382c9b79df1a78");

        const envelopeNonce = hex2bin("ac13171b2f17bc2c74997f0fce1e1f35bec6b91fe2e12dbd323d23ba7a38dfec");
        const finalizeRequest = opaque_FinalizeRegistrationRequestWithNonce(
            clientInputs.password,
            blindRegistration,
            registrationResponse,
            clientInputs.serverIdentity,
            clientInputs.clientIdentity,
            libecc.ecc_opaque_ristretto255_sha512_MHF_IDENTITY,
            envelopeNonce,
        );
        const registrationRecord = finalizeRequest.registrationRecord;
        const exportKey = finalizeRequest.exportKey;

        assert.strictEqual(bin2hex(registrationRecord), "8e5e5c04b2154336fa52ac691eb6df5f59ec7315b8467b0bba1ed4f413043b449afea0ddedbbce5c083c5d5d02aa5218bcc7100f541d841bb5974f084f7aa0b929399feb39efd17e13ce1035cbb23251da3b5126a574b239c7b73519d8847e2fac13171b2f17bc2c74997f0fce1e1f35bec6b91fe2e12dbd323d23ba7a38dfec8e8bde8d4eb9e171240b3d2dfb43ef93efe5cd15412614b3df11ecb58890047e2fa31c283e7c58c40495226cfa0ed7756e493431b85c464aad7fdaaf1ab41ac7");

        const clientState = new Uint8Array(libecc.ecc_opaque_ristretto255_sha512_CLIENTSTATESIZE);
        const blindLogin = hex2bin("6ecc102d2e7a7cf49617aad7bbe188556792d4acd60a1a8a8d2b65d4b0790308");
        const clientNonce = hex2bin("da7e07376d6d6f034cfa9bb537d11b8c6b4238c334333d1f0aebb380cae6a6cc");
        const clientPrivateKeyshare = hex2bin("22c919134c9bdd9dc0c5ef3450f18b54820f43f646a95223bf4a85b2018c2001");
        const clientKeyshare = hex2bin("0c3a00c961fead8a16f818929cc976f0475e4f723519318b96f4947a7a5f9663");
        const ke1 = opaque_ClientInitWithSecrets(
            clientState,
            clientInputs.password,
            blindLogin,
            clientNonce,
            clientPrivateKeyshare,
            clientKeyshare
        );

        assert.strictEqual(bin2hex(ke1), "1670c409ebb699a6012629451d218d42a34eddba1d2978536c45e199c60a0b4eda7e07376d6d6f034cfa9bb537d11b8c6b4238c334333d1f0aebb380cae6a6cc0c3a00c961fead8a16f818929cc976f0475e4f723519318b96f4947a7a5f9663");

        const serverState = new Uint8Array(libecc.ecc_opaque_ristretto255_sha512_SERVERSTATESIZE);
        const maskingNonce = hex2bin("38fe59af0df2c79f57b8780278f5ae47355fe1f817119041951c80f612fdfc6d");
        const serverNonce = hex2bin("71cd9960ecef2fe0d0f7494986fa3d8b2bb01963537e60efb13981e138e3d4a1");
        const serverPrivateKeyshare = hex2bin("2e842960258a95e28bcfef489cffd19d8ec99cc1375d840f96936da7dbb0b40d");
        const serverKeyshare = hex2bin("c8c39f573135474c51660b02425bca633e339cec4e1acc69c94dd48497fe4028");
        const ke2 = opaque_ServerInitWithSecrets(
            serverState,
            serverInputs.serverIdentity,
            serverInputs.serverPrivateKey,
            serverInputs.serverPublicKey,
            registrationRecord,
            serverInputs.credentialIdentifier,
            serverInputs.oprfSeed,
            ke1,
            serverInputs.clientIdentity,
            context,
            maskingNonce,
            serverNonce,
            serverPrivateKeyshare,
            serverKeyshare,
        );

        assert.strictEqual(bin2hex(ke2), "36b4d06f413b72004392d7359cd6a998c667533203d6a671afe81ca09a282f7238fe59af0df2c79f57b8780278f5ae47355fe1f817119041951c80f612fdfc6d378cc6b0113bf0b6afd9e0728e62ba793d5d25bb97794c154d036bf09c98c472368bffc4e35b7dc48f5a32dd3fede3b9e563f7a170d0e082d02c0a105cdf1ee0ea1928202076ff37ce174f2c669d52d8adc424e925a3bc9a4ca5ce16d9b7a1791ff7e47a0d2fa42424e5476f8cfa7bb20b2796ad877295a996ffcb049313f4e971cd9960ecef2fe0d0f7494986fa3d8b2bb01963537e60efb13981e138e3d4a1c8c39f573135474c51660b02425bca633e339cec4e1acc69c94dd48497fe402848f3b062916ea7666973222944dabe1027e5bea84b1b5d46dab64b1c6eda3170d4c9adba8afa61eb4153061d528b39102f32ecda7d7625dbc229e6630a607e03");

        const clientFinishResult = opaque_ClientFinish(
            clientState,
            clientInputs.clientIdentity,
            clientInputs.serverIdentity,
            ke2,
            libecc.ecc_opaque_ristretto255_sha512_MHF_IDENTITY,
            context,
        );

        const ke3 = clientFinishResult.ke3;

        assert.strictEqual(clientFinishResult.result, 0);
        assert.deepStrictEqual(clientFinishResult.exportKey, exportKey);
        assert.strictEqual(bin2hex(ke3), "4e23f0f84a5261918a7fc23bf1978a935cf4e320d56984079f8c7f4a54847b9e979f519928c5898927cf6aa8d51ac42dc2d0f5840956caa3a34dbc55ce74415f");

        const serverFinishResult = opaque_ServerFinish(serverState, ke3);

        assert.strictEqual(serverFinishResult.result, 0);
        assert.deepStrictEqual(serverFinishResult.sessionKey, clientFinishResult.sessionKey);
    });

    it("test protocol with random values", async () => {
        await libecc_promise;

        const context = randombytes(10);

        const clientInputs = {
            serverIdentity: str2bin("demo.ssohub.org"),
            clientIdentity: str2bin("user1"),
            password: randombytes(20),
        };

        const serverKeyPair = opaque_GenerateAuthKeyPair();

        const serverInputs = {
            serverPrivateKey: serverKeyPair.privateKey,
            serverPublicKey: serverKeyPair.publicKey,
            credentialIdentifier: randombytes(10),
            serverIdentity: str2bin("demo.ssohub.org"),
            clientIdentity: str2bin("user1"),
            oprfSeed: randombytes(libecc.ecc_opaque_ristretto255_sha512_Nh),
        };

        const request = opaque_CreateRegistrationRequest(clientInputs.password);
        const registrationRequest = request.registrationRequest;

        const registrationResponse = opaque_CreateRegistrationResponse(
            registrationRequest,
            serverInputs.serverPublicKey,
            serverInputs.credentialIdentifier,
            serverInputs.oprfSeed,
        );

        const finalizeRequest = opaque_FinalizeRegistrationRequest(
            clientInputs.password,
            request.blind,
            registrationResponse,
            clientInputs.serverIdentity,
            clientInputs.clientIdentity,
            libecc.ecc_opaque_ristretto255_sha512_MHF_SCRYPT,
        );
        const registrationRecord = finalizeRequest.registrationRecord;

        const clientState = new Uint8Array(libecc.ecc_opaque_ristretto255_sha512_CLIENTSTATESIZE);
        const ke1 = opaque_ClientInit(
            clientState,
            clientInputs.password,
        );

        const serverState = new Uint8Array(libecc.ecc_opaque_ristretto255_sha512_SERVERSTATESIZE);
        const ke2 = opaque_ServerInit(
            serverState,
            serverInputs.serverIdentity,
            serverInputs.serverPrivateKey,
            serverInputs.serverPublicKey,
            registrationRecord,
            serverInputs.credentialIdentifier,
            serverInputs.oprfSeed,
            ke1,
            serverInputs.clientIdentity,
            context,
        );

        const clientFinishResult = opaque_ClientFinish(
            clientState,
            clientInputs.clientIdentity,
            clientInputs.serverIdentity,
            ke2,
            libecc.ecc_opaque_ristretto255_sha512_MHF_SCRYPT,
            context,
        );

        const ke3 = clientFinishResult.ke3;

        assert.strictEqual(clientFinishResult.result, 0);
        assert.deepStrictEqual(clientFinishResult.exportKey, finalizeRequest.exportKey);

        const serverFinishResult = opaque_ServerFinish(serverState, ke3);

        assert.strictEqual(serverFinishResult.result, 0);
        assert.deepStrictEqual(serverFinishResult.sessionKey, clientFinishResult.sessionKey);
    });

    it("test protocol with bad password", async () => {
        await libecc_promise;

        const context = randombytes(10);

        const clientInputs = {
            serverIdentity: str2bin("demo.ssohub.org"),
            clientIdentity: str2bin("user1"),
            password: randombytes(20),
        };

        const serverKeyPair = opaque_GenerateAuthKeyPair();

        const serverInputs = {
            serverPrivateKey: serverKeyPair.privateKey,
            serverPublicKey: serverKeyPair.publicKey,
            credentialIdentifier: randombytes(10),
            serverIdentity: str2bin("demo.ssohub.org"),
            clientIdentity: str2bin("user1"),
            oprfSeed: randombytes(libecc.ecc_opaque_ristretto255_sha512_Nh),
        };

        const request = opaque_CreateRegistrationRequest(clientInputs.password);
        const registrationRequest = request.registrationRequest;

        const registrationResponse = opaque_CreateRegistrationResponse(
            registrationRequest,
            serverInputs.serverPublicKey,
            serverInputs.credentialIdentifier,
            serverInputs.oprfSeed,
        );

        const finalizeRequest = opaque_FinalizeRegistrationRequest(
            clientInputs.password,
            request.blind,
            registrationResponse,
            clientInputs.serverIdentity,
            clientInputs.clientIdentity,
            libecc.ecc_opaque_ristretto255_sha512_MHF_SCRYPT,
        );
        const registrationRecord = finalizeRequest.registrationRecord;

        const clientState = new Uint8Array(libecc.ecc_opaque_ristretto255_sha512_CLIENTSTATESIZE);
        const ke1 = opaque_ClientInit(
            clientState,
            randombytes(20),
        );

        const serverState = new Uint8Array(libecc.ecc_opaque_ristretto255_sha512_SERVERSTATESIZE);
        const ke2 = opaque_ServerInit(
            serverState,
            serverInputs.serverIdentity,
            serverInputs.serverPrivateKey,
            serverInputs.serverPublicKey,
            registrationRecord,
            serverInputs.credentialIdentifier,
            serverInputs.oprfSeed,
            ke1,
            serverInputs.clientIdentity,
            context,
        );

        const clientFinishResult = opaque_ClientFinish(
            clientState,
            clientInputs.clientIdentity,
            clientInputs.serverIdentity,
            ke2,
            libecc.ecc_opaque_ristretto255_sha512_MHF_SCRYPT,
            context,
        );

        const ke3 = clientFinishResult.ke3;

        assert.notStrictEqual(clientFinishResult.result, 0);
        assert.notDeepStrictEqual(clientFinishResult.exportKey, finalizeRequest.exportKey);

        const serverFinishResult = opaque_ServerFinish(serverState, ke3);

        assert.notStrictEqual(serverFinishResult.result, 0);
        assert.notDeepStrictEqual(serverFinishResult.sessionKey, clientFinishResult.sessionKey);
    });

});
