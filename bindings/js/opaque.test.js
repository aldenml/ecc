/*
 * Copyright (c) 2021-2023, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

import {
    hex2bin,
    bin2hex,
    str2bin,
    randombytes,
    libecc_promise,
    libecc,
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

        assert.strictEqual(bin2hex(registrationRequest), "5059ff249eb1551b7ce4991f3336205bde44a105a032e747d21bf382e75f7a71");

        const registrationResponse = opaque_CreateRegistrationResponse(
            registrationRequest,
            serverInputs.serverPublicKey,
            serverInputs.credentialIdentifier,
            serverInputs.oprfSeed,
        );

        assert.strictEqual(bin2hex(registrationResponse), "7408a268083e03abc7097fc05b587834539065e86fb0c7b6342fcf5e01e5b019b2fe7af9f48cc502d016729d2fe25cdd433f2c4bc904660b2a382c9b79df1a78");

        const envelopeNonce = hex2bin("ac13171b2f17bc2c74997f0fce1e1f35bec6b91fe2e12dbd323d23ba7a38dfec");
        const finalizeRequest = opaque_FinalizeRegistrationRequestWithNonce(
            clientInputs.password,
            blindRegistration,
            registrationResponse,
            clientInputs.serverIdentity,
            clientInputs.clientIdentity,
            libecc.ecc_opaque_ristretto255_sha512_MHF_IDENTITY,
            null,
            envelopeNonce,
        );
        const registrationRecord = finalizeRequest.registrationRecord;
        const exportKey = finalizeRequest.exportKey;

        assert.strictEqual(bin2hex(registrationRecord), "2ec892bdbf9b3e2ea834be9eb11f5d187e64ba661ec041c0a3b66db8b7d6cc301ac5844383c7708077dea41cbefe2fa15724f449e535dd7dd562e66f5ecfb95864eadddec9db5874959905117dad40a4524111849799281fefe3c51fa82785c5ac13171b2f17bc2c74997f0fce1e1f35bec6b91fe2e12dbd323d23ba7a38dfecb9dbe7d48cf714fc3533becab6faf60b783c94d258477eb74ecc453413bf61c53fd58f0fb3c1175410b674c02e1b59b2d729a865b709db3dc4ee2bb45703d5a8");

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

        assert.strictEqual(bin2hex(ke1), "c4dedb0ba6ed5d965d6f250fbe554cd45cba5dfcce3ce836e4aee778aa3cd44dda7e07376d6d6f034cfa9bb537d11b8c6b4238c334333d1f0aebb380cae6a6cc0c3a00c961fead8a16f818929cc976f0475e4f723519318b96f4947a7a5f9663");

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

        assert.strictEqual(bin2hex(ke2), "7e308140890bcde30cbcea28b01ea1ecfbd077cff62c4def8efa075aabcbb47138fe59af0df2c79f57b8780278f5ae47355fe1f817119041951c80f612fdfc6dd6ec60bcdb26dc455ddf3e718f1020490c192d70dfc7e403981179d8073d1146a4f9aa1ced4e4cd984c657eb3b54ced3848326f70331953d91b02535af44d9fe0610f003be80cb2098357928c8ea17bb065af33095f39d4e0b53b1687f02d522d96bad4ca354293d5c401177ccbd302cf565b96c327f71bc9eaf2890675d2fbb71cd9960ecef2fe0d0f7494986fa3d8b2bb01963537e60efb13981e138e3d4a1c8c39f573135474c51660b02425bca633e339cec4e1acc69c94dd48497fe40287f33611c2cf0eef57adbf48942737d9421e6b20e4b9d6e391d4168bf4bf96ea57aa42ad41c977605e027a9ef706a349f4b2919fe3562c8e86c4eeecf2f9457d4");

        const clientFinishResult = opaque_ClientFinish(
            clientState,
            clientInputs.clientIdentity,
            clientInputs.serverIdentity,
            ke2,
            libecc.ecc_opaque_ristretto255_sha512_MHF_IDENTITY,
            null,
            context,
        );

        const ke3 = clientFinishResult.ke3;

        assert.strictEqual(clientFinishResult.result, 0);
        assert.deepStrictEqual(clientFinishResult.exportKey, exportKey);
        assert.strictEqual(bin2hex(ke3), "df9a13cd256091f90f0fcb2ef6b3411e4aebff07bb0813299c0ec7f5dedd33a7681231a001a82f1dece1777921f42abfeee551ee34392e1c9743c5cc1dc1ef8c");

        const serverFinishResult = opaque_ServerFinish(serverState, ke3);

        assert.strictEqual(serverFinishResult.result, 0);
        assert.deepStrictEqual(serverFinishResult.sessionKey, clientFinishResult.sessionKey);
    });

    it("test protocol with random values and scrypt", async () => {
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
            null,
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
            null,
            context,
        );

        const ke3 = clientFinishResult.ke3;

        assert.strictEqual(clientFinishResult.result, 0);
        assert.deepStrictEqual(clientFinishResult.exportKey, finalizeRequest.exportKey);

        const serverFinishResult = opaque_ServerFinish(serverState, ke3);

        assert.strictEqual(serverFinishResult.result, 0);
        assert.deepStrictEqual(serverFinishResult.sessionKey, clientFinishResult.sessionKey);
    });

    it("test protocol with random values and argon2id", async () => {
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
            libecc.ecc_opaque_ristretto255_sha512_MHF_ARGON2ID,
            str2bin("abcdabcdabcdabcd"),
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
            libecc.ecc_opaque_ristretto255_sha512_MHF_ARGON2ID,
            str2bin("abcdabcdabcdabcd"),
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
            null,
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
            null,
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
