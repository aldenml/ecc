/*
 * Copyright (c) 2023, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

package org.ssohub.crypto.ecc.opaque;

import org.junit.jupiter.api.Test;
import org.ssohub.crypto.ecc.Data;
import org.ssohub.crypto.ecc.Util;
import org.ssohub.crypto.ecc.ristretto255.R255Scalar;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.ssohub.crypto.ecc.libecc.ecc_opaque_ristretto255_sha512_Nh;

/**
 * @author aldenml
 */
public class OpaqueTest {

    @Test
    void testProtocolWithKnownValues() {

        Data context = Data.fromHex("4f50415155452d504f43");

        ClientInputs clientInputs = new ClientInputs(
            null,
            null,
            Data.fromHex("436f7272656374486f72736542617474657279537461706c65") // password
        );

        ServerInputs serverInputs = new ServerInputs(
            OpaqueSk.fromHex("47451a85372f8b3537e249d7b54188091fb18edde78094b43e2ba42b5eb89f0d"),
            OpaquePk.fromHex("b2fe7af9f48cc502d016729d2fe25cdd433f2c4bc904660b2a382c9b79df1a78"),
            Data.fromHex("31323334"), // credential identifier
            null, null,
            Data.fromHex("f433d0227b0b9dd54f7c4422b600e764e47fb503f1f9a0f0a47c6606b054a7fdc65347f1a08f277e22358bbabe26f823fca82c7848e9a75661f4ec5d5c1989ef") // oprfSeed
        );

        assertEquals(serverInputs.getServerPublicKey(), Opaque.recoverPublicKey(serverInputs.getServerPrivateKey()));

        R255Scalar blindRegistration = R255Scalar.fromHex("76cfbfe758db884bebb33582331ba9f159720ca8784a2a070a265d9c2d6abe01");
        CreateRegistrationRequestResult request = Opaque.createRegistrationRequestWithBlind(
            clientInputs.getPassword(),
            blindRegistration
        );
        RegistrationRequest registrationRequest = request.getRegistrationRequest();

        assertEquals("62235332ae15911d69812e9eeb6ac8fe4fa0ffc7590831d5c5e1631e01049276", registrationRequest.toHex());

        RegistrationResponse registrationResponse = Opaque.createRegistrationResponse(
            registrationRequest,
            serverInputs.getServerPublicKey(),
            serverInputs.getCredentialIdentifier(),
            serverInputs.getOprfSeed()
        );

        assertEquals("6268d13fea98ebc8e6b88d0b3cc8a78d2ac8fa8efc741cd2e966940c52c31c71b2fe7af9f48cc502d016729d2fe25cdd433f2c4bc904660b2a382c9b79df1a78", registrationResponse.toHex());

        OpaqueSeed envelopeNonce = OpaqueSeed.fromHex("ac13171b2f17bc2c74997f0fce1e1f35bec6b91fe2e12dbd323d23ba7a38dfec");
        FinalizeRegistrationRequestResult finalizeRequest = Opaque.finalizeRegistrationRequestWithNonce(
            clientInputs.getPassword(),
            blindRegistration,
            registrationResponse,
            clientInputs.getServerIdentity(),
            clientInputs.getClientIdentity(),
            Opaque.MHF.IDENTITY,
            envelopeNonce
        );
        RegistrationRecord registrationRecord = finalizeRequest.getRegistrationRecord();
        Data exportKey = finalizeRequest.getExportKey();

        assertEquals("8e5e5c04b2154336fa52ac691eb6df5f59ec7315b8467b0bba1ed4f413043b449afea0ddedbbce5c083c5d5d02aa5218bcc7100f541d841bb5974f084f7aa0b929399feb39efd17e13ce1035cbb23251da3b5126a574b239c7b73519d8847e2fac13171b2f17bc2c74997f0fce1e1f35bec6b91fe2e12dbd323d23ba7a38dfec8e8bde8d4eb9e171240b3d2dfb43ef93efe5cd15412614b3df11ecb58890047e2fa31c283e7c58c40495226cfa0ed7756e493431b85c464aad7fdaaf1ab41ac7", registrationRecord.toHex());

        ClientState clientState = new ClientState();
        R255Scalar blindLogin = R255Scalar.fromHex("6ecc102d2e7a7cf49617aad7bbe188556792d4acd60a1a8a8d2b65d4b0790308");
        OpaqueSeed clientNonce = OpaqueSeed.fromHex("da7e07376d6d6f034cfa9bb537d11b8c6b4238c334333d1f0aebb380cae6a6cc");
        OpaqueSk clientPrivateKeyshare = OpaqueSk.fromHex("22c919134c9bdd9dc0c5ef3450f18b54820f43f646a95223bf4a85b2018c2001");
        OpaquePk clientKeyshare = OpaquePk.fromHex("0c3a00c961fead8a16f818929cc976f0475e4f723519318b96f4947a7a5f9663");
        KE1 ke1 = Opaque.clientInitWithSecrets(
            clientState,
            clientInputs.getPassword(),
            blindLogin,
            clientNonce,
            clientPrivateKeyshare,
            clientKeyshare
        );

        assertEquals("1670c409ebb699a6012629451d218d42a34eddba1d2978536c45e199c60a0b4eda7e07376d6d6f034cfa9bb537d11b8c6b4238c334333d1f0aebb380cae6a6cc0c3a00c961fead8a16f818929cc976f0475e4f723519318b96f4947a7a5f9663", ke1.toHex());

        ServerState serverState = new ServerState();
        OpaqueSeed maskingNonce = OpaqueSeed.fromHex("38fe59af0df2c79f57b8780278f5ae47355fe1f817119041951c80f612fdfc6d");
        OpaqueSeed serverNonce = OpaqueSeed.fromHex("71cd9960ecef2fe0d0f7494986fa3d8b2bb01963537e60efb13981e138e3d4a1");
        OpaqueSk serverPrivateKeyshare = OpaqueSk.fromHex("2e842960258a95e28bcfef489cffd19d8ec99cc1375d840f96936da7dbb0b40d");
        OpaquePk serverKeyshare = OpaquePk.fromHex("c8c39f573135474c51660b02425bca633e339cec4e1acc69c94dd48497fe4028");
        KE2 ke2 = Opaque.serverInitWithSecrets(
            serverState,
            serverInputs.getServerIdentity(),
            serverInputs.getServerPrivateKey(),
            serverInputs.getServerPublicKey(),
            registrationRecord,
            serverInputs.getCredentialIdentifier(),
            serverInputs.getOprfSeed(),
            ke1,
            serverInputs.getClientIdentity(),
            context,
            maskingNonce,
            serverNonce,
            serverPrivateKeyshare,
            serverKeyshare
        );

        assertEquals("36b4d06f413b72004392d7359cd6a998c667533203d6a671afe81ca09a282f7238fe59af0df2c79f57b8780278f5ae47355fe1f817119041951c80f612fdfc6d378cc6b0113bf0b6afd9e0728e62ba793d5d25bb97794c154d036bf09c98c472368bffc4e35b7dc48f5a32dd3fede3b9e563f7a170d0e082d02c0a105cdf1ee0ea1928202076ff37ce174f2c669d52d8adc424e925a3bc9a4ca5ce16d9b7a1791ff7e47a0d2fa42424e5476f8cfa7bb20b2796ad877295a996ffcb049313f4e971cd9960ecef2fe0d0f7494986fa3d8b2bb01963537e60efb13981e138e3d4a1c8c39f573135474c51660b02425bca633e339cec4e1acc69c94dd48497fe402848f3b062916ea7666973222944dabe1027e5bea84b1b5d46dab64b1c6eda3170d4c9adba8afa61eb4153061d528b39102f32ecda7d7625dbc229e6630a607e03", ke2.toHex());

        ClientFinishResult clientFinishResult = Opaque.clientFinish(
            clientState,
            clientInputs.getClientIdentity(),
            clientInputs.getServerIdentity(),
            ke2,
            Opaque.MHF.IDENTITY,
            context
        );

        KE3 ke3 = clientFinishResult.getKE3();

        assertEquals(0, clientFinishResult.getResult());
        assertEquals(exportKey, clientFinishResult.getExportKey());
        assertEquals("4e23f0f84a5261918a7fc23bf1978a935cf4e320d56984079f8c7f4a54847b9e979f519928c5898927cf6aa8d51ac42dc2d0f5840956caa3a34dbc55ce74415f", ke3.toHex());

        ServerFinishResult serverFinishResult = Opaque.serverFinish(serverState, ke3);

        assertEquals(0, serverFinishResult.getResult());
        assertEquals(clientFinishResult.getSessionKey(), serverFinishResult.getSessionKey());
    }

    private static ClientInputs randomClientInputs() {
        return new ClientInputs(
            new Data(Util.str2bin("demo.ssohub.org")), // server app id
            new Data(Util.str2bin("user1")), // username
            new Data(Util.str2bin(Util.randomAlphaNum(20))) // password
        );
    }

    private static ServerInputs randomServerInputs() {
        GenerateAuthKeyPairResult keyPair = Opaque.generateAuthKeyPair();

        Data credentialIdentifier = Util.randomData(10);
        Data oprfSeed = Util.randomData(ecc_opaque_ristretto255_sha512_Nh);

        return new ServerInputs(
            keyPair.getPrivateKey(),
            keyPair.getPublicKey(),
            credentialIdentifier,
            new Data(Util.str2bin("demo.ssohub.org")), // server app id
            new Data(Util.str2bin("user1")), // username, but not used until later
            oprfSeed
        );
    }

    @Test
    void testProtocolWithRandomValues() {

        Data context = Util.randomData(10);

        ClientInputs clientInputs = randomClientInputs();

        ServerInputs serverInputs = randomServerInputs();

        CreateRegistrationRequestResult request = Opaque.createRegistrationRequest(
            clientInputs.getPassword()
        );
        RegistrationRequest registrationRequest = request.getRegistrationRequest();

        RegistrationResponse registrationResponse = Opaque.createRegistrationResponse(
            registrationRequest,
            serverInputs.getServerPublicKey(),
            serverInputs.getCredentialIdentifier(),
            serverInputs.getOprfSeed()
        );

        FinalizeRegistrationRequestResult finalizeRequest = Opaque.finalizeRegistrationRequest(
            clientInputs.getPassword(),
            request.getBlind(),
            registrationResponse,
            clientInputs.getServerIdentity(),
            clientInputs.getClientIdentity(),
            Opaque.MHF.SCRYPT
        );
        RegistrationRecord registrationRecord = finalizeRequest.getRegistrationRecord();

        ClientState clientState = new ClientState();
        KE1 ke1 = Opaque.clientInit(
            clientState,
            clientInputs.getPassword()
        );

        ServerState serverState = new ServerState();
        KE2 ke2 = Opaque.serverInit(
            serverState,
            serverInputs.getServerIdentity(),
            serverInputs.getServerPrivateKey(),
            serverInputs.getServerPublicKey(),
            registrationRecord,
            serverInputs.getCredentialIdentifier(),
            serverInputs.getOprfSeed(),
            ke1,
            serverInputs.getClientIdentity(),
            context
        );

        ClientFinishResult clientFinishResult = Opaque.clientFinish(
            clientState,
            clientInputs.getClientIdentity(),
            clientInputs.getServerIdentity(),
            ke2,
            Opaque.MHF.SCRYPT,
            context
        );

        KE3 ke3 = clientFinishResult.getKE3();

        assertEquals(0, clientFinishResult.getResult());
        assertEquals(finalizeRequest.getExportKey(), clientFinishResult.getExportKey());

        ServerFinishResult serverFinishResult = Opaque.serverFinish(serverState, ke3);

        assertEquals(0, serverFinishResult.getResult());
        assertEquals(clientFinishResult.getSessionKey(), serverFinishResult.getSessionKey());
    }

    @Test
    void testProtocolWithBadPassword() {

        Data context = Util.randomData(10);

        ClientInputs clientInputs = randomClientInputs();

        ServerInputs serverInputs = randomServerInputs();

        CreateRegistrationRequestResult request = Opaque.createRegistrationRequest(
            clientInputs.getPassword()
        );
        RegistrationRequest registrationRequest = request.getRegistrationRequest();

        RegistrationResponse registrationResponse = Opaque.createRegistrationResponse(
            registrationRequest,
            serverInputs.getServerPublicKey(),
            serverInputs.getCredentialIdentifier(),
            serverInputs.getOprfSeed()
        );

        FinalizeRegistrationRequestResult finalizeRequest = Opaque.finalizeRegistrationRequest(
            clientInputs.getPassword(),
            request.getBlind(),
            registrationResponse,
            clientInputs.getServerIdentity(),
            clientInputs.getClientIdentity(),
            Opaque.MHF.IDENTITY
        );
        RegistrationRecord registrationRecord = finalizeRequest.getRegistrationRecord();

        ClientState clientState = new ClientState();
        KE1 ke1 = Opaque.clientInit(
            clientState,
            Util.randomData(21)
        );

        ServerState serverState = new ServerState();
        KE2 ke2 = Opaque.serverInit(
            serverState,
            serverInputs.getServerIdentity(),
            serverInputs.getServerPrivateKey(),
            serverInputs.getServerPublicKey(),
            registrationRecord,
            serverInputs.getCredentialIdentifier(),
            serverInputs.getOprfSeed(),
            ke1,
            serverInputs.getClientIdentity(),
            context
        );

        ClientFinishResult clientFinishResult = Opaque.clientFinish(
            clientState,
            clientInputs.getClientIdentity(),
            clientInputs.getServerIdentity(),
            ke2,
            Opaque.MHF.IDENTITY,
            context
        );

        KE3 ke3 = clientFinishResult.getKE3();

        assertNotEquals(0, clientFinishResult.getResult());
        assertNotEquals(finalizeRequest.getExportKey(), clientFinishResult.getExportKey());

        ServerFinishResult serverFinishResult = Opaque.serverFinish(serverState, ke3);

        assertNotEquals(0, serverFinishResult.getResult());
        assertNotEquals(clientFinishResult.getSessionKey(), serverFinishResult.getSessionKey());
    }
}
