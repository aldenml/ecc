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

        assertEquals("5059ff249eb1551b7ce4991f3336205bde44a105a032e747d21bf382e75f7a71", registrationRequest.toHex());

        RegistrationResponse registrationResponse = Opaque.createRegistrationResponse(
            registrationRequest,
            serverInputs.getServerPublicKey(),
            serverInputs.getCredentialIdentifier(),
            serverInputs.getOprfSeed()
        );

        assertEquals("7408a268083e03abc7097fc05b587834539065e86fb0c7b6342fcf5e01e5b019b2fe7af9f48cc502d016729d2fe25cdd433f2c4bc904660b2a382c9b79df1a78", registrationResponse.toHex());

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

        assertEquals("2ec892bdbf9b3e2ea834be9eb11f5d187e64ba661ec041c0a3b66db8b7d6cc301ac5844383c7708077dea41cbefe2fa15724f449e535dd7dd562e66f5ecfb95864eadddec9db5874959905117dad40a4524111849799281fefe3c51fa82785c5ac13171b2f17bc2c74997f0fce1e1f35bec6b91fe2e12dbd323d23ba7a38dfecb9dbe7d48cf714fc3533becab6faf60b783c94d258477eb74ecc453413bf61c53fd58f0fb3c1175410b674c02e1b59b2d729a865b709db3dc4ee2bb45703d5a8", registrationRecord.toHex());

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

        assertEquals("c4dedb0ba6ed5d965d6f250fbe554cd45cba5dfcce3ce836e4aee778aa3cd44dda7e07376d6d6f034cfa9bb537d11b8c6b4238c334333d1f0aebb380cae6a6cc0c3a00c961fead8a16f818929cc976f0475e4f723519318b96f4947a7a5f9663", ke1.toHex());

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

        assertEquals("7e308140890bcde30cbcea28b01ea1ecfbd077cff62c4def8efa075aabcbb47138fe59af0df2c79f57b8780278f5ae47355fe1f817119041951c80f612fdfc6dd6ec60bcdb26dc455ddf3e718f1020490c192d70dfc7e403981179d8073d1146a4f9aa1ced4e4cd984c657eb3b54ced3848326f70331953d91b02535af44d9fe0610f003be80cb2098357928c8ea17bb065af33095f39d4e0b53b1687f02d522d96bad4ca354293d5c401177ccbd302cf565b96c327f71bc9eaf2890675d2fbb71cd9960ecef2fe0d0f7494986fa3d8b2bb01963537e60efb13981e138e3d4a1c8c39f573135474c51660b02425bca633e339cec4e1acc69c94dd48497fe40287f33611c2cf0eef57adbf48942737d9421e6b20e4b9d6e391d4168bf4bf96ea57aa42ad41c977605e027a9ef706a349f4b2919fe3562c8e86c4eeecf2f9457d4", ke2.toHex());

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
        assertEquals("df9a13cd256091f90f0fcb2ef6b3411e4aebff07bb0813299c0ec7f5dedd33a7681231a001a82f1dece1777921f42abfeee551ee34392e1c9743c5cc1dc1ef8c", ke3.toHex());

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
