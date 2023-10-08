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

import static org.junit.jupiter.api.Assertions.*;
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
            null,
            envelopeNonce
        );
        RegistrationRecord registrationRecord = finalizeRequest.getRegistrationRecord();
        Data exportKey = finalizeRequest.getExportKey();

        assertEquals("76a845464c68a5d2f7e442436bb1424953b17d3e2e289ccbaccafb57ac5c36751ac5844383c7708077dea41cbefe2fa15724f449e535dd7dd562e66f5ecfb95864eadddec9db5874959905117dad40a4524111849799281fefe3c51fa82785c5ac13171b2f17bc2c74997f0fce1e1f35bec6b91fe2e12dbd323d23ba7a38dfec634b0f5b96109c198a8027da51854c35bee90d1e1c781806d07d49b76de6a28b8d9e9b6c93b9f8b64d16dddd9c5bfb5fea48ee8fd2f75012a8b308605cdd8ba5", registrationRecord.toHex());

        ClientState clientState = new ClientState();
        R255Scalar blindLogin = R255Scalar.fromHex("6ecc102d2e7a7cf49617aad7bbe188556792d4acd60a1a8a8d2b65d4b0790308");
        OpaqueSeed clientNonce = OpaqueSeed.fromHex("da7e07376d6d6f034cfa9bb537d11b8c6b4238c334333d1f0aebb380cae6a6cc");
        OpaqueSeed clientKeyshareSeed = OpaqueSeed.fromHex("82850a697b42a505f5b68fcdafce8c31f0af2b581f063cf1091933541936304b");
        KE1 ke1 = Opaque.generateKE1WithSeed(
            clientState,
            clientInputs.getPassword(),
            blindLogin,
            clientNonce,
            clientKeyshareSeed
        );

        assertEquals("c4dedb0ba6ed5d965d6f250fbe554cd45cba5dfcce3ce836e4aee778aa3cd44dda7e07376d6d6f034cfa9bb537d11b8c6b4238c334333d1f0aebb380cae6a6cc6e29bee50701498605b2c085d7b241ca15ba5c32027dd21ba420b94ce60da326", ke1.toHex());

        ServerState serverState = new ServerState();
        OpaqueSeed maskingNonce = OpaqueSeed.fromHex("38fe59af0df2c79f57b8780278f5ae47355fe1f817119041951c80f612fdfc6d");
        OpaqueSeed serverNonce = OpaqueSeed.fromHex("71cd9960ecef2fe0d0f7494986fa3d8b2bb01963537e60efb13981e138e3d4a1");
        OpaqueSeed serverKeyshareSeed = OpaqueSeed.fromHex("05a4f54206eef1ba2f615bc0aa285cb22f26d1153b5b40a1e85ff80da12f982f");
        KE2 ke2 = Opaque.generateKE2WithSeed(
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
            serverKeyshareSeed
        );

        assertEquals("7e308140890bcde30cbcea28b01ea1ecfbd077cff62c4def8efa075aabcbb47138fe59af0df2c79f57b8780278f5ae47355fe1f817119041951c80f612fdfc6dd6ec60bcdb26dc455ddf3e718f1020490c192d70dfc7e403981179d8073d1146a4f9aa1ced4e4cd984c657eb3b54ced3848326f70331953d91b02535af44d9fedc80188ca46743c52786e0382f95ad85c08f6afcd1ccfbff95e2bdeb015b166c6b20b92f832cc6df01e0b86a7efd92c1c804ff865781fa93f2f20b446c8371b671cd9960ecef2fe0d0f7494986fa3d8b2bb01963537e60efb13981e138e3d4a1c4f62198a9d6fa9170c42c3c71f1971b29eb1d5d0bd733e40816c91f7912cc4a660c48dae03e57aaa38f3d0cffcfc21852ebc8b405d15bd6744945ba1a93438a162b6111699d98a16bb55b7bdddfe0fc5608b23da246e7bd73b47369169c5c90", ke2.toHex());

        ClientFinishResult clientFinishResult = Opaque.generateKE3(
            clientState,
            clientInputs.getClientIdentity(),
            clientInputs.getServerIdentity(),
            ke2,
            Opaque.MHF.IDENTITY,
            null,
            context
        );

        KE3 ke3 = clientFinishResult.getKE3();

        assertEquals(0, clientFinishResult.getResult());
        assertEquals(exportKey, clientFinishResult.getExportKey());
        assertEquals("4455df4f810ac31a6748835888564b536e6da5d9944dfea9e34defb9575fe5e2661ef61d2ae3929bcf57e53d464113d364365eb7d1a57b629707ca48da18e442", ke3.toHex());

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

    private boolean protocolWithRandomValues(
        Opaque.MHF mhf,
        Data mhfSalt
    ) {

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
            mhf,
            mhfSalt
        );
        RegistrationRecord registrationRecord = finalizeRequest.getRegistrationRecord();

        ClientState clientState = new ClientState();
        KE1 ke1 = Opaque.generateKE1(
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

        ClientFinishResult clientFinishResult = Opaque.generateKE3(
            clientState,
            clientInputs.getClientIdentity(),
            clientInputs.getServerIdentity(),
            ke2,
            mhf,
            mhfSalt,
            context
        );

        KE3 ke3 = clientFinishResult.getKE3();

        assertEquals(0, clientFinishResult.getResult());
        assertEquals(finalizeRequest.getExportKey(), clientFinishResult.getExportKey());

        ServerFinishResult serverFinishResult = Opaque.serverFinish(serverState, ke3);

        assertEquals(0, serverFinishResult.getResult());
        assertEquals(clientFinishResult.getSessionKey(), serverFinishResult.getSessionKey());

        return true;
    }

    @Test
    void testProtocolWithRandomValuesAndScrypt() {
        boolean result = protocolWithRandomValues(
            Opaque.MHF.SCRYPT,
            null
        );

        assertTrue(result);
    }

    @Test
    void testProtocolWithRandomValuesAndArgon2id() {
        boolean result = protocolWithRandomValues(
            Opaque.MHF.ARGON2ID,
            new Data(Util.str2bin("abcdabcdabcdabcd"))
        );

        assertTrue(result);
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
            Opaque.MHF.IDENTITY,
            null
        );
        RegistrationRecord registrationRecord = finalizeRequest.getRegistrationRecord();

        ClientState clientState = new ClientState();
        KE1 ke1 = Opaque.generateKE1(
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

        ClientFinishResult clientFinishResult = Opaque.generateKE3(
            clientState,
            clientInputs.getClientIdentity(),
            clientInputs.getServerIdentity(),
            ke2,
            Opaque.MHF.IDENTITY,
            null,
            context
        );

        KE3 ke3 = clientFinishResult.getKE3();

        assertNotEquals(0, clientFinishResult.getResult());
        assertNotEquals(finalizeRequest.getExportKey(), clientFinishResult.getExportKey());

        ServerFinishResult serverFinishResult = Opaque.serverFinish(serverState, ke3);

        assertNotEquals(0, serverFinishResult.getResult());
        assertNotEquals(clientFinishResult.getSessionKey(), serverFinishResult.getSessionKey());
    }

    @Test
    void testKeyPairGeneration() {

        GenerateAuthKeyPairResult keyPairResult = Opaque.generateAuthKeyPair();
        System.out.println("Opaque sk=" + keyPairResult.getPrivateKey().toHex());
        System.out.println("Opaque pk=" + keyPairResult.getPublicKey().toHex());

        OpaquePk pk = Opaque.recoverPublicKey(keyPairResult.getPrivateKey());
        assertEquals(keyPairResult.getPublicKey(), pk);
    }
}
