/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

package org.ssohub.crypto.ecc;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.ssohub.crypto.ecc.Opaque.ClientFinishResult;
import static org.ssohub.crypto.ecc.Opaque.CreateRegistrationRequestResult;
import static org.ssohub.crypto.ecc.Opaque.CreateRegistrationResponseResult;
import static org.ssohub.crypto.ecc.Opaque.FinalizeRequestResult;
import static org.ssohub.crypto.ecc.Opaque.GenerateAuthKeyPairResult;
import static org.ssohub.crypto.ecc.Opaque.ServerFinishResult;
import static org.ssohub.crypto.ecc.Opaque.opaque_ristretto255_sha512_3DH_ClientFinish;
import static org.ssohub.crypto.ecc.Opaque.opaque_ristretto255_sha512_3DH_ClientInit;
import static org.ssohub.crypto.ecc.Opaque.opaque_ristretto255_sha512_3DH_ServerFinish;
import static org.ssohub.crypto.ecc.Opaque.opaque_ristretto255_sha512_3DH_ServerInit;
import static org.ssohub.crypto.ecc.Opaque.opaque_ristretto255_sha512_CreateRegistrationRequest;
import static org.ssohub.crypto.ecc.Opaque.opaque_ristretto255_sha512_CreateRegistrationResponse;
import static org.ssohub.crypto.ecc.Opaque.opaque_ristretto255_sha512_FinalizeRequest;
import static org.ssohub.crypto.ecc.Opaque.opaque_ristretto255_sha512_GenerateAuthKeyPair;
import static org.ssohub.crypto.ecc.Util.randombytes;

/**
 * @author aldenml
 */
public class OpaqueTest {

    @Test
    void opaque_ristretto255_sha512_test1_random() {
        // client
        byte[] password = randombytes(10);

        // server
        byte[] oprf_seed = randombytes(64);
        GenerateAuthKeyPairResult keys = opaque_ristretto255_sha512_GenerateAuthKeyPair();
        byte[] server_private_key = keys.private_key;
        byte[] server_public_key = keys.public_key;
        byte[] credential_identifier = randombytes(10);

        // registration flow
        CreateRegistrationRequestResult regReq = opaque_ristretto255_sha512_CreateRegistrationRequest(password);

        CreateRegistrationResponseResult regRes = opaque_ristretto255_sha512_CreateRegistrationResponse(
            regReq.request,
            server_public_key,
            credential_identifier,
            oprf_seed
        );

        FinalizeRequestResult regEnd = opaque_ristretto255_sha512_FinalizeRequest(
            null,
            password,
            regReq.blind,
            regRes.response,
            null,
            null
        );

        // tinker with the password
        //password[0] = 0;

        // authentication flow
        byte[] client_state = new byte[160];
        byte[] ke1 = opaque_ristretto255_sha512_3DH_ClientInit(
            client_state,
            null,
            password
        );

        byte[] server_state = new byte[128];
        byte[] ke2 = opaque_ristretto255_sha512_3DH_ServerInit(
            server_state,
            null,
            server_private_key,
            server_public_key,
            regEnd.record,
            credential_identifier,
            oprf_seed,
            ke1,
            null
        );

        ClientFinishResult clientEnd = opaque_ristretto255_sha512_3DH_ClientFinish(
            client_state,
            password,
            null,
            null,
            ke2
        );
        assertEquals(0, clientEnd.finish_ret);

        ServerFinishResult serverEnd = opaque_ristretto255_sha512_3DH_ServerFinish(
            server_state,
            clientEnd.ke3
        );
        assertEquals(0, serverEnd.finish_ret);

        assertArrayEquals(clientEnd.session_key, serverEnd.session_key);

        assertArrayEquals(regEnd.export_key, clientEnd.export_key);
    }
}
