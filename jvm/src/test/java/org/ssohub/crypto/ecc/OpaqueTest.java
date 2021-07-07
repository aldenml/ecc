/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

package org.ssohub.crypto.ecc;

import org.junit.jupiter.api.Test;

import static org.ssohub.crypto.ecc.Opaque.CreateRegistrationRequestResult;
import static org.ssohub.crypto.ecc.Opaque.GenerateAuthKeyPairResult;
import static org.ssohub.crypto.ecc.Opaque.opaque_ristretto255_sha512_CreateRegistrationRequest;
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

        // TODO: continue impl
    }
}
