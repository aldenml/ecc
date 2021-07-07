/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

package org.ssohub.crypto.ecc;

import static org.ssohub.crypto.ecc.libecc.ecc_opaque_ristretto255_sha512_CreateRegistrationRequest;
import static org.ssohub.crypto.ecc.libecc.ecc_opaque_ristretto255_sha512_GenerateAuthKeyPair;

/**
 * @author aldenml
 */
public final class Opaque {

    private Opaque() {
    }

    public static final class GenerateAuthKeyPairResult {

        GenerateAuthKeyPairResult(byte[] private_key, byte[] public_key) {
            this.private_key = private_key;
            this.public_key = public_key;
        }

        public final byte[] private_key;
        public final byte[] public_key;
    }

    /**
     * Returns a randomly generated private and public key pair.
     * <p>
     * This is implemented by generating a random "seed", then
     * calling internally DeriveAuthKeyPair.
     * <p>
     * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-05#section-2
     *
     * @return object {private_key, public_key}
     */
    public static GenerateAuthKeyPairResult opaque_ristretto255_sha512_GenerateAuthKeyPair() {
        byte[] private_key = new byte[32];
        byte[] public_key = new byte[32];

        ecc_opaque_ristretto255_sha512_GenerateAuthKeyPair(private_key, public_key);

        return new GenerateAuthKeyPairResult(private_key, public_key);
    }

    public static final class CreateRegistrationRequestResult {

        CreateRegistrationRequestResult(byte[] request, byte[] blind) {
            this.request = request;
            this.blind = blind;
        }

        public final byte[] request;
        public final byte[] blind;
    }

    /**
     * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-05#section-5.1.1.1
     *
     * @param password an opaque byte string containing the client's password
     * @return object {request, blind}
     */
    public static CreateRegistrationRequestResult opaque_ristretto255_sha512_CreateRegistrationRequest(byte[] password) {
        byte[] request_raw = new byte[32];
        byte[] blind = new byte[32];

        ecc_opaque_ristretto255_sha512_CreateRegistrationRequest(
            request_raw,
            blind,
            password, password.length
        );

        return new CreateRegistrationRequestResult(request_raw, blind);
    }
}
