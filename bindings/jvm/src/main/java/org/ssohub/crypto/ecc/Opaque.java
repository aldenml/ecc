/*
 * Copyright (c) 2021-2022, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

package org.ssohub.crypto.ecc;

import static org.ssohub.crypto.ecc.libecc.*;

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
     * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-07#section-2
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
     * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-07#section-5.1.1.1
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

    public static final class CreateRegistrationResponseResult {

        CreateRegistrationResponseResult(byte[] response, byte[] oprf_key) {
            this.response = response;
            this.oprf_key = oprf_key;
        }

        public final byte[] response;
        public final byte[] oprf_key;
    }

    /**
     * In order to make this method not to use dynamic memory allocation, there is a
     * limit of credential_identifier to length &lt;= 200.
     * <p>
     * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-07#section-5.1.1.2
     *
     * @param request_raw           a RegistrationRequest structure
     * @param server_public_key     the server's public key
     * @param credential_identifier an identifier that uniquely represents the credential being registered
     * @param oprf_seed             the server-side seed of Nh bytes used to generate an oprf_key
     * @return object {response, oprf_key}
     */
    public static CreateRegistrationResponseResult opaque_ristretto255_sha512_CreateRegistrationResponse(
        byte[] request_raw,
        byte[] server_public_key,
        byte[] credential_identifier,
        byte[] oprf_seed
    ) {
        byte[] response_raw = new byte[64];
        byte[] oprf_key = new byte[32];

        ecc_opaque_ristretto255_sha512_CreateRegistrationResponse(
            response_raw,
            oprf_key,
            request_raw,
            server_public_key,
            credential_identifier, credential_identifier.length,
            oprf_seed
        );

        return new CreateRegistrationResponseResult(
            response_raw,
            oprf_key
        );
    }

    public static final class FinalizeRequestResult {

        FinalizeRequestResult(byte[] record, byte[] export_key) {
            this.record = record;
            this.export_key = export_key;
        }

        public final byte[] record;
        public final byte[] export_key;
    }

    /**
     * To create the user record used for further authentication, the client
     * executes the following function. Since this works in the internal key mode, the
     * "client_private_key" is null.
     * <p>
     * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-07#section-5.1.1.3
     *
     * @param password        an opaque byte string containing the client's password
     * @param blind           the OPRF scalar value used for blinding
     * @param response_raw    a RegistrationResponse structure
     * @param server_identity the optional encoded server identity
     * @param client_identity the optional encoded client identity
     * @return object {record, export_key}
     */
    public static FinalizeRequestResult opaque_ristretto255_sha512_FinalizeRequest(
        byte[] password,
        byte[] blind,
        byte[] response_raw,
        byte[] server_identity,
        byte[] client_identity
    ) {
        if (server_identity == null)
            server_identity = new byte[0];
        if (client_identity == null)
            client_identity = new byte[0];

        byte[] record_raw = new byte[192];
        byte[] export_key = new byte[64];

        ecc_opaque_ristretto255_sha512_FinalizeRequest(
            record_raw,
            export_key,
            password, password.length,
            blind,
            response_raw,
            server_identity, server_identity.length,
            client_identity, client_identity.length,
            ecc_opaque_ristretto255_sha512_MHF_SCRYPT
        );

        return new FinalizeRequestResult(
            record_raw,
            export_key
        );
    }

    /**
     * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-07#section-6.2.3
     *
     * @param state_raw       a ClientState structure
     * @param password        an opaque byte string containing the client's password
     * @return a KE1 message structure
     */
    public static byte[] opaque_ristretto255_sha512_3DH_ClientInit(
        byte[] state_raw,
        byte[] password
    ) {
        byte[] ke1_raw = new byte[96];

        ecc_opaque_ristretto255_sha512_3DH_ClientInit(
            ke1_raw,
            state_raw,
            password, password.length
        );

        return ke1_raw;
    }

    public static final class ClientFinishResult {

        ClientFinishResult(byte[] ke3, byte[] session_key, byte[] export_key, int finish_ret) {
            this.ke3 = ke3;
            this.session_key = session_key;
            this.export_key = export_key;
            this.finish_ret = finish_ret;
        }

        public final byte[] ke3;
        public final byte[] session_key;
        public final byte[] export_key;
        public final int finish_ret;
    }

    /**
     * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-07#section-6.2.3
     *
     * @param state_raw       a ClientState structure
     * @param password        an opaque byte string containing the client's password
     * @param client_identity the optional encoded client identity, which is set
     *                        to client_public_key if not specified
     * @param server_identity the optional encoded server identity, which is set
     *                        to server_public_key if not specified
     * @param ke2_raw         a KE2 message structure
     * @return object {ke3, session_key, export_key, finish_ret}
     */
    public static ClientFinishResult opaque_ristretto255_sha512_3DH_ClientFinish(
        byte[] state_raw,
        byte[] password,
        byte[] client_identity,
        byte[] server_identity,
        byte[] ke2_raw
    ) {
        if (client_identity == null)
            client_identity = new byte[0];
        if (server_identity == null)
            server_identity = new byte[0];

        byte[] ke3_raw = new byte[64];
        byte[] session_key = new byte[64];
        byte[] export_key = new byte[64];

        int ret = ecc_opaque_ristretto255_sha512_3DH_ClientFinish(
            ke3_raw,
            session_key,
            export_key,
            state_raw,
            password, password.length,
            client_identity, client_identity.length,
            server_identity, server_identity.length,
            ke2_raw,
            ecc_opaque_ristretto255_sha512_MHF_SCRYPT,
            new byte[0], 0
        );

        return new ClientFinishResult(
            ke3_raw,
            session_key,
            export_key,
            ret
        );
    }

    /**
     * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-07#section-6.2.4
     *
     * @param state_raw             a ServerState structure
     * @param server_identity       the optional encoded server identity, which is set to
     *                              server_public_key if null
     * @param server_private_key    the server's private key
     * @param server_public_key     the server's public key
     * @param record_raw            the client's RegistrationUpload structure
     * @param credential_identifier an identifier that uniquely represents the credential
     *                              being registered
     * @param oprf_seed             the server-side seed of Nh bytes used to generate an oprf_key
     * @param ke1_raw               a KE1 message structure
     * @param context               the application specific context
     * @return a KE2 structure
     */
    public static byte[] opaque_ristretto255_sha512_3DH_ServerInit(
        byte[] state_raw,
        byte[] server_identity,
        byte[] server_private_key,
        byte[] server_public_key,
        byte[] client_identity,
        byte[] record_raw,
        byte[] credential_identifier,
        byte[] oprf_seed,
        byte[] ke1_raw,
        byte[] context
    ) {
        if (server_identity == null)
            server_identity = new byte[0];
        if (client_identity == null)
            client_identity = new byte[0];
        if (context == null)
            context = new byte[0];

        byte[] ke2_raw = new byte[320];

        ecc_opaque_ristretto255_sha512_3DH_ServerInit(
            ke2_raw,
            state_raw,
            server_identity, server_identity.length,
            server_private_key,
            server_public_key,
            client_identity, client_identity.length,
            record_raw,
            credential_identifier, credential_identifier.length,
            oprf_seed,
            ke1_raw,
            context, context.length
        );

        return ke2_raw;
    }

    public static final class ServerFinishResult {

        ServerFinishResult(byte[] session_key, int finish_ret) {
            this.session_key = session_key;
            this.finish_ret = finish_ret;
        }

        public final byte[] session_key;
        public final int finish_ret;
    }

    /**
     * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-07#section-6.2.4
     *
     * @param state_raw a ServerState structure
     * @param ke3_raw   a KE3 structure
     * @return object {session_key, finish_ret}
     */
    public static ServerFinishResult opaque_ristretto255_sha512_3DH_ServerFinish(
        byte[] state_raw,
        byte[] ke3_raw
    ) {
        byte[] session_key = new byte[64];

        int ret = ecc_opaque_ristretto255_sha512_3DH_ServerFinish(
            session_key,
            state_raw,
            ke3_raw
        );

        return new ServerFinishResult(
            session_key,
            ret
        );
    }
}
