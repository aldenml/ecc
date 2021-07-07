/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

package org.ssohub.crypto.ecc;

/**
 * JNI java interface for libecc-jvm.
 *
 * @author aldenml
 */
public final class libecc {

    static {
        try {
            String path = System.getProperty("libecc.jni.path", "");
            if ("".equals(path)) {
                String libname = "ecc-jvm";
                String os = System.getProperty("os.name");
                if (os != null && os.toLowerCase(java.util.Locale.US).contains("windows"))
                    libname = "lib" + libname;

                System.loadLibrary(libname);
            } else {
                System.load(path);
            }
        } catch (LinkageError e) {
            throw new LinkageError(
                "Look for your architecture binary instructions at: https://github.com/aldenml/ecc", e);
        }
    }

    private libecc() {
    }

    // util

    public static void ecc_memzero(byte[] buf, int len) {
        for (int i = 0; i < len; i++) {
            buf[i] = 0;
        }
    }

    /**
     * Fills `n` bytes at buf with an unpredictable sequence of bytes.
     *
     * @param buf (output) the byte array to fill
     * @param len the number of bytes to fill
     */
    public static native void ecc_randombytes(byte[] buf, int len);

    // h2c

    /**
     * Produces a uniformly random byte string using SHA-512.
     * <p>
     * In order to make this method to use only the stack, len should be <= 256.
     * <p>
     * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-11#section-5.4.1
     *
     * @param out     (output) a byte string, should be at least of size `len`
     * @param msg     a byte string
     * @param msg_len the length of `msg`
     * @param dst     a byte string of at most 255 bytes
     * @param dst_len the length of `dst`, should be <= 256
     * @param len     the length of the requested output in bytes, should be <= 256
     */
    public static native void ecc_h2c_expand_message_xmd_sha512(
        byte[] out,
        byte[] msg, int msg_len,
        byte[] dst, int dst_len,
        int len
    );

    // opaque

    /**
     * Returns a randomly generated private and public key pair.
     * <p>
     * This is implemented by generating a random "seed", then
     * calling internally DeriveAuthKeyPair.
     * <p>
     * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-05#section-2
     *
     * @param private_key (output) a private key
     * @param public_key  (output) the associated public key
     */
    public static native void ecc_opaque_ristretto255_sha512_GenerateAuthKeyPair(
        byte[] private_key, byte[] public_key
    );

    /**
     * Same as calling CreateRegistrationRequest with a specified blind.
     * <p>
     * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-05#section-5.1.1.1
     *
     * @param request_raw  (output) a RegistrationRequest structure
     * @param password     an opaque byte string containing the client's password
     * @param password_len the length of `password`
     * @param blind        the OPRF scalar value to use
     */
    public static native void ecc_opaque_ristretto255_sha512_CreateRegistrationRequestWithBlind(
        byte[] request_raw,
        byte[] password, int password_len,
        byte[] blind
    );

    /**
     * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-05#section-5.1.1.1
     *
     * @param request_raw  (output) a RegistrationRequest structure
     * @param blind        (output) an OPRF scalar value
     * @param password     an opaque byte string containing the client's password
     * @param password_len the length of `password`
     */
    public static native void ecc_opaque_ristretto255_sha512_CreateRegistrationRequest(
        byte[] request_raw,
        byte[] blind, // 32
        byte[] password, int password_len
    );

    /**
     * In order to make this method not to use dynamic memory allocation, there is a
     * limit of credential_identifier_len <= 200.
     * <p>
     * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-05#section-5.1.1.2
     *
     * @param response_raw              (output) a RegistrationResponse structure
     * @param oprf_key                  (output) the per-client OPRF key known only to the server
     * @param request_raw               a RegistrationRequest structure
     * @param server_public_key         the server's public key
     * @param credential_identifier     an identifier that uniquely represents the credential being registered
     * @param credential_identifier_len the length of `credential_identifier`
     * @param oprf_seed                 the server-side seed of Nh bytes used to generate an oprf_key
     */
    public static native void ecc_opaque_ristretto255_sha512_CreateRegistrationResponse(
        byte[] response_raw,
        byte[] oprf_key,
        byte[] request_raw,
        byte[] server_public_key,
        byte[] credential_identifier, int credential_identifier_len,
        byte[] oprf_seed
    );

    /**
     * To create the user record used for further authentication, the client
     * executes the following function. Since this works in the internal key mode, the
     * "client_private_key" is null.
     * <p>
     * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-05#section-5.1.1.3
     *
     * @param record_raw          (output) a RegistrationUpload structure
     * @param export_key          (output) an additional client key
     * @param client_private_key  the client's private key (always null, internal mode)
     * @param password            an opaque byte string containing the client's password
     * @param password_len        the length of `password`
     * @param blind               the OPRF scalar value used for blinding
     * @param response_raw        a RegistrationResponse structure
     * @param server_identity     the optional encoded server identity
     * @param server_identity_len the length of `server_identity`
     * @param client_identity     the optional encoded client identity
     * @param client_identity_len the length of `client_identity`
     */
    public static native void ecc_opaque_ristretto255_sha512_FinalizeRequest(
        byte[] record_raw, // RegistrationUpload_t
        byte[] export_key,
        byte[] client_private_key,
        byte[] password, int password_len,
        byte[] blind,
        byte[] response_raw, // RegistrationResponse_t
        byte[] server_identity, int server_identity_len,
        byte[] client_identity, int client_identity_len
    );

    /**
     * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-05#section-6.2.3
     *
     * @param ke1_raw             (output) a KE1 message structure
     * @param state_raw           a ClientState structure
     * @param client_identity     the optional encoded client identity, which is null if not specified
     * @param client_identity_len the length of `client_identity`
     * @param password            an opaque byte string containing the client's password
     * @param password_len        the length of `password`
     */
    public static native void ecc_opaque_ristretto255_sha512_3DH_ClientInit(
        byte[] ke1_raw,
        byte[] state_raw,
        byte[] client_identity, int client_identity_len,
        byte[] password, int password_len
    );

    /**
     * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-05#section-6.2.3
     *
     * @param ke3_raw             (output) a KE3 message structure
     * @param session_key         (output) the session's shared secret
     * @param export_key          (output) an additional client key
     * @param state_raw           a ClientState structure
     * @param password            an opaque byte string containing the client's password
     * @param password_len        the length of `password`
     * @param client_identity     the optional encoded client identity, which is set
     *                            to client_public_key if not specified
     * @param client_identity_len the length of `client_identity`
     * @param server_identity     the optional encoded server identity, which is set
     *                            to server_public_key if not specified
     * @param server_identity_len the length of `server_identity`
     * @param ke2_raw             a KE2 message structure
     * @return 0 if is able to recover credentials and authenticate with the
     * server, else -1
     */
    public static native int ecc_opaque_ristretto255_sha512_3DH_ClientFinish(
        byte[] ke3_raw,
        byte[] session_key,
        byte[] export_key,
        byte[] state_raw,
        byte[] password, int password_len,
        byte[] client_identity, int client_identity_len,
        byte[] server_identity, int server_identity_len,
        byte[] ke2_raw
    );

    /**
     * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-05#section-6.2.4
     *
     * @param ke2_raw                   (output) a KE2 structure
     * @param state_raw                 a ServerState structure
     * @param server_identity           the optional encoded server identity, which is set to
     *                                  server_public_key if null
     * @param server_identity_len       the length of `server_identity`
     * @param server_private_key        the server's private key
     * @param server_public_key         the server's public key
     * @param record_raw                the client's RegistrationUpload structure
     * @param credential_identifier     an identifier that uniquely represents the credential
     *                                  being registered
     * @param credential_identifier_len the length of `credential_identifier`
     * @param oprf_seed                 the server-side seed of Nh bytes used to generate an oprf_key
     * @param ke1_raw                   a KE1 message structure
     * @param context                   the application specific context
     * @param context_len               the length of `context_len`
     */
    public static native void ecc_opaque_ristretto255_sha512_3DH_ServerInit(
        byte[] ke2_raw,
        byte[] state_raw,
        byte[] server_identity, int server_identity_len,
        byte[] server_private_key,
        byte[] server_public_key,
        byte[] record_raw,
        byte[] credential_identifier, int credential_identifier_len,
        byte[] oprf_seed,
        byte[] ke1_raw,
        byte[] context, int context_len
    );

    /**
     * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-05#section-6.2.4
     *
     * @param session_key (output) the shared session secret if and only if KE3 is valid
     * @param state_raw   a ServerState structure
     * @param ke3_raw     a KE3 structure
     * @return 0 if the user was authenticated, else -1
     */
    public static native int ecc_opaque_ristretto255_sha512_3DH_ServerFinish(
        byte[] session_key,
        byte[] state_raw,
        byte[] ke3_raw
    );
}
