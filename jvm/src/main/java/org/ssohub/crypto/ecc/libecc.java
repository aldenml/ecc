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
}
