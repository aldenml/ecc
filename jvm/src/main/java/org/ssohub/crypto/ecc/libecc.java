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

    /**
     * Zero the array `buf` up to `len` elements.
     *
     * @param buf the byte array
     * @param len the amount of elements to zero
     */
    public static void ecc_memzero(byte[] buf, int len) {
        for (int i = 0; i < len; i++)
            buf[i] = 0;
    }

    /**
     * Fills `n` bytes at buf with an unpredictable sequence of bytes.
     *
     * @param buf (output) the byte array to fill
     * @param len the number of bytes to fill
     */
    public static native void ecc_randombytes(byte[] buf, int len);

    /**
     * Concatenates two byte arrays. Sames as a || b.
     * <p>
     * a || b: denotes the concatenation of byte strings a and b. For
     * example, "ABC" || "DEF" == "ABCDEF".
     * <p>
     * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-11#section-4
     *
     * @param out    (output) result of the concatenation
     * @param a1     first byte array
     * @param a1_len the length of `a1`
     * @param a2     second byte array
     * @param a2_len the length of `a2`
     */
    public static native void ecc_concat2(
        byte[] out,
        byte[] a1, int a1_len,
        byte[] a2, int a2_len
    );

    /**
     * Same as calling ecc_concat2 but with three byte arrays.
     *
     * @param out    (output) result of the concatenation
     * @param a1     first byte array
     * @param a1_len the length of `a1`
     * @param a2     second byte array
     * @param a2_len the length of `a2`
     * @param a3     third byte array
     * @param a3_len the length of `a3`
     */
    public static native void ecc_concat3(
        byte[] out,
        byte[] a1, int a1_len,
        byte[] a2, int a2_len,
        byte[] a3, int a3_len
    );

    /**
     * Same as calling ecc_concat2 but with four byte arrays.
     *
     * @param out    (output) result of the concatenation
     * @param a1     first byte array
     * @param a1_len the length of `a1`
     * @param a2     second byte array
     * @param a2_len the length of `a2`
     * @param a3     third byte array
     * @param a3_len the length of `a4`
     * @param a4     fourth byte array
     * @param a4_len the length of `a4`
     */
    public static native void ecc_concat4(
        byte[] out,
        byte[] a1, int a1_len,
        byte[] a2, int a2_len,
        byte[] a3, int a3_len,
        byte[] a4, int a4_len
    );

    /**
     * For byte strings a and b, ecc_strxor(a, b) returns the bitwise XOR of
     * the two byte strings. For example, ecc_strxor("abc", "XYZ") == "9;9" (the
     * strings in this example are ASCII literals, but ecc_strxor is defined for
     * arbitrary byte strings).
     * <p>
     * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-11#section-4
     *
     * @param out (output) result of the operation
     * @param a   first byte array
     * @param b   second byte array
     * @param len length of both `a` and `b`
     */
    public static native void ecc_strxor(byte[] out, byte[] a, byte[] b, int len);

    /**
     * I2OSP converts a nonnegative integer to an octet string of a
     * specified length.
     * <p>
     * See https://datatracker.ietf.org/doc/html/rfc8017#section-4.1
     *
     * @param out  (output) corresponding octet string of length xLen
     * @param x    nonnegative integer to be converted
     * @param xLen intended length of the resulting octet string
     */
    public static native void ecc_I2OSP(byte[] out, int x, int xLen);

    /**
     * Takes two pointers to unsigned numbers encoded in little-endian
     * format and returns:
     * <p>
     * -1 if a &lt; b
     * 0 if a == b
     * 1 if a &gt; b
     * <p>
     * The comparison is done in constant time
     *
     * @param a   first unsigned integer argument
     * @param b   second unsigned integer argument
     * @param len the length of both `a` and `b`
     * @return -1, 0 or 1
     */
    public static native int ecc_compare(byte[] a, byte[] b, int len);

    /**
     * Takes a byte array and test if it contains only zeros. It runs
     * in constant-time.
     *
     * @param n   the byte array
     * @param len the length of `n`
     * @return 0 if non-zero bits are found
     */
    public static native int ecc_is_zero(byte[] n, int len);

    /**
     * Takes a pointer to an arbitrary-long unsigned integer encoded in
     * little-endian format, and increments it. It runs in constant-time.
     * <p>
     * Can be used to increment nonces in constant time.
     *
     * @param n   (input/output) unsigned integer
     * @param len length of `n`
     */
    public static native void ecc_increment(byte[] n, int len);

    /**
     * Takes two pointers to unsigned numbers encoded in little-endian
     * format, computes (a + b) mod 2^(8*len) and store the result in `a`.
     * It runs in constant-time.
     *
     * @param a   (input/output) first unsigned integer argument
     * @param b   second unsigned integer argument
     * @param len the length of both `a` and `b`
     */
    public static native void ecc_add(byte[] a, byte[] b, int len);

    /**
     * Takes two pointers to unsigned numbers encoded in little-endian
     * format, computes (a - b) mod 2^(8*len) and store the result in `a`.
     * It runs in constant-time.
     *
     * @param a   (input/output) first unsigned integer argument
     * @param b   second unsigned integer argument
     * @param len the length of both `a` and `b`
     */
    public static native void ecc_sub(byte[] a, byte[] b, int len);

    // hash

    /**
     * Computes the SHA-256 of a given input.
     * <p>
     * See https://en.wikipedia.org/wiki/SHA-2
     *
     * @param digest    (output) the SHA-256 of the input
     * @param input     the input message
     * @param input_len the length of `input`
     */
    public static native void ecc_hash_sha256(byte[] digest, byte[] input, int input_len);

    /**
     * Computes the SHA-512 of a given input.
     * <p>
     * See https://en.wikipedia.org/wiki/SHA-2
     *
     * @param digest    (output) the SHA-512 of the input
     * @param input     the input message
     * @param input_len the length of `input`
     */
    public static native void ecc_hash_sha512(byte[] digest, byte[] input, int input_len);

    // mac

    /**
     * Computes the HMAC-SHA-256 of the input stream.
     * <p>
     * See https://datatracker.ietf.org/doc/html/rfc2104
     * See https://datatracker.ietf.org/doc/html/rfc4868
     *
     * @param digest   (output) the HMAC-SHA-256 of the input
     * @param text     the input message
     * @param text_len the length of `input`
     * @param key      authentication key
     */
    public static native void ecc_mac_hmac_sha256(
        byte[] digest,
        byte[] text, int text_len,
        byte[] key
    );

    /**
     * Computes the HMAC-SHA-512 of the input stream.
     * <p>
     * See https://datatracker.ietf.org/doc/html/rfc2104
     * See https://datatracker.ietf.org/doc/html/rfc4868
     *
     * @param digest   (output) the HMAC-SHA-512 of the input
     * @param text     the input message
     * @param text_len the length of `input`
     * @param key      authentication key
     */
    public static native void ecc_mac_hmac_sha512(
        byte[] digest,
        byte[] text, int text_len,
        byte[] key
    );

    // kdf

    /**
     * Computes the HKDF-SHA-256 extract of the input using a key material.
     * <p>
     * See https://datatracker.ietf.org/doc/html/rfc5869
     *
     * @param prk      (output) a pseudorandom key
     * @param salt     optional salt value (a non-secret random value)
     * @param salt_len the length of `salt`
     * @param ikm      input keying material
     * @param ikm_len  the length of `ikm`
     */
    public static native void ecc_kdf_hkdf_sha256_extract(
        byte[] prk,
        byte[] salt, int salt_len,
        byte[] ikm, int ikm_len
    );

    /**
     * Computes the HKDF-SHA-256 expand of the input using a key.
     * <p>
     * See https://datatracker.ietf.org/doc/html/rfc5869
     *
     * @param okm      (output) output keying material of length `len`
     * @param prk      a pseudorandom key
     * @param info     optional context and application specific information
     * @param info_len length of `info`
     * @param len      length of output keying material in octets
     */
    public static native void ecc_kdf_hkdf_sha256_expand(
        byte[] okm,
        byte[] prk,
        byte[] info, int info_len,
        int len
    );

    /**
     * Computes the HKDF-SHA-512 extract of the input using a key material.
     * <p>
     * See https://datatracker.ietf.org/doc/html/rfc5869
     *
     * @param prk      (output) a pseudorandom key
     * @param salt     optional salt value (a non-secret random value)
     * @param salt_len the length of `salt`
     * @param ikm      input keying material
     * @param ikm_len  the length of `ikm`
     */
    public static native void ecc_kdf_hkdf_sha512_extract(
        byte[] prk,
        byte[] salt, int salt_len,
        byte[] ikm, int ikm_len
    );

    /**
     * Computes the HKDF-SHA-512 expand of the input using a key.
     * <p>
     * See https://datatracker.ietf.org/doc/html/rfc5869
     *
     * @param okm      (output) output keying material of length `len`
     * @param prk      a pseudorandom key
     * @param info     optional context and application specific information
     * @param info_len length of `info`
     * @param len      length of output keying material in octets
     */
    public static native void ecc_kdf_hkdf_sha512_expand(
        byte[] okm,
        byte[] prk,
        byte[] info, int info_len,
        int len
    );

    // ed25519

    /**
     * Checks that p represents a point on the edwards25519 curve, in canonical
     * form, on the main subgroup, and that the point doesn't have a small order.
     *
     * @param p potential point to test
     * @return 1 on success, and 0 if the checks didn't pass
     */
    public static native int ecc_ed25519_is_valid_point(byte[] p);

    /**
     * Fills p with the representation of a random group element.
     *
     * @param p (output) random group element
     */
    public static native void ecc_ed25519_random(byte[] p);

    /**
     * Generates a random key pair of public and private keys.
     *
     * @param pk (output) public key
     * @param sk (output) private key
     */
    public static native void ecc_ed25519_sign_keypair(byte[] pk, byte[] sk);

    /**
     * Generates a random key pair of public and private keys derived
     * from a seed.
     *
     * @param pk   (output) public key
     * @param sk   (output) private key
     * @param seed seed to generate the keys
     */
    public static native void ecc_ed25519_sign_seed_keypair(byte[] pk, byte[] sk, byte[] seed);

    // ristretto255

    /**
     * Maps a 64 bytes vector r (usually the output of a hash function) to
     * a group element, and stores its representation into p.
     *
     * @param p (output) group element
     * @param r bytes vector hash
     */
    public static native void ecc_ristretto255_from_hash(byte[] p, byte[] r);

    /**
     * Fills r with a bytes representation of the scalar in
     * the ]0..L[ interval where L is the order of the
     * group (2^252 + 27742317777372353535851937790883648493).
     *
     * @param r (output) random scalar
     */
    public static native void ecc_ristretto255_scalar_random(byte[] r);

    /**
     * Computes the multiplicative inverse of s over L, and puts it into recip.
     *
     * @param recip (output) the result
     * @param s     an scalar
     * @return 0 on success, or -1 if s is zero
     */
    public static native int ecc_ristretto255_scalar_invert(byte[] recip, byte[] s);

    /**
     * Multiplies an element represented by p by a valid scalar n
     * and puts the resulting element into q.
     *
     * @param q (output) the result
     * @param n the valid input scalar
     * @param p the point on the curve
     * @return 0 on success, or -1 if q is the identity element.
     */
    public static native int ecc_ristretto255_scalarmult(byte[] q, byte[] n, byte[] p);

    // bls12_381

    /**
     * Size of a an element in G1.
     */
    public static final int ecc_bls12_381_G1SIZE = 96;

    /**
     * Size of an element in G2.
     */
    public static final int ecc_bls12_381_G2SIZE = 192;

    /**
     * Size of the scalar used in the curve operations.
     */
    public static final int ecc_bls12_381_SCALARSIZE = 32;

    /**
     * Size of an element in Fp12.
     */
    public static final int ecc_bls12_381_FP12SIZE = 576;

    /**
     * Multiplies the generator by a valid scalar n and puts the resulting
     * element into q.
     *
     * @param q (output) the result
     * @param n the valid input scalar
     */
    public static native void ecc_bls12_381_g1_scalarmult_base(byte[] q, byte[] n);

    /**
     * Multiplies the generator by a valid scalar n and puts the resulting
     * element into q.
     *
     * @param q (output) the result
     * @param n the valid input scalar
     */
    public static native void ecc_bls12_381_g2_scalarmult_base(byte[] q, byte[] n);

    /**
     * Fills r with a bytes representation of an scalar.
     *
     * @param r (output) random scalar
     */
    public static native void ecc_bls12_381_scalar_random(byte[] r);

    /**
     * Evaluates a pairing of BLS12-381.
     * <p>
     * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-pairing-friendly-curves-09#section-2.2
     * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-pairing-friendly-curves-09#section-2.4
     * <p>
     * G1 is a subgroup of E(GF(p)) of order r.
     * G2 is a subgroup of E'(GF(p^2)) of order r.
     * GT is a subgroup of a multiplicative group (GF(p^12))^* of order r.
     *
     * @param ret   (output) the result of the pairing evaluation in GT
     * @param p1_g1 point in G1
     * @param p2_g2 point in G2
     */
    public static native void ecc_bls12_381_pairing(byte[] ret, byte[] p1_g1, byte[] p2_g2);

    /**
     * Perform the verification of a pairing match. Useful if the
     * inputs are raw output values from the miller loop.
     *
     * @param a the first argument to verify
     * @param b the second argument to verify
     * @return 1 if it's a pairing match, else 0
     */
    public static native int ecc_bls12_381_pairing_final_verify(byte[] a, byte[] b);

    /**
     * @param sk
     * @param ikm
     * @param ikm_len
     */
    public static native void ecc_bls12_381_sign_keygen(byte[] sk, byte[] ikm, int ikm_len);

    // h2c

    /**
     * Produces a uniformly random byte string using SHA-512.
     * <p>
     * In order to make this method to use only the stack, len should be &lt;= 256.
     * <p>
     * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-11#section-5.4.1
     *
     * @param out     (output) a byte string, should be at least of size `len`
     * @param msg     a byte string
     * @param msg_len the length of `msg`
     * @param dst     a byte string of at most 255 bytes
     * @param dst_len the length of `dst`, should be &lt;= 256
     * @param len     the length of the requested output in bytes, should be &lt;= 256
     */
    public static native void ecc_h2c_expand_message_xmd_sha512(
        byte[] out,
        byte[] msg, int msg_len,
        byte[] dst, int dst_len,
        int len
    );

    // oprf

    /**
     * Evaluates serialized representations of blinded group elements from the
     * client as inputs.
     * <p>
     * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-06#section-3.4.1.1
     *
     * @param evaluatedElement (output) evaluated element
     * @param skS              private key
     * @param blindedElement   blinded element
     */
    public static native void ecc_oprf_ristretto255_sha512_Evaluate(
        byte[] evaluatedElement,
        byte[] skS,
        byte[] blindedElement
    );

    /**
     * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-06#section-3.4.3.3
     *
     * @param output           (output)
     * @param input            the input message
     * @param input_len        the length of `blind`
     * @param blind
     * @param evaluatedElement
     * @param mode             mode to build the internal DST string (modeBase=0x00, modeVerifiable=0x01)
     */
    public static native void ecc_oprf_ristretto255_sha512_Finalize(
        byte[] output,
        byte[] input, int input_len,
        byte[] blind,
        byte[] evaluatedElement,
        int mode
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
     * limit of credential_identifier_len &lt;= 200.
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
