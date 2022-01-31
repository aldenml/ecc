/*
 * Copyright (c) 2021-2022, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#include "ecc_test.h"

static void ecc_pre_schema1_random_encrypt_level1_test(void **state) {
    ECC_UNUSED(state);

    byte_t pkA[ecc_pre_schema1_PUBLICKEYSIZE];
    byte_t skA[ecc_pre_schema1_PRIVATEKEYSIZE];
    byte_t spkA[ecc_pre_schema1_SIGNINGPUBLICKEYSIZE];
    byte_t sskA[ecc_pre_schema1_SIGNINGPRIVATEKEYSIZE];
    ecc_pre_schema1_KeyGen(pkA, skA);
    ecc_pre_schema1_SigningKeyGen(spkA, sskA);

    byte_t m[ecc_pre_schema1_MESSAGESIZE];
    ecc_pre_schema1_MessageGen(m);

    byte_t C_j[ecc_pre_schema1_CIPHERTEXTLEVEL1SIZE];
    ecc_pre_schema1_Encrypt(
        C_j,
        m,
        pkA,
        spkA,
        sskA
    );

    byte_t dm[ecc_pre_schema1_MESSAGESIZE];
    int r = ecc_pre_schema1_DecryptLevel1(
        dm,
        C_j,
        skA,
        spkA
    );
    assert_int_equal(r, 0);

    ecc_log("m", m, ecc_pre_schema1_MESSAGESIZE);
    ecc_log("dm", dm, ecc_pre_schema1_MESSAGESIZE);
    assert_memory_equal(dm, m, ecc_pre_schema1_MESSAGESIZE);
}

static void ecc_pre_schema1_re_encrypt_test(void **state) {
    ECC_UNUSED(state);

    // client A setup public/private keys and signing keys
    byte_t pkA[ecc_pre_schema1_PUBLICKEYSIZE];
    byte_t skA[ecc_pre_schema1_PRIVATEKEYSIZE];
    byte_t spkA[ecc_pre_schema1_SIGNINGPUBLICKEYSIZE];
    byte_t sskA[ecc_pre_schema1_SIGNINGPRIVATEKEYSIZE];
    ecc_pre_schema1_KeyGen(pkA, skA);
    ecc_pre_schema1_SigningKeyGen(spkA, sskA);

    // client B setup public/private keys and signing keys
    byte_t pkB[ecc_pre_schema1_PUBLICKEYSIZE];
    byte_t skB[ecc_pre_schema1_PRIVATEKEYSIZE];
    byte_t spkB[ecc_pre_schema1_SIGNINGPUBLICKEYSIZE];
    byte_t sskB[ecc_pre_schema1_SIGNINGPRIVATEKEYSIZE];
    ecc_pre_schema1_KeyGen(pkB, skB);
    ecc_pre_schema1_SigningKeyGen(spkB, sskB);

    // proxy server setup signing keys
    byte_t spkSrv[ecc_pre_schema1_SIGNINGPUBLICKEYSIZE];
    byte_t sskSrv[ecc_pre_schema1_SIGNINGPRIVATEKEYSIZE];
    ecc_pre_schema1_SigningKeyGen(spkSrv, sskSrv);

    // client A select a plaintext message, this message
    // in itself is random, but can be used as a seed
    // for symmetric encryption keys
    byte_t m[ecc_pre_schema1_MESSAGESIZE];
    ecc_pre_schema1_MessageGen(m);

    // client A encrypts the message to itself, making it
    // possible to send this ciphertext to the proxy.
    byte_t C_A[ecc_pre_schema1_CIPHERTEXTLEVEL1SIZE];
    ecc_pre_schema1_Encrypt(
        C_A,
        m,
        pkA,
        spkA,
        sskA
    );

    // client A sends C_A to the proxy server and eventually client A
    // allows client B to see the encrypted message, in this case the
    // proxy needs to re-encrypt C_A (without ever knowing the plaintext).
    // In order to do that, the client A needs to create a re-encryption
    // key that the proxy can use to perform such operation.

    // client A creates a re-encryption key that the proxy can use
    // to re-encrypt the ciphertext (C_A) in order for client B be
    // able to recover the original message
    byte_t tk_A_B[ecc_pre_schema1_REKEYSIZE];
    ecc_pre_schema1_ReKeyGen(
        tk_A_B,
        skA,
        pkB,
        spkA,
        sskA
    );

    // the proxy re-encrypt the ciphertext C_A with such a key that
    // allows client B to recover the original message
    byte_t C_B[ecc_pre_schema1_CIPHERTEXTLEVEL2SIZE];
    int r1 = ecc_pre_schema1_ReEncrypt(
        C_B,
        C_A,
        tk_A_B,
        spkA,
        pkB,
        spkSrv,
        sskSrv
    );
    assert_int_equal(r1, 0);

    // client B is able to decrypt C_B and the result is the original
    // plaintext message
    byte_t mB[ecc_pre_schema1_MESSAGESIZE];
    int r = ecc_pre_schema1_DecryptLevel2(
        mB,
        C_B,
        skB,
        spkSrv
    );
    assert_int_equal(r, 0);

    // now both client A and client B share the same plaintext message
    assert_memory_equal(mB, m, ecc_pre_schema1_MESSAGESIZE);
}

static void ecc_pre_schema1_derive_key_test(void **state) {
    ECC_UNUSED(state);

    byte_t seed[ecc_pre_schema1_SEEDSIZE]; // 32
    ecc_hex2bin(seed, "637b73c2a559be379650e043efcbfce501f116711f2db74b18ff486e2cfa4e35", 64);

    byte_t pk[ecc_pre_schema1_PUBLICKEYSIZE];
    byte_t sk[ecc_pre_schema1_PRIVATEKEYSIZE];
    ecc_pre_schema1_DeriveKey(pk, sk, seed);

    ecc_log("pk", pk, ecc_pre_schema1_PUBLICKEYSIZE);
    ecc_log("sk", sk, ecc_pre_schema1_PRIVATEKEYSIZE);

    char pk_hex[2 * (ecc_pre_schema1_PUBLICKEYSIZE + 1)];
    ecc_bin2hex(pk_hex, pk, ecc_pre_schema1_PUBLICKEYSIZE);
    assert_string_equal(pk_hex, "a78176bbdd0489fa3009f6a5d00b8a4b5f5d8968da2834bd7aa4a8d9e7d7c9f7d5a419a702ffb60e12ad83f52d061d50");

    char sk_hex[2 * (ecc_pre_schema1_PRIVATEKEYSIZE + 1)];
    ecc_bin2hex(sk_hex, sk, ecc_pre_schema1_PRIVATEKEYSIZE);
    assert_string_equal(sk_hex, "097997a5f7862d8c6a37386ee50127d796fb2aa6c1add81976bcc2e626580e53");
}

static void ecc_pre_schema1_derive_signingkey_test(void **state) {
    ECC_UNUSED(state);

    byte_t seed[ecc_pre_schema1_SEEDSIZE]; // 32
    ecc_hex2bin(seed, "637b73c2a559be379650e043efcbfce501f116711f2db74b18ff486e2cfa4e35", 64);

    byte_t spk[ecc_pre_schema1_SIGNINGPUBLICKEYSIZE];
    byte_t ssk[ecc_pre_schema1_SIGNINGPRIVATEKEYSIZE];
    ecc_pre_schema1_DeriveSigningKey(spk, ssk, seed);

    ecc_log("spk", spk, ecc_pre_schema1_SIGNINGPUBLICKEYSIZE);
    ecc_log("ssk", ssk, ecc_pre_schema1_SIGNINGPRIVATEKEYSIZE);

    char spk_hex[2 * (ecc_pre_schema1_SIGNINGPUBLICKEYSIZE + 1)];
    ecc_bin2hex(spk_hex, spk, ecc_pre_schema1_SIGNINGPUBLICKEYSIZE);
    assert_string_equal(spk_hex, "25abc08049f70630732a966ac79eec17b05346aa1e4883a496a6fa4c6ef88a4a");

    char ssk_hex[2 * (ecc_pre_schema1_SIGNINGPRIVATEKEYSIZE + 1)];
    ecc_bin2hex(ssk_hex, ssk, ecc_pre_schema1_SIGNINGPRIVATEKEYSIZE);
    assert_string_equal(ssk_hex, "ab542c03b70651b701200b484cbf2160ede805c371f613616635c829cd6869652"
                                 "5abc08049f70630732a966ac79eec17b05346aa1e4883a496a6fa4c6ef88a4a");
}

int main() {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(ecc_pre_schema1_random_encrypt_level1_test),
        cmocka_unit_test(ecc_pre_schema1_re_encrypt_test),
        // deterministic tests
        cmocka_unit_test(ecc_pre_schema1_derive_key_test),
        cmocka_unit_test(ecc_pre_schema1_derive_signingkey_test),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
