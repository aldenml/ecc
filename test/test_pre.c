/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#include "ecc.h"
#include <stdarg.h>
#include <setjmp.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <cmocka.h>
#include "test_util.h"

static void ecc_pre_schema1_random_encrypt_level1_test(void **state) {
    ECC_UNUSED(state);

    byte_t pkA[ecc_pre_schema1_PUBLICKEYSIZE];
    byte_t skA[ecc_pre_schema1_PRIVATEKEYSIZE];
    byte_t spkA[ecc_pre_schema1_PUBLICKEYSIZE];
    byte_t sskA[ecc_pre_schema1_PRIVATEKEYSIZE];
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

    logd("m", m, ecc_pre_schema1_MESSAGESIZE);
    logd("dm", dm, ecc_pre_schema1_MESSAGESIZE);
    assert_memory_equal(dm, m, ecc_pre_schema1_MESSAGESIZE);
}

static void ecc_pre_schema1_re_encrypt_test(void **state) {
    ECC_UNUSED(state);

    // client A setup public/private keys and signing keys
    byte_t pkA[ecc_pre_schema1_PUBLICKEYSIZE];
    byte_t skA[ecc_pre_schema1_PRIVATEKEYSIZE];
    byte_t spkA[ecc_pre_schema1_PUBLICKEYSIZE];
    byte_t sskA[ecc_pre_schema1_PRIVATEKEYSIZE];
    ecc_pre_schema1_KeyGen(pkA, skA);
    ecc_pre_schema1_SigningKeyGen(spkA, sskA);

    // client B setup public/private keys and signing keys
    byte_t pkB[ecc_pre_schema1_PUBLICKEYSIZE];
    byte_t skB[ecc_pre_schema1_PRIVATEKEYSIZE];
    byte_t spkB[ecc_pre_schema1_PUBLICKEYSIZE];
    byte_t sskB[ecc_pre_schema1_PRIVATEKEYSIZE];
    ecc_pre_schema1_KeyGen(pkB, skB);
    ecc_pre_schema1_SigningKeyGen(spkB, sskB);

    // proxy server setup signing keys
    byte_t spkSrv[ecc_pre_schema1_PUBLICKEYSIZE];
    byte_t sskSrv[ecc_pre_schema1_PRIVATEKEYSIZE];
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

    logd("pk", pk, ecc_pre_schema1_PUBLICKEYSIZE);
    logd("sk", sk, ecc_pre_schema1_PRIVATEKEYSIZE);

    char pk_hex[2 * ecc_pre_schema1_PUBLICKEYSIZE + 1];
    ecc_bin2hex(pk_hex, pk, ecc_pre_schema1_PUBLICKEYSIZE);
    assert_string_equal(pk_hex, "078176bbdd0489fa3009f6a5d00b8a4b5f5d8968da2834bd7aa4a8d9e7d7c9f7"
                                "d5a419a702ffb60e12ad83f52d061d500f2aa7c3b5c91b4242ca3ce66390ea1b"
                                "e29fab577cd78d2256cab6d1f9426cea30d5e7d860edf968542c465062309c1e");

    char sk_hex[2 * ecc_pre_schema1_PRIVATEKEYSIZE + 1];
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

    logd("spk", spk, ecc_pre_schema1_SIGNINGPUBLICKEYSIZE);
    logd("ssk", ssk, ecc_pre_schema1_SIGNINGPRIVATEKEYSIZE);

    char spk_hex[2 * ecc_pre_schema1_SIGNINGPUBLICKEYSIZE + 1];
    ecc_bin2hex(spk_hex, spk, ecc_pre_schema1_SIGNINGPUBLICKEYSIZE);
    assert_string_equal(spk_hex, "25abc08049f70630732a966ac79eec17b05346aa1e4883a496a6fa4c6ef88a4a");

    char ssk_hex[2 * ecc_pre_schema1_SIGNINGPRIVATEKEYSIZE + 1];
    ecc_bin2hex(ssk_hex, ssk, ecc_pre_schema1_SIGNINGPRIVATEKEYSIZE);
    assert_string_equal(ssk_hex, "ab542c03b70651b701200b484cbf2160ede805c371f613616635c829cd6869652"
                                 "5abc08049f70630732a966ac79eec17b05346aa1e4883a496a6fa4c6ef88a4a");
}

static void ecc_pre_schema1_encrypt_level1_test(void **state) {
    ECC_UNUSED(state);

    byte_t seed[ecc_pre_schema1_SEEDSIZE]; // 32
    ecc_hex2bin(seed, "637b73c2a559be379650e043efcbfce501f116711f2db74b18ff486e2cfa4e35", 64);

    byte_t pk[ecc_pre_schema1_PUBLICKEYSIZE];
    byte_t sk[ecc_pre_schema1_PRIVATEKEYSIZE];
    ecc_pre_schema1_DeriveKey(pk, sk, seed);

    logd("pk", pk, ecc_pre_schema1_PUBLICKEYSIZE);
    logd("sk", sk, ecc_pre_schema1_PRIVATEKEYSIZE);

    char pk_hex[2 * (ecc_pre_schema1_PUBLICKEYSIZE + 1)];
    ecc_bin2hex(pk_hex, pk, ecc_pre_schema1_PUBLICKEYSIZE);
    assert_string_equal(pk_hex, "078176bbdd0489fa3009f6a5d00b8a4b5f5d8968da2834bd7aa4a8d9e7d7c9f7"
                                "d5a419a702ffb60e12ad83f52d061d500f2aa7c3b5c91b4242ca3ce66390ea1b"
                                "e29fab577cd78d2256cab6d1f9426cea30d5e7d860edf968542c465062309c1e");

    char sk_hex[2 * (ecc_pre_schema1_PRIVATEKEYSIZE + 1)];
    ecc_bin2hex(sk_hex, sk, ecc_pre_schema1_PRIVATEKEYSIZE);
    assert_string_equal(sk_hex, "097997a5f7862d8c6a37386ee50127d796fb2aa6c1add81976bcc2e626580e53");

    byte_t spk[ecc_pre_schema1_SIGNINGPUBLICKEYSIZE];
    byte_t ssk[ecc_pre_schema1_SIGNINGPRIVATEKEYSIZE];
    ecc_pre_schema1_DeriveSigningKey(spk, ssk, seed);

    logd("spk", spk, ecc_pre_schema1_SIGNINGPUBLICKEYSIZE);
    logd("ssk", ssk, ecc_pre_schema1_SIGNINGPRIVATEKEYSIZE);

    char spk_hex[2 * (ecc_pre_schema1_SIGNINGPUBLICKEYSIZE + 1)];
    ecc_bin2hex(spk_hex, spk, ecc_pre_schema1_SIGNINGPUBLICKEYSIZE);
    assert_string_equal(spk_hex, "25abc08049f70630732a966ac79eec17b05346aa1e4883a496a6fa4c6ef88a4a");

    char ssk_hex[2 * (ecc_pre_schema1_SIGNINGPRIVATEKEYSIZE + 1)];
    ecc_bin2hex(ssk_hex, ssk, ecc_pre_schema1_SIGNINGPRIVATEKEYSIZE);
    assert_string_equal(ssk_hex, "ab542c03b70651b701200b484cbf2160ede805c371f613616635c829cd6869652"
                                 "5abc08049f70630732a966ac79eec17b05346aa1e4883a496a6fa4c6ef88a4a");

    byte_t m[ecc_pre_schema1_MESSAGESIZE];
    ecc_hex2bin(m, "bbc865a2fb1a96a0b900086bcdc8e1f8bc8e39caa795614932b9a129abc3afa8"
                   "6969001c31fd0aa67635086278d82009d9998ca8547d8b92408ba4ebde8ded68"
                   "c8089f232ac000cb24dd6e48b658ab7fb9f4c76fe709146ea7d9940f96e5220c"
                   "350311ad911bf6ecca99ac9bb464f9825303a8e61386f4b5ca98bd8d5a0060f5"
                   "979277f9f3ff15c0fa63c8623fb0780512e93f62c7c6f1f2d4a3fa472ac2e3f7"
                   "f7bc5b2a340c5eccee09083b3407100b1685b1ba94b68760b870fc5f49d3e408"
                   "d31bc04ab057c636f38a4a07e6f897e2f2f15b9ed9880df80bbe3adb5136b355"
                   "bc2a49cd31c22202e136d0358fafec13a9b52fddc1628cdc94c6b0fa8ee6bfae"
                   "233bc466917021d9668ed3c2a70c7cbf044c032a8145bd8487f8be2a75817e00"
                   "2794ced39053f64afc3bb8e7a72b2999d1d206556093c451d795f1ae3a31c6d9"
                   "0047834606a23d762fe5001a981ddb09741dafaf5220bcc060114fc1ced54963"
                   "c1da7f226b5d7c0d97aea5eb1dce3890524f6acd97eb6b142470e11c3d83e200"
                   "a1c1b4e410bcfb0d26ff472fe5daf01ecfc975a00dc1b7bef3a7aa9cb6dcd052"
                   "9ee832f1f489bbac56036ae92955740d3265a362b35958b870ed096ab4974ceb"
                   "ced19bc8536beaddc3f46dde96158f89af4e16e05b3401f66ace9b8fa071c115"
                   "03850b884054b2a6aaf88fd1f1bee74cec50e44fd14934023994e3c644de64f9"
                   "1e74c9bd15e3e00ad7ef6a53cc704210eb17967ec6a79393a7582dd3a36a28a4"
                   "0ce4ab97132a5b3102a0b4a9e5442a010e4d7dce46100e781d3d4b5522635816",
                ecc_pre_schema1_MESSAGESIZE * 2);

    byte_t encrypt_seed[ecc_pre_schema1_SEEDSIZE]; // 32
    ecc_hex2bin(seed, "037b73c2a559be379650e043efcbfce501f116711f2db74b18ff486e2cfa4e35", 64);

    byte_t C1[ecc_pre_schema1_CIPHERTEXTLEVEL1SIZE];
    ecc_pre_schema1_EncryptWithSeed(
        C1,
        m,
        pk,
        spk,
        ssk,
        encrypt_seed
    );

    logd("C1", C1, sizeof C1);

    char C1_hex[2 * (ecc_pre_schema1_CIPHERTEXTLEVEL1SIZE + 1)];
    ecc_bin2hex(C1_hex, C1, ecc_pre_schema1_CIPHERTEXTLEVEL1SIZE);
    assert_string_equal(C1_hex, "100e7ee44d923fd1f3d8da0b2d303acb0e492cbf26fa5a937a4e9e76db8d3725"
                                "68dc709eea430ca2ca65d6386d1b24e50bf9401d8e01c7636743fafe3217fb7b"
                                "752366d4a64a99c756f1b51c885e2fc70ae4fe87e41c616b6f43cf68078c025b"
                                "eda8079b743f387ff432109742f5c7585982a99f0f227b72d01124ee69b7611f"
                                "2ffaf4a95b0ecf0c0506f3ea589dd515f51c85141ea64233c15e7d70a1dab0bf"
                                "118f810dee00744b582eb72553dd1b8669df364dcd98ac4efceaa295fc961e11"
                                "2cdd68a131e4b9ea454ac5cf02268ad58adf9e62467fd82fa509ccbe4ffc8b37"
                                "a9d518895136fb003a6bbe316eb9a20c2100738f83a1d042622e87e9430d8588"
                                "6da2db9751b32f8b8847713bf822391ef293e6e2b8a24770e61bac70cf0dd104"
                                "e44d8c6ea793e05858b204504fb08cee20f495fcc323a3ba7fbc8f31cae6adda"
                                "08a4673aa35995a895a296422630751057f45564983ee22ec49d3e8f36c97ee7"
                                "e521e58446a255e286b0c93c3460f74330ab533e8deb438aad1ee400cf09b302"
                                "6523e36759aa228ebb873fa963b3811827b952f0586c3137912d67ee16542226"
                                "8c23ca5d41a18b24946c8801844c3e0b31ef3b8293b5a75bd6cd10f44fb26110"
                                "d9afb1dc30dabec173f10e5f9ecd09f340db831722964d9dd0ab99293b67390f"
                                "358b93255892a057ae7f3a6efe13eb4cdbe76c8bb7dff7cc905114534de4473b"
                                "337fea523e50c21da6a224ac368b490795333a54836c991d93fce6d228c8550d"
                                "b69251177a37129d18543a0b25c004891a4c8a2af67ba74c1e10cda265be5d02"
                                "896b248ad4dc152827135e548167a5b6e4cd465fc7c2196c8000c78d1996587c"
                                "dfc1fbada0285b60b20e56ceb4db3c0cf962cb9c28dda99269e120508dc88c89"
                                "6679d7162bf468569d72168d2f217ff347ecabf38a29e3f35711651067d4fc19"
                                "4d9767ab88eb0e66ee86a083c09a298ca20902e0db7de8aa52fbb2a822969735"
                                "25abc08049f70630732a966ac79eec17b05346aa1e4883a496a6fa4c6ef88a4a"
                                "2024cd813e8801eff520e07646c2bc86c44fa2d633715a290a821e5beed4382b"
                                "25aa2da9cb187cb2b755c19ef42814be1d44d70556cb6f47f610df9c10aaa201");

    byte_t dm[ecc_pre_schema1_MESSAGESIZE];
    int r = ecc_pre_schema1_DecryptLevel1(
        dm,
        C1,
        sk,
        spk
    );
    assert_int_equal(r, 0);

    logd("m", m, ecc_pre_schema1_MESSAGESIZE);
    logd("dm", dm, ecc_pre_schema1_MESSAGESIZE);
    assert_memory_equal(dm, m, ecc_pre_schema1_MESSAGESIZE);
}

int main() {
    const struct CMUnitTest tests[] = {
        // TODO: restore random tests for linux
        //cmocka_unit_test(ecc_pre_schema1_random_encrypt_level1_test),
        //cmocka_unit_test(ecc_pre_schema1_re_encrypt_test),
        // deterministic tests
        //cmocka_unit_test(ecc_pre_schema1_derive_key_test),
        //cmocka_unit_test(ecc_pre_schema1_derive_signingkey_test),
        cmocka_unit_test(ecc_pre_schema1_encrypt_level1_test),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
