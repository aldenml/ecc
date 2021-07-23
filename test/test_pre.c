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
    ecc_hex2bin(m, "5ed531955bd205d146a3e79d26f70d7078ba665442f4f37c2f0f55a863d3db6d"
                   "39a0fa5364fcea8e8c8755384bb56513f1321f24febf2772359df3938810041d"
                   "8be766b536db7babdda18227d3c59fc525e3e5ea118aadbeb73bb5477ac5b019"
                   "1cbd11be4b2e7688a03e1852a58c2c002d80b1616197b71d8c9093c23df73246"
                   "23edc05968db6da7d59c76bf895de1137b3f98245d4b4489c074c44420613a18"
                   "99a1593ee8c0fd2132f4ff7caad9cfd8fbc3183f58ea2c759125db80d9e29219"
                   "3c427a56f261974e846aac9adeccb312b525ba3097a9b4fb1e690be3ebd02361"
                   "d4e3b9cac2babae34937a5c66e41ef19396cf94d96023ba6da5d147b392d6dd8"
                   "75acdb1dcf3e69d416d3c03bb293ddeded6ac8a83449a7c2439a4529702d3b16"
                   "489fcda80d58a88b9bb9cfaf9059b999f5d18ae9de51bcd90345a4aeb29aea66"
                   "a61db0e98552cd93c07a5dfb63199804f6965d8a8bf1b28c10ee3b3f1753f9e7"
                   "3e3cee1d3f30918a163727208b098a994c7c04507ca8daac29e48a2901b0360e"
                   "6e6e08e405cc272f80f5880116a24982043670880056aa0ae2e489263cdbc22d"
                   "585d8d978e4debfc36dd6caf6249dd0aa516174eb9c1f1083c92b702ae85f0ef"
                   "bf97cf70e08587e3ba70fdc1e7a616857ced0cfcea9e49aa42dd23e37d750d10"
                   "1960428bd203024aadb463b7849c3be1341b62a57ee6a354ebbc9dbc6ebe11c2"
                   "602b570eaaf1279d663afbdbce598004e1b19d14cfb18e61de7bff51c3d1d549"
                   "2dcea7729064a8026b0cbefffb02b9d02e456af40f4e7f82b5660caeffcda201",
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
                                "f606d840d8d98d1a4bae60a6b11768013e239861ff5ede84c06bfef84d3244f9"
                                "888326bf57848cd474f0f21384185b1763f33146f3ec533546443bc59f83feb5"
                                "c960a6b9831da2f188792ba174cfd0d9866dee5f03400fa275d91b8c9acfee07"
                                "cb2245b9fb288bf773c68b30c6402abe6309798144d04261e5c388ef6d31ecf7"
                                "c8103dd72dd44776a0d66d88a86f961154251a03d9eeb42c8f9def01280fba4c"
                                "de3c87c80eb5f91fd26bf22955f2cff1bc8e66e20442a0063436147feb963d19"
                                "bdaf3b52e1e775a286a3fab99e201bdd6bb033462fb38c4a603800019f442b38"
                                "b8c99711f44dedf638c446018c839d0d5e5c5a9c4badcb59f105a5400c9b5144"
                                "cd7a5fb818e84a6efbbd15838bfe45ce73ff3acecb1d718435950e3b9a0a7506"
                                "dd0816257f2ebb01ca81c9947ee509e164c8ab0bbb4847f73ce2e2175f388903"
                                "de176ef7191a6e5b40517314ec6ac90997df31f3e30115f608328120ff8d15ff"
                                "2034bf99c5363014149349fbdc922050a68be3ecacf6e3e2a9fbe5f36ae7c804"
                                "7214afa380df767e12ed0527b151faf54bc35485fca8d363e1bd276738d2e08f"
                                "327d972ce176d1b472545b94203fcd05f621266feaaaab8becf550106149a347"
                                "bfeeb324d9580e6afc29a4b8af24ebfc4200ded7ef6b1baf10e76d39cb116c18"
                                "982e0e2ae267e4f83c1c2ca453632acae495cd615f295ba881d9ba874bf23d4f"
                                "3d1a7bd5b36ddab993f5019ed0e8a5017684c289039ecc279db06cd792fecd79"
                                "449c199f007ffa5b59c0ec0fb575f341a1e311779459a2bc07e5f040dff2fc19"
                                "f5b6e9c4818f877ca81be96791011155f4d660007e17bcb7a83d1b0d1319182c"
                                "25abc08049f70630732a966ac79eec17b05346aa1e4883a496a6fa4c6ef88a4a"
                                "afa2aaeb5e39a734d4f70c0897f1d169944ec3906420939d14f3a60c9341093e"
                                "647288f417f649abe82f9feb8545f5bc6d507ea488dc59190f8bf17efa8ae40e");

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
        cmocka_unit_test(ecc_pre_schema1_random_encrypt_level1_test),
        //cmocka_unit_test(ecc_pre_schema1_re_encrypt_test),
        // deterministic tests
        //cmocka_unit_test(ecc_pre_schema1_derive_key_test),
        //cmocka_unit_test(ecc_pre_schema1_derive_signingkey_test),
        cmocka_unit_test(ecc_pre_schema1_encrypt_level1_test),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
