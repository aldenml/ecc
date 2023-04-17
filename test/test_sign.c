/*
 * Copyright (c) 2021-2023, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#include "ecc_test.h"

// Test Vectors for BLS Signature taken from:
// https://github.com/ethereum/bls12-381-tests

static void test_ecc_sign_eth_bls_SkToPk(void **state) {
    ECC_UNUSED(state);

    byte_t sk[ecc_sign_eth_bls_PRIVATEKEYSIZE];
    ecc_hex2bin(sk,
        "47b8192d77bf871b62e87859d653922725724a5c031afeabc60bcef5ff665138",
        2 * ecc_sign_eth_bls_PRIVATEKEYSIZE
    );

    byte_t pk[ecc_sign_eth_bls_PUBLICKEYSIZE];
    ecc_sign_eth_bls_SkToPk(pk, sk);

    char pk_hex[2 * ecc_sign_eth_bls_SIGNATURESIZE + 1];
    ecc_bin2hex(pk_hex, pk, sizeof pk);
    assert_string_equal(pk_hex, "b301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81");
}

static void test_ecc_sign_eth_bls_KeyValidate(void **state) {
    ECC_UNUSED(state);

    // not in curve
    byte_t pk1[ecc_sign_eth_bls_PUBLICKEYSIZE];
    ecc_hex2bin(pk1,
        "8123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde0",
        2 * ecc_sign_eth_bls_PUBLICKEYSIZE
    );

    int ret1 = ecc_sign_eth_bls_KeyValidate(pk1);

    assert_int_equal(ret1, -1);

    // not in G1
    byte_t pk2[ecc_sign_eth_bls_PUBLICKEYSIZE];
    ecc_hex2bin(pk2,
        "8123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        2 * ecc_sign_eth_bls_PUBLICKEYSIZE
    );

    int ret2 = ecc_sign_eth_bls_KeyValidate(pk2);

    assert_int_equal(ret2, -1);
}

static void test_ecc_sign_eth_bls_Sign(void **state) {
    ECC_UNUSED(state);

    byte_t sk[ecc_sign_eth_bls_PRIVATEKEYSIZE];
    ecc_hex2bin(sk,
        "328388aff0d4a5b7dc9205abd374e7e98f3cd9f3418edb4eafda5fb16473d216",
        2 * ecc_sign_eth_bls_PRIVATEKEYSIZE
    );
    byte_t message[32];
    ecc_hex2bin(message,
        "5656565656565656565656565656565656565656565656565656565656565656",
        64
    );

    byte_t sig[ecc_sign_eth_bls_SIGNATURESIZE];
    ecc_sign_eth_bls_Sign(sig, sk, message, sizeof message);

    char sig_hex[2 * ecc_sign_eth_bls_SIGNATURESIZE + 1];
    ecc_bin2hex(sig_hex, sig, sizeof sig);
    assert_string_equal(sig_hex, "a4efa926610b8bd1c8330c918b7a5e9bf374e53435ef8b7ec186abf62e1b1f65aeaaeb365677ac1d1172a1f5b44b4e6d022c252c58486c0a759fbdc7de15a756acc4d343064035667a594b4c2a6f0b0b421975977f297dba63ee2f63ffe47bb6");
}

static void test_ecc_sign_eth_bls_Verify(void **state) {
    ECC_UNUSED(state);

    byte_t pk[ecc_sign_eth_bls_PUBLICKEYSIZE];
    ecc_hex2bin(pk,
        "b53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f",
        2 * ecc_sign_eth_bls_PUBLICKEYSIZE
    );
    byte_t message[32];
    ecc_hex2bin(message,
        "5656565656565656565656565656565656565656565656565656565656565656",
        64
    );
    byte_t signature[ecc_sign_eth_bls_SIGNATURESIZE];
    ecc_hex2bin(signature,
        "a4efa926610b8bd1c8330c918b7a5e9bf374e53435ef8b7ec186abf62e1b1f65aeaaeb365677ac1d1172a1f5b44b4e6d022c252c58486c0a759fbdc7de15a756acc4d343064035667a594b4c2a6f0b0b421975977f297dba63ee2f63ffe47bb6",
        2 * ecc_sign_eth_bls_SIGNATURESIZE
    );

    int ret = ecc_sign_eth_bls_Verify(pk, message, sizeof message, signature);

    assert_int_equal(ret, 0);
}

static void test_ecc_sign_eth_bls_Aggregate(void **state) {
    ECC_UNUSED(state);

    ecc_json_t json = ecc_json_load("../test/data/bls_tests_json/aggregate/aggregate_0x5656565656565656565656565656565656565656565656565656565656565656.json");

    byte_t input[3 * ecc_sign_eth_bls_SIGNATURESIZE];
    ecc_hex2bin(&input[0],
        ecc_json_array_string(json, "input", 0) + 2,
        2 * ecc_sign_eth_bls_SIGNATURESIZE
    );
    ecc_log("input0", &input[0], ecc_sign_eth_bls_SIGNATURESIZE);
    ecc_hex2bin(&input[ecc_sign_eth_bls_SIGNATURESIZE],
        ecc_json_array_string(json, "input", 1) + 2,
        2 * ecc_sign_eth_bls_SIGNATURESIZE
    );
    ecc_log("input1", &input[ecc_sign_eth_bls_SIGNATURESIZE], ecc_sign_eth_bls_SIGNATURESIZE);
    ecc_hex2bin(&input[2 * ecc_sign_eth_bls_SIGNATURESIZE],
        ecc_json_array_string(json, "input", 2) + 2,
        2 * ecc_sign_eth_bls_SIGNATURESIZE
    );
    ecc_log("input2", &input[2 * ecc_sign_eth_bls_SIGNATURESIZE], ecc_sign_eth_bls_SIGNATURESIZE);
    byte_t output[ecc_sign_eth_bls_SIGNATURESIZE];
    ecc_hex2bin(output,
        ecc_json_string(json, "output") + 2,
        2 * ecc_sign_eth_bls_SIGNATURESIZE
    );
    ecc_log("output", output, ecc_sign_eth_bls_SIGNATURESIZE);

    ecc_json_destroy(json);

    byte_t signature[ecc_sign_eth_bls_SIGNATURESIZE];
    ecc_sign_eth_bls_Aggregate(signature, input, 3);
    ecc_log("signature", signature, ecc_sign_eth_bls_SIGNATURESIZE);

    assert_memory_equal(signature, output, ecc_sign_eth_bls_SIGNATURESIZE);
}

static void test_ecc_sign_eth_bls_FastAggregateVerify(void **state) {
    ECC_UNUSED(state);

    ecc_json_t json = ecc_json_load("../test/data/bls_tests_json/fast_aggregate_verify/fast_aggregate_verify_valid_3d7576f3c0e3570a.json");

    byte_t pks[3 * ecc_sign_eth_bls_PUBLICKEYSIZE];
    ecc_hex2bin(&pks[0],
        ecc_json_array_string(json, "input.pubkeys", 0) + 2,
        2 * ecc_sign_eth_bls_PUBLICKEYSIZE
    );
    ecc_log("pk0", &pks[0], ecc_sign_eth_bls_PUBLICKEYSIZE);
    ecc_hex2bin(&pks[ecc_sign_eth_bls_PUBLICKEYSIZE],
        ecc_json_array_string(json, "input.pubkeys", 1) + 2,
        2 * ecc_sign_eth_bls_PUBLICKEYSIZE
    );
    ecc_log("pk1", &pks[ecc_sign_eth_bls_PUBLICKEYSIZE], ecc_sign_eth_bls_PUBLICKEYSIZE);
    ecc_hex2bin(&pks[2 * ecc_sign_eth_bls_PUBLICKEYSIZE],
        ecc_json_array_string(json, "input.pubkeys", 2) + 2,
        2 * ecc_sign_eth_bls_PUBLICKEYSIZE
    );
    ecc_log("pk2", &pks[2 * ecc_sign_eth_bls_PUBLICKEYSIZE], ecc_sign_eth_bls_PUBLICKEYSIZE);
    byte_t message[32];
    ecc_hex2bin(message,
        "abababababababababababababababababababababababababababababababab",
        64
    );
    ecc_log("message", message, sizeof message);
    byte_t signature[ecc_sign_eth_bls_SIGNATURESIZE];
    ecc_hex2bin(signature,
        ecc_json_string(json, "input.signature") + 2,
        2 * ecc_sign_eth_bls_SIGNATURESIZE
    );
    ecc_log("signature", signature, sizeof signature);

    int ret = ecc_sign_eth_bls_FastAggregateVerify(pks, 3, message, sizeof message, signature);

    assert_int_equal(ret, 0);

    ecc_json_destroy(json);
}

static void test_ecc_sign_eth_bls_AggregateVerify(void **state) {
    ECC_UNUSED(state);

    ecc_json_t json = ecc_json_load("../test/data/bls_tests_json/aggregate_verify/aggregate_verify_valid.json");

    byte_t pks[3 * ecc_sign_eth_bls_PUBLICKEYSIZE];
    ecc_hex2bin(&pks[0],
        ecc_json_array_string(json, "input.pubkeys", 0) + 2,
        2 * ecc_sign_eth_bls_PUBLICKEYSIZE
    );
    ecc_log("pk0", &pks[0], ecc_sign_eth_bls_PUBLICKEYSIZE);
    ecc_hex2bin(&pks[ecc_sign_eth_bls_PUBLICKEYSIZE],
        ecc_json_array_string(json, "input.pubkeys", 1) + 2,
        2 * ecc_sign_eth_bls_PUBLICKEYSIZE
    );
    ecc_log("pk1", &pks[ecc_sign_eth_bls_PUBLICKEYSIZE], ecc_sign_eth_bls_PUBLICKEYSIZE);
    ecc_hex2bin(&pks[2 * ecc_sign_eth_bls_PUBLICKEYSIZE],
        ecc_json_array_string(json, "input.pubkeys", 2) + 2,
        2 * ecc_sign_eth_bls_PUBLICKEYSIZE
    );
    ecc_log("pk2", &pks[2 * ecc_sign_eth_bls_PUBLICKEYSIZE], ecc_sign_eth_bls_PUBLICKEYSIZE);
    byte_t messages[3 + 3 * 32];
    ecc_hex2bin(messages,
        "200000000000000000000000000000000000000000000000000000000000000000"
        "205656565656565656565656565656565656565656565656565656565656565656"
        "20abababababababababababababababababababababababababababababababab",
        6 + 3 * 64
    );
    ecc_log("messages", messages, sizeof messages);
    byte_t signature[ecc_sign_eth_bls_SIGNATURESIZE];
    ecc_hex2bin(signature,
        ecc_json_string(json, "input.signature") + 2,
        2 * ecc_sign_eth_bls_SIGNATURESIZE
    );
    ecc_log("signature", signature, sizeof signature);

    int ret = ecc_sign_eth_bls_AggregateVerify(
        3,
        pks,
        messages, sizeof messages,
        signature
    );

    assert_int_equal(ret, 0);

    ecc_json_destroy(json);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_ecc_sign_eth_bls_SkToPk),
        cmocka_unit_test(test_ecc_sign_eth_bls_KeyValidate),
        cmocka_unit_test(test_ecc_sign_eth_bls_Sign),
        cmocka_unit_test(test_ecc_sign_eth_bls_Verify),
        cmocka_unit_test(test_ecc_sign_eth_bls_Aggregate),
        cmocka_unit_test(test_ecc_sign_eth_bls_FastAggregateVerify),
        cmocka_unit_test(test_ecc_sign_eth_bls_AggregateVerify),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
