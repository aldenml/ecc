/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#include "ecc_test.h"
#include <stdarg.h>
#include <setjmp.h>
#include <string.h>
#include <cmocka.h>
#include <stdio.h>

// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-08#appendix-A.1.1.1
static void oprf_ristretto255_sha512_base_test1(void **state) {
    ECC_UNUSED(state);

    byte_t skSm[ecc_oprf_ristretto255_sha512_SCALARSIZE];
    ecc_hex2bin(skSm, "74db8e13d2c5148a1181d57cc06debd730da4df1978b72ac18bc48992a0d2c0f", 64);

    byte_t input[1];
    ecc_hex2bin(input, "00", 2);
    byte_t info[9];
    ecc_hex2bin(info, "7465737420696e666f", 18);
    byte_t blind[ecc_oprf_ristretto255_sha512_ELEMENTSIZE];
    ecc_hex2bin(blind, "c604c785ada70d77a5256ae21767de8c3304115237d262134f5e46e512cf8e03", 64);

    byte_t blindedElement[ecc_oprf_ristretto255_sha512_ELEMENTSIZE];
    ecc_oprf_ristretto255_sha512_BlindWithScalar(blindedElement, input, sizeof input, blind,
        ecc_oprf_ristretto255_sha512_MODE_BASE
    );
    char blindedElementHex[2 * ecc_oprf_ristretto255_sha512_ELEMENTSIZE + 1];
    ecc_bin2hex(blindedElementHex, blindedElement, sizeof blindedElement);
    assert_string_equal(blindedElementHex, "744441a5d3ee12571a84d34812443eba2b6521a47265ad655f01e759b3dd7d35");

    byte_t evaluationElement[ecc_oprf_ristretto255_sha512_ELEMENTSIZE];
    ecc_oprf_ristretto255_sha512_Evaluate(evaluationElement, skSm, blindedElement, info, sizeof info);
    char evaluationElementHex[2 * ecc_oprf_ristretto255_sha512_ELEMENTSIZE + 1];
    ecc_bin2hex(evaluationElementHex, evaluationElement, sizeof evaluationElement);
    assert_string_equal(evaluationElementHex, "4254c503ee2013262473eec926b109b018d699b8dd954ee878bc17b159696353");

    byte_t output[ecc_oprf_ristretto255_sha512_Nh];
    ecc_oprf_ristretto255_sha512_Finalize(output, input, sizeof input, blind, evaluationElement, info, sizeof info);
    char outputHex[2 * ecc_oprf_ristretto255_sha512_Nh + 1];
    ecc_bin2hex(outputHex, output, sizeof output);
    assert_string_equal(outputHex, "9aef8983b729baacb7ecf1be98d1276ca29e7d62dbf39bc595be018b66b199119f18579a9ae96a39d7d506c9e00f75b433a870d76ba755a3e7196911fff89ff3");
}

// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-08#appendix-A.1.1.2
static void oprf_ristretto255_sha512_base_test2(void **state) {
    ECC_UNUSED(state);

    byte_t skSm[ecc_oprf_ristretto255_sha512_SCALARSIZE];
    ecc_hex2bin(skSm, "74db8e13d2c5148a1181d57cc06debd730da4df1978b72ac18bc48992a0d2c0f", 64);

    byte_t input[17];
    ecc_hex2bin(input, "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a", 34);
    byte_t info[9];
    ecc_hex2bin(info, "7465737420696e666f", 18);
    byte_t blind[ecc_oprf_ristretto255_sha512_ELEMENTSIZE];
    ecc_hex2bin(blind, "5ed895206bfc53316d307b23e46ecc6623afb3086da74189a416012be037e50b", 64);

    byte_t blindedElement[ecc_oprf_ristretto255_sha512_ELEMENTSIZE];
    ecc_oprf_ristretto255_sha512_BlindWithScalar(blindedElement, input, sizeof input, blind,
        ecc_oprf_ristretto255_sha512_MODE_BASE
    );
    char blindedElementHex[2 * ecc_oprf_ristretto255_sha512_ELEMENTSIZE + 1];
    ecc_bin2hex(blindedElementHex, blindedElement, sizeof blindedElement);
    assert_string_equal(blindedElementHex, "f4eeea4e1bcb2ec818ee2d5c1fcec56c24064a9ff4bea5b3dd6877800fc28e4d");

    byte_t evaluationElement[ecc_oprf_ristretto255_sha512_ELEMENTSIZE];
    ecc_oprf_ristretto255_sha512_Evaluate(evaluationElement, skSm, blindedElement, info, sizeof info);
    char evaluationElementHex[2 * ecc_oprf_ristretto255_sha512_ELEMENTSIZE + 1];
    ecc_bin2hex(evaluationElementHex, evaluationElement, sizeof evaluationElement);
    assert_string_equal(evaluationElementHex, "185dae43b6209dacbc41a62fd4889700d11eeeff4e83ffbc72d54daee7e25659");

    byte_t output[ecc_oprf_ristretto255_sha512_Nh];
    ecc_oprf_ristretto255_sha512_Finalize(output, input, sizeof input, blind, evaluationElement, info, sizeof info);
    char outputHex[2 * ecc_oprf_ristretto255_sha512_Nh + 1];
    ecc_bin2hex(outputHex, output, sizeof output);
    assert_string_equal(outputHex, "f556e2d83e576b4edc890472572d08f0d90d2ecc52a73b35b2a8416a72ff676549e3a83054fdf4fd16fe03e03bee7bb32cbd83c7ca212ea0d03b8996c2c268b2");
}

// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-08#appendix-A.1.2.1
static void oprf_ristretto255_sha512_verifiable_test1(void **state) {
    ECC_UNUSED(state);

    byte_t skSm[ecc_oprf_ristretto255_sha512_SCALARSIZE];
    ecc_hex2bin(skSm, "ad08ad9c7107691d792d346d743e8a79b8f6ae0673d58cbf7389d7003598c903", 64);
    byte_t pkSm[ecc_oprf_ristretto255_sha512_ELEMENTSIZE];
    ecc_hex2bin(pkSm, "7a5627aec2f2209a2fc62f39f57a8f5ffc4bbfd679d0273e6081b2b621ee3b52", 64);

    byte_t input[1];
    ecc_hex2bin(input, "00", 2);
    byte_t info[9];
    ecc_hex2bin(info, "7465737420696e666f", 18);
    byte_t blind[ecc_oprf_ristretto255_sha512_ELEMENTSIZE];
    ecc_hex2bin(blind, "ed8366feb6b1d05d1f46acb727061e43aadfafe9c10e5a64e7518d63e3263503", 64);

    byte_t blindedElement[ecc_oprf_ristretto255_sha512_ELEMENTSIZE];
    ecc_oprf_ristretto255_sha512_BlindWithScalar(blindedElement, input, sizeof input, blind,
        ecc_oprf_ristretto255_sha512_MODE_VERIFIABLE
    );
    char blindedElementHex[2 * ecc_oprf_ristretto255_sha512_ELEMENTSIZE + 1];
    ecc_bin2hex(blindedElementHex, blindedElement, sizeof blindedElement);
    assert_string_equal(blindedElementHex, "56c6926e940df23d5dfe6a48949c5a9e5b503df3bff36454ba4821afa1528718");

    byte_t proofRandomScalar[ecc_oprf_ristretto255_sha512_SCALARSIZE];
    ecc_hex2bin(proofRandomScalar, "019cbd1d7420292528f8cdd62f339fdabb602f04a95dac9dbcec831b8c681a09", 64);

    byte_t evaluationElement[ecc_oprf_ristretto255_sha512_ELEMENTSIZE];
    byte_t proof[ecc_oprf_ristretto255_sha512_PROOFSIZE];
    ecc_oprf_ristretto255_sha512_VerifiableEvaluateWithScalar(
        evaluationElement,
        proof,
        skSm, blindedElement, info, sizeof info,
        proofRandomScalar
    );
    char evaluationElementHex[2 * ecc_oprf_ristretto255_sha512_ELEMENTSIZE + 1];
    ecc_bin2hex(evaluationElementHex, evaluationElement, sizeof evaluationElement);
    assert_string_equal(evaluationElementHex, "523774950001072a4fb1f1f3300f7feb1eeddb5b8304baa9c3d463c11e7f0509");
    char proofHex[2 * ecc_oprf_ristretto255_sha512_PROOFSIZE + 1];
    ecc_bin2hex(proofHex, proof, sizeof proof);
    assert_string_equal(proofHex, "c973c8cfbcdbb12a09e7640e44e45d85d420ed0539a18dc6c67c189b4f28"
                                  "c70dd32f9b13717ee073e1e73333a7cb17545dd42ed8a2008c5dae11a3bd7e70260d");

    byte_t output[ecc_oprf_ristretto255_sha512_Nh];
    ecc_oprf_ristretto255_sha512_VerifiableFinalize(
        output,
        input, sizeof input,
        blind,
        evaluationElement, blindedElement,
        pkSm,
        proof,
        info, sizeof info
    );
    char outputHex[2 * ecc_oprf_ristretto255_sha512_Nh + 1];
    ecc_bin2hex(outputHex, output, sizeof output);
    assert_string_equal(outputHex, "2d9ed987fdfa623a5b4d5e445b127e86212b7c8f2567c175b424c59602fbba7c36975df5e4ecdf060430c8b1b581fc97e953535fd82089e15afbafcf310b3399");
}

// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-08#appendix-A.1.2.2
static void oprf_ristretto255_sha512_verifiable_test2(void **state) {
    ECC_UNUSED(state);

    byte_t skSm[ecc_oprf_ristretto255_sha512_SCALARSIZE];
    ecc_hex2bin(skSm, "ad08ad9c7107691d792d346d743e8a79b8f6ae0673d58cbf7389d7003598c903", 64);
    byte_t pkSm[ecc_oprf_ristretto255_sha512_ELEMENTSIZE];
    ecc_hex2bin(pkSm, "7a5627aec2f2209a2fc62f39f57a8f5ffc4bbfd679d0273e6081b2b621ee3b52", 64);

    byte_t input[17];
    ecc_hex2bin(input, "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a", 34);
    byte_t info[9];
    ecc_hex2bin(info, "7465737420696e666f", 18);
    byte_t blind[ecc_oprf_ristretto255_sha512_ELEMENTSIZE];
    ecc_hex2bin(blind, "e6d0f1d89ad552e383d6c6f4e8598cc3037d6e274d22da3089e7afbd4171ea02", 64);

    byte_t blindedElement[ecc_oprf_ristretto255_sha512_ELEMENTSIZE];
    ecc_oprf_ristretto255_sha512_BlindWithScalar(blindedElement, input, sizeof input, blind,
        ecc_oprf_ristretto255_sha512_MODE_VERIFIABLE
    );
    char blindedElementHex[2 * ecc_oprf_ristretto255_sha512_ELEMENTSIZE + 1];
    ecc_bin2hex(blindedElementHex, blindedElement, sizeof blindedElement);
    assert_string_equal(blindedElementHex, "5cd133d03df2e1ff919ed85501319c2039853dd7dc59da73605fd5791b835d23");

    byte_t proofRandomScalar[ecc_oprf_ristretto255_sha512_SCALARSIZE];
    ecc_hex2bin(proofRandomScalar, "74ae06fd50d5f26c2519bd7b184f45dd3ef2cb50197d42df9d013f7d6c312a0b", 64);

    byte_t evaluationElement[ecc_oprf_ristretto255_sha512_ELEMENTSIZE];
    byte_t proof[ecc_oprf_ristretto255_sha512_PROOFSIZE];
    ecc_oprf_ristretto255_sha512_VerifiableEvaluateWithScalar(
        evaluationElement,
        proof,
        skSm, blindedElement, info, sizeof info,
        proofRandomScalar
    );
    char evaluationElementHex[2 * ecc_oprf_ristretto255_sha512_ELEMENTSIZE + 1];
    ecc_bin2hex(evaluationElementHex, evaluationElement, sizeof evaluationElement);
    assert_string_equal(evaluationElementHex, "c0ba1012cbfb0338dadb435ef1d910eb179dc18c0d0a341f0249a3a9ff03b06e");
    char proofHex[2 * ecc_oprf_ristretto255_sha512_PROOFSIZE + 1];
    ecc_bin2hex(proofHex, proof, sizeof proof);
    assert_string_equal(proofHex, "156761aee4eb6a5e1e32bc0adb56ea46d65883777e152d4c607a3a3b8abf"
                                  "3b036ecebae005d3f26222a8da0a3924cceed8a1a7c707ef4ba077456c3e80f8c40f");

    byte_t output[ecc_oprf_ristretto255_sha512_Nh];
    ecc_oprf_ristretto255_sha512_VerifiableFinalize(
        output,
        input, sizeof input,
        blind,
        evaluationElement, blindedElement,
        pkSm,
        proof,
        info, sizeof info
    );
    char outputHex[2 * ecc_oprf_ristretto255_sha512_Nh + 1];
    ecc_bin2hex(outputHex, output, sizeof output);
    assert_string_equal(outputHex, "f5da1276b5ca3de4591534cf2d96f7bb49059bd374f40259f42dca89d723cac69ed3ae567128aaa2dfdf777f333615524aec24bc77b0a38e200e6a07b6c638eb");
}

static void test_oprf_ristretto255_sha512_evaluate(void **state) {
    ECC_UNUSED(state);

    byte_t skSm[ecc_oprf_ristretto255_sha512_SCALARSIZE];
    ecc_hex2bin(skSm, "74db8e13d2c5148a1181d57cc06debd730da4df1978b72ac18bc48992a0d2c0f", 64);

    byte_t info[9];
    ecc_hex2bin(info, "7465737420696e666f", 18);

    byte_t blindedElement[ecc_oprf_ristretto255_sha512_ELEMENTSIZE];
    ecc_hex2bin(blindedElement, "744441a5d3ee12571a84d34812443eba2b6521a47265ad655f01e759b3dd7d35", 64);

    byte_t evaluationElement[ecc_oprf_ristretto255_sha512_ELEMENTSIZE];
    ecc_oprf_ristretto255_sha512_Evaluate(
        evaluationElement,
        skSm,
        blindedElement,
        info, sizeof info
    );

    char evaluationElementHex[2 * ecc_oprf_ristretto255_sha512_ELEMENTSIZE + 1];
    ecc_bin2hex(evaluationElementHex, evaluationElement, sizeof evaluationElement);
    assert_string_equal(evaluationElementHex, "4254c503ee2013262473eec926b109b018d699b8dd954ee878bc17b159696353");
}

// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-08#appendix-A.1.2.1
static void test_oprf_ristretto255_sha512_verifiable_evaluate(void **state) {
    ECC_UNUSED(state);

    byte_t skSm[ecc_oprf_ristretto255_sha512_SCALARSIZE];
    ecc_hex2bin(skSm, "ad08ad9c7107691d792d346d743e8a79b8f6ae0673d58cbf7389d7003598c903", 64);

    byte_t info[9];
    ecc_hex2bin(info, "7465737420696e666f", 18);

    byte_t blindedElement[ecc_oprf_ristretto255_sha512_ELEMENTSIZE];
    ecc_hex2bin(blindedElement, "56c6926e940df23d5dfe6a48949c5a9e5b503df3bff36454ba4821afa1528718", 64);

    byte_t proofRandomScalar[ecc_oprf_ristretto255_sha512_SCALARSIZE];
    ecc_hex2bin(proofRandomScalar, "019cbd1d7420292528f8cdd62f339fdabb602f04a95dac9dbcec831b8c681a09", 64);

    byte_t evaluationElement[ecc_oprf_ristretto255_sha512_ELEMENTSIZE];
    byte_t proof[ecc_oprf_ristretto255_sha512_PROOFSIZE];
    ecc_oprf_ristretto255_sha512_VerifiableEvaluateWithScalar(
        evaluationElement,
        proof,
        skSm,
        blindedElement,
        info, sizeof info,
        proofRandomScalar
    );

    char evaluationElementHex[2 * ecc_oprf_ristretto255_sha512_ELEMENTSIZE + 1];
    ecc_bin2hex(evaluationElementHex, evaluationElement, sizeof evaluationElement);
    assert_string_equal(evaluationElementHex, "523774950001072a4fb1f1f3300f7feb1eeddb5b8304baa9c3d463c11e7f0509");

    char proofHex[2 * ecc_oprf_ristretto255_sha512_PROOFSIZE + 1];
    ecc_bin2hex(proofHex, proof, sizeof proof);
    assert_string_equal(proofHex, "c973c8cfbcdbb12a09e7640e44e45d85d420ed0539a18dc6c67c189b4f28c70dd32f9b13717ee073e1e73333a7cb17545dd42ed8a2008c5dae11a3bd7e70260d");
}

int main() {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(oprf_ristretto255_sha512_base_test1),
        cmocka_unit_test(oprf_ristretto255_sha512_base_test2),
        cmocka_unit_test(oprf_ristretto255_sha512_verifiable_test1),
        cmocka_unit_test(oprf_ristretto255_sha512_verifiable_test2),
        cmocka_unit_test(test_oprf_ristretto255_sha512_evaluate),
        cmocka_unit_test(test_oprf_ristretto255_sha512_verifiable_evaluate),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
