/*
 * Copyright (c) 2021-2023, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#include "ecc_test.h"

static void test_ecc_voprf_ristretto255_sha512_oprf(void **state) {
    ECC_UNUSED(state);

    ecc_json_t json = ecc_json_load("../test/data/voprf/ristretto255_sha512_oprf.json");

    byte_t Seed[ecc_voprf_ristretto255_sha512_SCALARSIZE];
    int SeedLen;
    ecc_json_hex(Seed, &SeedLen, json, "Seed");
    ecc_log("Seed", Seed, sizeof Seed);

    byte_t KeyInfo[8 * 1024];
    int KeyInfoLen;
    ecc_json_hex(KeyInfo, &KeyInfoLen, json, "KeyInfo");
    ecc_log("KeyInfo", KeyInfo, KeyInfoLen);

    byte_t skSm[ecc_voprf_ristretto255_sha512_SCALARSIZE];
    int skSmLen;
    ecc_json_hex(skSm, &skSmLen, json, "skSm");
    ecc_log("skSm", skSm, sizeof skSm);

    const int n = ecc_json_array_size(json, "vectors");

    for (int i = 0; i < n; i++) {
        ecc_json_t item = ecc_json_array_item(json, "vectors", i);

        byte_t Input[8 * 1024];
        int InputLen;
        ecc_json_hex(Input, &InputLen, item, "Input");
        ecc_log("Input", Input, InputLen);

        byte_t Blind[ecc_voprf_ristretto255_sha512_SCALARSIZE];
        int BlindLen;
        ecc_json_hex(Blind, &BlindLen, item, "Blind");
        ecc_log("Blind", Blind, sizeof Blind);

        byte_t BlindedElement[ecc_voprf_ristretto255_sha512_ELEMENTSIZE];
        int BlindedElementLen;
        ecc_json_hex(BlindedElement, &BlindedElementLen, item, "BlindedElement");
        ecc_log("BlindedElement", BlindedElement, sizeof BlindedElement);

        byte_t EvaluationElement[ecc_voprf_ristretto255_sha512_ELEMENTSIZE];
        int EvaluationElementLen;
        ecc_json_hex(EvaluationElement, &EvaluationElementLen, item, "EvaluationElement");
        ecc_log("EvaluationElement", EvaluationElement, sizeof EvaluationElement);

        byte_t Output[ecc_voprf_ristretto255_sha512_Nh];
        int OutputLen;
        ecc_json_hex(Output, &OutputLen, item, "Output");
        ecc_log("Output", Output, sizeof Output);

        byte_t blindedElement[ecc_voprf_ristretto255_sha512_ELEMENTSIZE];
        int r = ecc_voprf_ristretto255_sha512_BlindWithScalar(
            blindedElement,
            Input, InputLen,
            Blind,
            ecc_voprf_ristretto255_sha512_MODE_OPRF
        );

        assert_int_equal(r, 0);
        assert_memory_equal(blindedElement, BlindedElement, sizeof blindedElement);

        byte_t evaluatedElement[ecc_voprf_ristretto255_sha512_ELEMENTSIZE];
        ecc_voprf_ristretto255_sha512_BlindEvaluate(
            evaluatedElement,
            skSm,
            blindedElement
        );

        assert_memory_equal(evaluatedElement, EvaluationElement, sizeof evaluatedElement);

        byte_t output[ecc_voprf_ristretto255_sha512_Nh];
        ecc_voprf_ristretto255_sha512_Finalize(
            output,
            Input, InputLen,
            Blind,
            evaluatedElement
        );

        assert_memory_equal(output, Output, sizeof output);
    }

    ecc_json_destroy(json);
}

static void test_ecc_voprf_ristretto255_sha512_voprf(void **state) {
    ECC_UNUSED(state);

    ecc_json_t json = ecc_json_load("../test/data/voprf/ristretto255_sha512_voprf.json");

    byte_t Seed[ecc_voprf_ristretto255_sha512_SCALARSIZE];
    int SeedLen;
    ecc_json_hex(Seed, &SeedLen, json, "Seed");
    ecc_log("Seed", Seed, sizeof Seed);

    byte_t KeyInfo[8 * 1024];
    int KeyInfoLen;
    ecc_json_hex(KeyInfo, &KeyInfoLen, json, "KeyInfo");
    ecc_log("KeyInfo", KeyInfo, KeyInfoLen);

    byte_t skSm[ecc_voprf_ristretto255_sha512_SCALARSIZE];
    int skSmLen;
    ecc_json_hex(skSm, &skSmLen, json, "skSm");
    ecc_log("skSm", skSm, sizeof skSm);

    byte_t pkSm[ecc_voprf_ristretto255_sha512_ELEMENTSIZE];
    int pkSmLen;
    ecc_json_hex(pkSm, &pkSmLen, json, "pkSm");
    ecc_log("pkSm", pkSm, sizeof pkSm);

    const int n = ecc_json_array_size(json, "vectors");

    for (int i = 0; i < n; i++) {
        ecc_json_t item = ecc_json_array_item(json, "vectors", i);

        byte_t Input[8 * 1024];
        int InputLen;
        ecc_json_hex(Input, &InputLen, item, "Input");
        ecc_log("Input", Input, InputLen);

        byte_t Blind[ecc_voprf_ristretto255_sha512_SCALARSIZE];
        int BlindLen;
        ecc_json_hex(Blind, &BlindLen, item, "Blind");
        ecc_log("Blind", Blind, sizeof Blind);

        byte_t BlindedElement[ecc_voprf_ristretto255_sha512_ELEMENTSIZE];
        int BlindedElementLen;
        ecc_json_hex(BlindedElement, &BlindedElementLen, item, "BlindedElement");
        ecc_log("BlindedElement", BlindedElement, sizeof BlindedElement);

        byte_t EvaluationElement[ecc_voprf_ristretto255_sha512_ELEMENTSIZE];
        int EvaluationElementLen;
        ecc_json_hex(EvaluationElement, &EvaluationElementLen, item, "EvaluationElement");
        ecc_log("EvaluationElement", EvaluationElement, sizeof EvaluationElement);

        byte_t Proof[ecc_voprf_ristretto255_sha512_PROOFSIZE];
        int ProofLen;
        ecc_json_hex(Proof, &ProofLen, item, "Proof");
        ecc_log("Proof", Proof, sizeof Proof);

        byte_t ProofRandomScalar[ecc_voprf_ristretto255_sha512_SCALARSIZE];
        int ProofRandomScalarLen;
        ecc_json_hex(ProofRandomScalar, &ProofRandomScalarLen, item, "ProofRandomScalar");
        ecc_log("ProofRandomScalar", ProofRandomScalar, sizeof ProofRandomScalar);

        byte_t Output[ecc_voprf_ristretto255_sha512_Nh];
        int OutputLen;
        ecc_json_hex(Output, &OutputLen, item, "Output");
        ecc_log("Output", Output, sizeof Output);

        byte_t blindedElement[ecc_voprf_ristretto255_sha512_ELEMENTSIZE];
        int r = ecc_voprf_ristretto255_sha512_BlindWithScalar(
            blindedElement,
            Input, InputLen,
            Blind,
            ecc_voprf_ristretto255_sha512_MODE_VOPRF
        );

        assert_int_equal(r, 0);
        assert_memory_equal(blindedElement, BlindedElement, sizeof blindedElement);

        byte_t evaluatedElement[ecc_voprf_ristretto255_sha512_ELEMENTSIZE];
        byte_t proof[ecc_voprf_ristretto255_sha512_PROOFSIZE];
        ecc_voprf_ristretto255_sha512_VerifiableBlindEvaluateWithScalar(
            evaluatedElement,
            proof,
            skSm,
            pkSm,
            blindedElement,
            ProofRandomScalar
        );

        assert_memory_equal(evaluatedElement, EvaluationElement, sizeof evaluatedElement);
        assert_memory_equal(proof, Proof, sizeof proof);

        byte_t output[ecc_voprf_ristretto255_sha512_Nh];
        r = ecc_voprf_ristretto255_sha512_VerifiableFinalize(
            output,
            Input, InputLen,
            Blind,
            evaluatedElement,
            blindedElement,
            pkSm,
            proof
        );

        assert_int_equal(r, 0);
        assert_memory_equal(output, Output, sizeof output);
    }

    ecc_json_destroy(json);
}

// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-16#appendix-A-1-3
static void test_ecc_voprf_ristretto255_sha512_poprf(void **state) {
    ECC_UNUSED(state);

    ecc_json_t json = ecc_json_load("../test/data/voprf/ristretto255_sha512_poprf.json");

    byte_t Seed[ecc_voprf_ristretto255_sha512_SCALARSIZE];
    int SeedLen;
    ecc_json_hex(Seed, &SeedLen, json, "Seed");
    ecc_log("Seed", Seed, sizeof Seed);

    byte_t KeyInfo[8 * 1024];
    int KeyInfoLen;
    ecc_json_hex(KeyInfo, &KeyInfoLen, json, "KeyInfo");
    ecc_log("KeyInfo", KeyInfo, KeyInfoLen);

    byte_t skSm[ecc_voprf_ristretto255_sha512_SCALARSIZE];
    int skSmLen;
    ecc_json_hex(skSm, &skSmLen, json, "skSm");
    ecc_log("skSm", skSm, sizeof skSm);

    byte_t pkSm[ecc_voprf_ristretto255_sha512_ELEMENTSIZE];
    int pkSmLen;
    ecc_json_hex(pkSm, &pkSmLen, json, "pkSm");
    ecc_log("pkSm", pkSm, sizeof pkSm);

    const int n = ecc_json_array_size(json, "vectors");

    for (int i = 0; i < n; i++) {
        ecc_json_t item = ecc_json_array_item(json, "vectors", i);

        byte_t Input[8 * 1024];
        int InputLen;
        ecc_json_hex(Input, &InputLen, item, "Input");
        ecc_log("Input", Input, InputLen);

        byte_t Info[ecc_voprf_ristretto255_sha512_MAXINFOSIZE];
        int InfoLen;
        ecc_json_hex(Info, &InfoLen, item, "Info");
        ecc_log("Info", Info, InfoLen);

        byte_t Blind[ecc_voprf_ristretto255_sha512_SCALARSIZE];
        int BlindLen;
        ecc_json_hex(Blind, &BlindLen, item, "Blind");
        ecc_log("Blind", Blind, sizeof Blind);

        byte_t BlindedElement[ecc_voprf_ristretto255_sha512_ELEMENTSIZE];
        int BlindedElementLen;
        ecc_json_hex(BlindedElement, &BlindedElementLen, item, "BlindedElement");
        ecc_log("BlindedElement", BlindedElement, sizeof BlindedElement);

        byte_t EvaluationElement[ecc_voprf_ristretto255_sha512_ELEMENTSIZE];
        int EvaluationElementLen;
        ecc_json_hex(EvaluationElement, &EvaluationElementLen, item, "EvaluationElement");
        ecc_log("EvaluationElement", EvaluationElement, sizeof EvaluationElement);

        byte_t Proof[ecc_voprf_ristretto255_sha512_PROOFSIZE];
        int ProofLen;
        ecc_json_hex(Proof, &ProofLen, item, "Proof");
        ecc_log("Proof", Proof, sizeof Proof);

        byte_t ProofRandomScalar[ecc_voprf_ristretto255_sha512_SCALARSIZE];
        int ProofRandomScalarLen;
        ecc_json_hex(ProofRandomScalar, &ProofRandomScalarLen, item, "ProofRandomScalar");
        ecc_log("ProofRandomScalar", ProofRandomScalar, sizeof ProofRandomScalar);

        byte_t Output[ecc_voprf_ristretto255_sha512_Nh];
        int OutputLen;
        ecc_json_hex(Output, &OutputLen, item, "Output");
        ecc_log("Output", Output, sizeof Output);

        byte_t blindedElement[ecc_voprf_ristretto255_sha512_ELEMENTSIZE];
        byte_t tweakedKey[ecc_voprf_ristretto255_sha512_ELEMENTSIZE];
        int r = ecc_voprf_ristretto255_sha512_PartiallyBlindWithScalar(
            blindedElement,
            tweakedKey,
            Input, InputLen,
            Info, InfoLen,
            pkSm,
            Blind
        );

        assert_int_equal(r, 0);
        assert_memory_equal(blindedElement, BlindedElement, sizeof blindedElement);

        byte_t evaluatedElement[ecc_voprf_ristretto255_sha512_ELEMENTSIZE];
        byte_t proof[ecc_voprf_ristretto255_sha512_PROOFSIZE];
        ecc_voprf_ristretto255_sha512_PartiallyBlindEvaluateWithScalar(
            evaluatedElement,
            proof,
            skSm,
            blindedElement,
            Info, InfoLen,
            ProofRandomScalar
        );

        assert_memory_equal(evaluatedElement, EvaluationElement, sizeof evaluatedElement);
        assert_memory_equal(proof, Proof, sizeof proof);

        byte_t output[ecc_voprf_ristretto255_sha512_Nh];
        r = ecc_voprf_ristretto255_sha512_PartiallyFinalize(
            output,
            Input, InputLen,
            Blind,
            evaluatedElement,
            blindedElement,
            proof,
            Info, InfoLen,
            tweakedKey
        );

        assert_int_equal(r, 0);
        assert_memory_equal(output, Output, sizeof output);

        // move verifications
        r = ecc_voprf_ristretto255_sha512_PartiallyEvaluate(
            output,
            skSm,
            Input, InputLen,
            Info, InfoLen
        );
        assert_int_equal(r, 0);
        assert_memory_equal(output, Output, sizeof output);
    }

    ecc_json_destroy(json);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_ecc_voprf_ristretto255_sha512_oprf),
        cmocka_unit_test(test_ecc_voprf_ristretto255_sha512_voprf),
        cmocka_unit_test(test_ecc_voprf_ristretto255_sha512_poprf),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
