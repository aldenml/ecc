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
#include <cmocka.h>
#include <stdio.h>

// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-07#appendix-A.1.1.1
static void oprf_ristretto255_sha512_test1(void **state) {
    ECC_UNUSED(state);

    byte_t skSm[ecc_oprf_ristretto255_sha512_SCALARSIZE];
    ecc_hex2bin(skSm, "caeff69352df4905a9121a4997704ca8cee1524a110819eb87deba1a39ec1701", 64);

    byte_t input[1];
    ecc_hex2bin(input, "00", 2);
    byte_t blind[ecc_oprf_ristretto255_sha512_ELEMENTSIZE];
    ecc_hex2bin(blind, "c604c785ada70d77a5256ae21767de8c3304115237d262134f5e46e512cf8e03", 64);

    byte_t blindedElement[ecc_oprf_ristretto255_sha512_ELEMENTSIZE];
    ecc_oprf_ristretto255_sha512_BlindWithScalar(blindedElement, input, sizeof input, blind);
    char blindedElementHex[2 * (ecc_oprf_ristretto255_sha512_ELEMENTSIZE + 1)];
    ecc_bin2hex(blindedElementHex, blindedElement, sizeof blindedElement);
    assert_string_equal(blindedElementHex, "fc20e03aff3a9de9b37e8d35886ade11ec7d85c2a1fb5bb0b1686c64e07ac467");

    byte_t evaluationElement[ecc_oprf_ristretto255_sha512_ELEMENTSIZE];
    ecc_oprf_ristretto255_sha512_Evaluate(evaluationElement, skSm, blindedElement);
    char evaluationElementHex[2 * (ecc_oprf_ristretto255_sha512_ELEMENTSIZE + 1)];
    ecc_bin2hex(evaluationElementHex, evaluationElement, sizeof evaluationElement);
    assert_string_equal(evaluationElementHex, "7c72cc293cd7d44c0b57c273f27befd598b132edc665694bdc9c42a4d3083c0a");

    byte_t output[ecc_oprf_ristretto255_sha512_Nh];
    ecc_oprf_ristretto255_sha512_Finalize(output, input, sizeof input, blind, evaluationElement, 0x00);
    char outputHex[2 * (ecc_oprf_ristretto255_sha512_Nh + 1)];
    ecc_bin2hex(outputHex, output, sizeof output);
    assert_string_equal(outputHex, "e3a209dce2d3ea3d84fcddb282818caebb756a341e08a310d9904314f5392085d13c3f76339d745db0f46974a6049c3ea9546305af55d37760b2136d9b3f0134");
}

// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-07#appendix-A.1.1.2
static void oprf_ristretto255_sha512_test2(void **state) {
    ECC_UNUSED(state);

    byte_t skSm[ecc_oprf_ristretto255_sha512_SCALARSIZE];
    ecc_hex2bin(skSm, "caeff69352df4905a9121a4997704ca8cee1524a110819eb87deba1a39ec1701", 64);

    byte_t input[17];
    ecc_hex2bin(input, "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a", 34);
    byte_t blind[ecc_oprf_ristretto255_sha512_ELEMENTSIZE];
    ecc_hex2bin(blind, "5ed895206bfc53316d307b23e46ecc6623afb3086da74189a416012be037e50b", 64);

    byte_t blindedElement[ecc_oprf_ristretto255_sha512_ELEMENTSIZE];
    ecc_oprf_ristretto255_sha512_BlindWithScalar(blindedElement, input, sizeof input, blind);
    char blindedElementHex[2 * (ecc_oprf_ristretto255_sha512_ELEMENTSIZE + 1)];
    ecc_bin2hex(blindedElementHex, blindedElement, sizeof blindedElement);
    assert_string_equal(blindedElementHex, "483d4f39de5ff77fa0f9a0ad2334dd5bf87f2cda868539d21de67ce49e7d1536");

    byte_t evaluationElement[ecc_oprf_ristretto255_sha512_ELEMENTSIZE];
    ecc_oprf_ristretto255_sha512_Evaluate(evaluationElement, skSm, blindedElement);
    char evaluationElementHex[2 * (ecc_oprf_ristretto255_sha512_ELEMENTSIZE + 1)];
    ecc_bin2hex(evaluationElementHex, evaluationElement, sizeof evaluationElement);
    assert_string_equal(evaluationElementHex, "026f2758fc62f02a7ff95f35ec6f20186aa57c0274361655543ea235d7b2aa34");

    byte_t output[ecc_oprf_ristretto255_sha512_Nh];
    ecc_oprf_ristretto255_sha512_Finalize(output, input, sizeof input, blind, evaluationElement, 0x00);
    char outputHex[2 * (ecc_oprf_ristretto255_sha512_Nh + 1)];
    ecc_bin2hex(outputHex, output, sizeof output);
    assert_string_equal(outputHex, "2c17dc3e9398dadb44bb2d3360c446302e99f1fe0ec40f0b1ad25c9cf002be1e4b41b4900ef056537fe8c14532ccea4d796f5feab9541af48057d83c0db86fe9");
}

int main() {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(oprf_ristretto255_sha512_test1),
        cmocka_unit_test(oprf_ristretto255_sha512_test2),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
