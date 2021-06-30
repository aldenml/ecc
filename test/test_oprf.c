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

// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-06#appendix-A.1.1.1
static void oprf_ristretto255_sha512_test1(void **state) {
    byte_t skSm[32];
    ecc_hex2bin(skSm, "758cbac0e1eb4265d80f6e6489d9a74d788f7ddeda67d7fb3c08b08f44bda30a", 64);

    byte_t input[1];
    ecc_hex2bin(input, "00", 2);
    byte_t blind[32];
    ecc_hex2bin(blind, "c604c785ada70d77a5256ae21767de8c3304115237d262134f5e46e512cf8e03", 64);

    byte_t blindedElement[32];
    ecc_oprf_ristretto255_sha512_BlindWithScalar(blindedElement, input, 1, blind);
    byte_t evaluationElement[32];
    ecc_oprf_ristretto255_sha512_Evaluate(evaluationElement, skSm, blindedElement);
    byte_t output[64];
    ecc_oprf_ristretto255_sha512_Finalize(output, input, sizeof input, blind, evaluationElement, 0x00);

    char blindedElementHex[65];
    ecc_bin2hex(blindedElementHex, blindedElement, 32);
    assert_string_equal(blindedElementHex, "3c7f2d901c0d4f245503a186086fbdf5d8b4408432b25c5163e8b5a19c258348");
    char evaluationElementHex[65];
    ecc_bin2hex(evaluationElementHex, evaluationElement, 32);
    assert_string_equal(evaluationElementHex, "fc6c2b854553bf1ed6674072ed0bde1a9911e02b4bd64aa02cfb428f30251e77");
    char outputHex[129];
    ecc_bin2hex(outputHex, output, 64);
    assert_string_equal(outputHex, "d8ed12382086c74564ae19b7a2b5ed9bdc52656d1fc151faaae51aaba86291e8df0b2143a92f24d44d5efd0892e2e26721d27d88745343493634a66d3a925e3a");
}

int main() {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(oprf_ristretto255_sha512_test1),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
