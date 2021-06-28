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
    byte_t input[1];
    ecc_hex2bin(input, "00", 2);
    byte_t blind[32];
    ecc_hex2bin(blind, "c604c785ada70d77a5256ae21767de8c3304115237d262134f5e46e512cf8e03", 64);

    byte_t blindedElement[32];
    ecc_oprf_ristretto255_sha512_BlindWithScalar(blindedElement, input, 1, blind);

    char blindedElementHex[65];
    ecc_bin2hex(blindedElementHex, blindedElement, 32);
    assert_string_equal(blindedElementHex, "3c7f2d901c0d4f245503a186086fbdf5d8b4408432b25c5163e8b5a19c258348");
}

int main() {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(oprf_ristretto255_sha512_test1),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
