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

// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-05#appendix-C.1

static void opaque_ristretto255_sha512_CreateRegistrationRequestWithBlind_test1(void **state) {
    byte_t password[25];
    ecc_hex2bin(password, "436f7272656374486f72736542617474657279537461706c65", 50);
    byte_t blind_registration[32];
    ecc_hex2bin(blind_registration, "c62937d17dc9aa213c9038f84fe8c5bf3d953356db01c4d48acb7cae48e6a504", 64);
    byte_t registration_request[32];
    ecc_opaque_ristretto255_sha512_CreateRegistrationRequestWithBlind(registration_request, password, 25, blind_registration);

    char hex[65];
    ecc_bin2hex(hex, registration_request, 32);
    assert_string_equal(hex, "80576bce33c6ce89f9e1a06d8595cd9d09d9aef46b20dadd57a845dc50e7c074");
}

static void opaque_ristretto255_sha512_CreateRegistrationRequestWithBlind_test2(void **state) {
    byte_t password[25];
    ecc_hex2bin(password, "436f7272656374486f72736542617474657279537461706c65", 50);
    byte_t blind_registration[32];
    ecc_hex2bin(blind_registration, "a66ffb41ccf1194a8d7dda900f8b6b0652e4c7fac4610066fe0489a804d3bb05", 64);
    byte_t registration_request[32];
    ecc_opaque_ristretto255_sha512_CreateRegistrationRequestWithBlind(registration_request, password, 25, blind_registration);

    char hex[65];
    ecc_bin2hex(hex, registration_request, 32);
    assert_string_equal(hex, "f841cbb85844967568c7405f3831a58c4f5f37ccddb0baa4972ea912c960ae66");
}

int main() {
    const struct CMUnitTest tests[] = {
        // ecc_opaque_ristretto255_sha512_CreateRegistrationRequestWithBlind
        cmocka_unit_test(opaque_ristretto255_sha512_CreateRegistrationRequestWithBlind_test1),
        cmocka_unit_test(opaque_ristretto255_sha512_CreateRegistrationRequestWithBlind_test2),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
