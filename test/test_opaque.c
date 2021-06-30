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
    byte_t oprf_seed[64];
    ecc_hex2bin(oprf_seed, "5c4f99877d253be5817b4b03f37b6da680b0d5671d1ec5351fa61c5d82eab28b9de4c4e170f27e433ba377c71c49aa62ad26391ee1cac17011d8a7e9406657c8", 128);
    byte_t credential_identifier[8] = "31323334";
    //byte_t credential_identifier[4];
    //ecc_hex2bin(credential_identifier, "31323334", 8);
    byte_t password[25];
    ecc_hex2bin(password, "436f7272656374486f72736542617474657279537461706c65", 50);
    byte_t server_public_key[32];
    ecc_hex2bin(server_public_key, "18d5035fd0a9c1d6412226df037125901a43f4dff660c0549d402f672bcc0933", 64);
    byte_t blind_registration[32];
    ecc_hex2bin(blind_registration, "c62937d17dc9aa213c9038f84fe8c5bf3d953356db01c4d48acb7cae48e6a504", 64);
    byte_t oprf_key[32];
    ecc_hex2bin(oprf_key, "23d431bab39aea4d2737ac391a50076300210730971788e3a6a8c29ad3c5930e", 64);

    byte_t registration_request[32];
    ecc_opaque_ristretto255_sha512_CreateRegistrationRequestWithBlind(registration_request, password, 25, blind_registration);
    char registration_request_hex[65];
    ecc_bin2hex(registration_request_hex, registration_request, 32);
    assert_string_equal(registration_request_hex, "80576bce33c6ce89f9e1a06d8595cd9d09d9aef46b20dadd57a845dc50e7c074");

    byte_t registration_response[64];
    ecc_opaque_ristretto255_sha512_CreateRegistrationResponseWithOprfKey(
        registration_response,
        registration_request,
        server_public_key,
        credential_identifier, sizeof credential_identifier,
        oprf_key
    );
    char registration_response_hex[129];
    ecc_bin2hex(registration_response_hex, registration_response, 64);
    assert_string_equal(registration_response_hex, "1a80fdb4f4eb1985587b5b95661d2cff1ef2493cdcdd88b5699f39048f0d6c2618d5035fd0a9c1d6412226df037125901a43f4dff660c0549d402f672bcc0933");

    byte_t record[64];
    ecc_opaque_ristretto255_sha512_FinalizeRequest(
        record, NULL,
        NULL,
        password, sizeof password,
        blind_registration, registration_response,
        server_public_key,
        NULL
    );
    char record_hex[129];
    ecc_bin2hex(record_hex, record, 64);
    // for now: randomized_pwd
    assert_string_equal(record_hex, "750ef06299c2fb102242fd84e59613616338f83e69c09c1dc3f91c57ac0642876ccbe785e94aa094262efdc6aed08b3faff7c1bddfa14c434c5a908ad6c5f9d5");
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
