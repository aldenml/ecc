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
#include "test_util.h"

static void opaque_CreateCleartextCredentials_test(void **state) {
    ECC_UNUSED(state);

    //byte_t cleartext_credentials[],
    byte_t server_public_key[32] = {1, 0};
    byte_t client_public_key[32] = {2, 0};
    byte_t client_identity[2] = "cd";

    int len = ecc_opaque_ristretto255_sha512_CreateCleartextCredentials(
        NULL,
        server_public_key,
        client_public_key,
        NULL, 0,
        client_identity, sizeof client_identity
    );

    assert_int_equal(len, 32 + 32 + 2);

    byte_t creds[32 + 32 + 2];
    ecc_opaque_ristretto255_sha512_CreateCleartextCredentials(
        creds,
        server_public_key,
        client_public_key,
        NULL, 0,
        client_identity, sizeof client_identity
    );

    assert_int_equal(creds[0], 1);
    assert_int_equal(creds[1], 0);
    assert_int_equal(creds[32], 1);
    assert_int_equal(creds[33], 0);
    assert_int_equal(creds[64], 'c');
    assert_int_equal(creds[65], 'd');
}

// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-05#appendix-C.1

static void opaque_ristretto255_sha512_CreateRegistrationRequestWithBlind_test1(void **state) {
    byte_t oprf_seed[64];
    ecc_hex2bin(oprf_seed, "5c4f99877d253be5817b4b03f37b6da680b0d5671d1ec5351fa61c5d82eab28b9de4c4e170f27e433ba377c71c49aa62ad26391ee1cac17011d8a7e9406657c8", 128);
    //byte_t credential_identifier[8] = "31323334";
    byte_t credential_identifier[4];
    ecc_hex2bin(credential_identifier, "31323334", 8);
    byte_t password[25];
    ecc_hex2bin(password, "436f7272656374486f72736542617474657279537461706c65", 50);
    byte_t envelope_nonce[32];
    ecc_hex2bin(envelope_nonce, "71b8f14b7a1059cdadc414c409064a22cf9e970b0ffc6f1fc6fdd539c4676775", 64);
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

    byte_t record[32 + 64 + 96];
    byte_t export_key[64];
    ecc_opaque_ristretto255_sha512_FinalizeRequest(
        record, export_key,
        NULL,
        password, sizeof password,
        blind_registration, registration_response,
        NULL, 0,
        NULL, 0
    );
//    char record_hex[129];
//    ecc_bin2hex(record_hex, record, 64);
//    // for now: randomized_pwd
//    assert_string_equal(record_hex, "750ef06299c2fb102242fd84e59613616338f83e69c09c1dc3f91c57ac0642876ccbe785e94aa094262efdc6aed08b3faff7c1bddfa14c434c5a908ad6c5f9d5");

    //byte_t envelope[96];
    //byte_t client_public_key[32];
//    byte_t masking_key[64];
//    ecc_opaque_ristretto255_sha512_CreateEnvelopeWithNonce(
//        envelope,
//        client_public_key, masking_key, export_key,
//        record,
//        server_public_key, NULL,
//        NULL, 0,
//        NULL, 0,
//        envelope_nonce
//    );
//    char client_public_key_hex[65];
//    ecc_bin2hex(client_public_key_hex, record, 32);
//    assert_string_equal(client_public_key_hex, "f692d6b738b4e240d5f59d534371363b47817c00c7058d4a33439911e66c3c27");
//    char envelope_hex[193];
//    ecc_bin2hex(envelope_hex, envelope, 96);
//    assert_string_equal(envelope_hex, "71b8f14b7a1059cdadc414c409064a22cf9e970b0ffc6f1fc6fdd539c46"
//                                      "76775455739db882585a7c8b3e9ae7955da7135900d85ab832aa83a34b3ce481efc9e"
//                                      "43d4c2276220c8bcb9d27b5a827a5a2d655700321f3b32d21f578c21316195d8");
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

static void opaque_ristretto255_sha512_test1(void **state) {
    // client
    byte_t password[25];
    ecc_hex2bin(password, "436f7272656374486f72736542617474657279537461706c65", 50);

    // server
    byte_t oprf_seed[64];
    ecc_hex2bin(oprf_seed, "5c4f99877d253be5817b4b03f37b6da680b0d5671d1ec5351fa61c5d82eab28b9de4c4e170f27e433ba377c71c49aa62ad26391ee1cac17011d8a7e9406657c8", 128);
    byte_t server_private_key[32];
    ecc_hex2bin(server_private_key, "16eb9dc74a3df2033cd738bf2cfb7a3670c569d7749f284b2b241cb237e7d10f", 64);
    byte_t server_public_key[32];
    ecc_hex2bin(server_public_key, "18d5035fd0a9c1d6412226df037125901a43f4dff660c0549d402f672bcc0933", 64);
    byte_t credential_identifier[4];
    ecc_hex2bin(credential_identifier, "31323334", 8);

    byte_t registration_request[32];
    byte_t blind[32];
    ecc_opaque_ristretto255_sha512_CreateRegistrationRequest(
        registration_request,
        blind,
        password, 25
    );

    byte_t registration_response[64];
    byte_t oprf_key[32];
    ecc_opaque_ristretto255_sha512_CreateRegistrationResponse(
        registration_response,
        oprf_key,
        registration_request,
        server_public_key,
        credential_identifier, sizeof credential_identifier,
        oprf_seed
    );

    byte_t record[192];
    byte_t export_key[64];
    ecc_opaque_ristretto255_sha512_FinalizeRequest(
        record,
        export_key,
        NULL,
        password, sizeof password,
        blind,
        registration_response,
        NULL, 0,
        NULL, 0
    );

    // tinker with password
    //password[0] = 0;

    byte_t client_state[160] = {0};
    byte_t ke1[96];
    ecc_opaque_ristretto255_sha512_3DH_ClientInit(
        ke1,
        client_state,
        NULL, 0,
        password, sizeof password
    );

    byte_t server_state[128] = {0};
    byte_t ke2[320];
    ecc_opaque_ristretto255_sha512_3DH_ServerInit(
        ke2,
        server_state,
        NULL, 0,
        server_private_key,
        server_public_key,
        record,
        credential_identifier, sizeof credential_identifier,
        oprf_seed,
        ke1,
        NULL, 0
    );

    byte_t ke3[64];
    byte_t client_session_key[64];
    byte_t export_key2[64];
    int client_finish_ret = ecc_opaque_ristretto255_sha512_3DH_ClientFinish(
        ke3,
        client_session_key,
        export_key2,
        client_state,
        password, sizeof password,
        NULL, 0,
        NULL, 0,
        ke2
    );
    assert_int_equal(client_finish_ret, 0);

    byte_t server_session_key[64];
    int server_finish_ret = ecc_opaque_ristretto255_sha512_3DH_ServerFinish(
        server_session_key,
        server_state,
        ke3
    );
    assert_int_equal(server_finish_ret, 0);

    log("client_session_key", client_session_key, sizeof client_session_key);
    log("server_session_key", server_session_key, sizeof server_session_key);
    assert_memory_equal(client_session_key, server_session_key, 64);
}

static void opaque_ristretto255_sha512_RecoverPublicKey_test1(void **state) {
    byte_t server_private_key[32];
    ecc_hex2bin(server_private_key, "16eb9dc74a3df2033cd738bf2cfb7a3670c569d7749f284b2b241cb237e7d10f", 64);

    byte_t server_public_key[32];
    ecc_opaque_ristretto255_sha512_RecoverPublicKey(
        server_public_key,
        server_private_key
    );

    char hex[65];
    ecc_bin2hex(hex, server_public_key, 32);
    assert_string_equal(hex, "18d5035fd0a9c1d6412226df037125901a43f4dff660c0549d402f672bcc0933");
}

int main() {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(opaque_CreateCleartextCredentials_test),
        // ecc_opaque_ristretto255_sha512_CreateRegistrationRequestWithBlind
        cmocka_unit_test(opaque_ristretto255_sha512_CreateRegistrationRequestWithBlind_test1),
        cmocka_unit_test(opaque_ristretto255_sha512_CreateRegistrationRequestWithBlind_test2),
        cmocka_unit_test(opaque_ristretto255_sha512_RecoverPublicKey_test1),
        // protocol
        cmocka_unit_test(opaque_ristretto255_sha512_test1),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
