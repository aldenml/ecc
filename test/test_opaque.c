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
#include "ecc_log.h"

static void opaque_CreateCleartextCredentials_test(void **state) {
    ECC_UNUSED(state);

    //byte_t cleartext_credentials[],
    byte_t server_public_key[32] = {1, 0};
    byte_t client_public_key[32] = {2, 0};
    byte_t client_identity[2] = "cd";

    int len = ecc_opaque_ristretto255_sha512_CreateCleartextCredentials(
        NULL, 0,
        server_public_key,
        client_public_key,
        NULL, 0,
        client_identity, sizeof client_identity
    );

    assert_int_equal(len, 32 + 32 + 2);

    byte_t creds[32 + 32 + 2];
    ecc_opaque_ristretto255_sha512_CreateCleartextCredentials(
        creds, sizeof creds,
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

static void ecc_opaque_ristretto255_sha512_3DH_Preamble_test1(void **state) {
    ECC_UNUSED(state);

    byte_t context[4] = "abcd";
    byte_t client_identity[7] = "client1";
    byte_t ke1[3] = "111";
    byte_t server_identity[7] = "server1";
    byte_t inner_ke2[3] = "222";

    byte_t preamble[256];
    int len = ecc_opaque_ristretto255_sha512_3DH_Preamble(
        preamble, sizeof preamble,
        context, sizeof context,
        client_identity, sizeof client_identity,
        ke1, sizeof ke1,
        server_identity, sizeof server_identity,
        inner_ke2, sizeof inner_ke2
    );

    assert_memory_equal(preamble, "RFCXXXX\0\4abcd\0\7client1111\0\7server1222", len);
    assert_int_equal(len, 37);
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
    ECC_UNUSED(state);

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
//    ecc_log("client_state", client_state, sizeof client_state);
//    ecc_log("password", password, sizeof password);
//    ecc_log("ke2", ke2, sizeof ke2);
//    ecc_log("ke3", ke3, sizeof ke3);
//    ecc_log("client_session_key", client_session_key, sizeof client_session_key);
//    ecc_log("export_key2", export_key2, sizeof export_key2);

    byte_t server_session_key[64];
    int server_finish_ret = ecc_opaque_ristretto255_sha512_3DH_ServerFinish(
        server_session_key,
        server_state,
        ke3
    );
    assert_int_equal(server_finish_ret, 0);

    ecc_log("client_session_key", client_session_key, sizeof client_session_key);
    ecc_log("server_session_key", server_session_key, sizeof server_session_key);
    assert_memory_equal(client_session_key, server_session_key, 64);
    assert_memory_equal(export_key, export_key2, 64);
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

static void ecc_opaque_ristretto255_sha512_CreateRegistrationResponse_test1(void **state) {
    byte_t registration_request[64];
    ecc_hex2bin(registration_request, "e61a3864330ae06a4fb67dd3710ef96e73ad0fc9f057feedee96307680081518", 64);
    byte_t server_public_key[64];
    ecc_hex2bin(server_public_key, "18d5035fd0a9c1d6412226df037125901a43f4dff660c0549d402f672bcc0933", 64);
    byte_t credential_identifier[4];
    ecc_hex2bin(credential_identifier, "31323334", 8);
    byte_t oprf_seed[64];
    ecc_hex2bin(oprf_seed, "5c4f99877d253be5817b4b03f37b6da680b0d5671d1ec5351fa61c5d82eab28b9de4c4e170f27e433ba377c71c49aa62ad26391ee1cac17011d8a7e9406657c8", 128);

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
    char hex[129];
    ecc_bin2hex(hex, registration_response, 64);
    assert_string_equal(hex, "8e7f5534f0a2ff2e2c0bc9ac5952f870711f74e1547199425b79ca80c9656b0d18d5035fd0a9c1d6412226df037125901a43f4dff660c0549d402f672bcc0933");
    ecc_bin2hex(hex, oprf_key, 32);
    assert_string_equal(hex, "840f43a856a90968af35423ef4951133ba2fed30f7679ec1ee490fb257ef4f02");
}

static void ecc_opaque_ristretto255_sha512_FinalizeRequest_test1(void **state) {
    byte_t password[25];
    ecc_hex2bin(password, "436f7272656374486f72736542617474657279537461706c65", 50);
    byte_t blind[32];
    ecc_hex2bin(blind, "17f9d715dcc44faed5608f06d1106c623676206813756f9f888efb7989106c06", 64);
    byte_t registration_response[64];
    ecc_hex2bin(registration_response, "8e7f5534f0a2ff2e2c0bc9ac5952f870711f74e1547199425b79ca80c9656b0d18d5035fd0a9c1d6412226df037125901a43f4dff660c0549d402f672bcc0933", 128);
    byte_t nonce[32];
    ecc_hex2bin(nonce, "88888888dcc44faed5608f06d1106c623676206813756f9f888efb7989106c06", 64);

    byte_t record[192];
    byte_t export_key[64];
    ecc_opaque_ristretto255_sha512_FinalizeRequestWithNonce(
        record,
        export_key,
        NULL,
        password, sizeof password,
        blind,
        registration_response,
        NULL, 0,
        NULL, 0,
        nonce
    );
    char hex[385];
    ecc_bin2hex(hex, record, 192);
    assert_string_equal(hex, "0436d5abd24da98174f917663ccff94b70b93f81abaf9651539197345f857820d561753"
                             "b08f52c98a21b62df41366ff3f6f5853108f5a63c574acdd56db5885e8ff145ad6f100d"
                             "14763ca834b0d599d4bc8da03261dc2fb42b27ac495f0bb09588888888dcc44faed5608"
                             "f06d1106c623676206813756f9f888efb7989106c06e8d34f02855380ad30d71710833b"
                             "708330305cb5ced5d373b721ced517dd75d621b9d12ad9646a60dffd80b5ab98018d04e"
                             "a32677f29808d62de81aff22c0535");
    ecc_bin2hex(hex, export_key, 64);
    assert_string_equal(hex, "8a17e3b8fdbf042a36383a8be6479ce66fd5e916969266a45f7957f1bbd585d566c62f1"
                             "91c6ad70fd2ac5b784c79355b5e9ecd35bee4fe27b2ece31e1133ad06");
}

static void ecc_opaque_ristretto255_sha512_3DH_ClientFinish_test1(void **state) {
    byte_t client_state[160];
    ecc_hex2bin(client_state, "b5930d735a1597cce3960cc32f9a1f4f9cc26bfbd2c407943a82e9c0b6f180073702b"
                              "fee4e40c83aa38da4ce17d6bcd96e3274dea12ec9d97f1799f7e19058031ee702a87bc07e07f3"
                              "1970b3307b54d4f274cc93a590a2fa381634b4c06c7117fb99917146a372df1719bddbd5e473e"
                              "ee4a356586e72a7db0cef8bbfa9a333de0661feae590c9763a19a82dcab3fa5fe7f97cf97c9a1"
                              "20dba8c32ff141e7f556", 320);
    byte_t password[25];
    ecc_hex2bin(password, "436f7272656374486f72736542617474657279537461706c65", 50);
    byte_t ke2[320];
    ecc_hex2bin(ke2, "f8d47b6db3cbd250aa9bf7f6c41b9da24e97a289727e23a700ddac799b607f74136d601f183137"
                     "f322ab7dc60453ae33d53ae6773a23a502ab2cc4769d8c0d83e702999f994663953d966573825eb9f99160"
                     "bef3bf176629bf41ef06e1edca08d8065f5638fa4e6dcfe635d2523c2e168023cf50be01255a3a3774a586"
                     "9aa3d5f1eaa1bc064c88d63732917b005fdec8009b6634c8f63c0fb2caf8f50cabc76f7a75544fb5d9a438"
                     "57b224d5d523384628fcd26d70ac9900a8369522f779e96630ab26eff16259d4eba34ca1a9086fee0a9b0c"
                     "d7588fce39e8f47412864bccbe360f95705d41173f01694a7156436eaeb245c8df77e22e2a804a14ae900e"
                     "3c0b25cf06d722ea56e0b5690f2ee02725f5599d443b88acf36816d184222113d1bef32fdc1fe7b01f2361"
                     "d871ed23a72543a60cb7caf6c5aaa78a2991a12fb6237b", 640);

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
    char hex[129];
    ecc_bin2hex(hex, ke3, 64);
    assert_string_equal(hex, "83e2b6b89377355759664bac9759565e3e24ce7f8cc0a1ada9d97dae6ceab83c61ef1f07b6dc3ce7d3b393e95a68ee8004195522b3833f484fa42a9a3b3038e7");
    ecc_bin2hex(hex, client_session_key, 64);
    assert_string_equal(hex, "a53ea052c3d32fb9521ecca5b0c4b921450761e1403a9673ea367d382806e1fc8e6094d647553c61e734f891b4887c0fcdec05076f74283b487bf375619bab61");
    ecc_bin2hex(hex, export_key2, 64);
    assert_string_equal(hex, "fe015f5e10a485383bdd638b3387e9ac074b3fbc183d927896a9b1acf720a60ab56b4f7aef7ce2db9619e806f960f293e0857d60bd74d766da44d43ad88850a1");
}

int main() {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(opaque_CreateCleartextCredentials_test),
        cmocka_unit_test(ecc_opaque_ristretto255_sha512_3DH_Preamble_test1),
        // ecc_opaque_ristretto255_sha512_CreateRegistrationRequestWithBlind
        //cmocka_unit_test(opaque_ristretto255_sha512_CreateRegistrationRequestWithBlind_test1),
        //cmocka_unit_test(opaque_ristretto255_sha512_CreateRegistrationRequestWithBlind_test2),
        cmocka_unit_test(opaque_ristretto255_sha512_RecoverPublicKey_test1),
        cmocka_unit_test(ecc_opaque_ristretto255_sha512_CreateRegistrationResponse_test1),
        cmocka_unit_test(ecc_opaque_ristretto255_sha512_FinalizeRequest_test1),
        cmocka_unit_test(ecc_opaque_ristretto255_sha512_3DH_ClientFinish_test1),
        // protocol
        cmocka_unit_test(opaque_ristretto255_sha512_test1),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
