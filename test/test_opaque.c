/*
 * Copyright (c) 2021-2022, Alden Torres
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

// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-09#appendix-D.1.1.1
static void test_opaque_ristretto255_sha512_vector1(void **state) {
    ECC_UNUSED(state);

    byte_t context[10];
    ecc_hex2bin(context, "4f50415155452d504f43", 20);
    byte_t oprf_seed[64];
    ecc_hex2bin(oprf_seed, "f433d0227b0b9dd54f7c4422b600e764e47fb503f1f9a0f0a47c6606b0"
                           "54a7fdc65347f1a08f277e22358bbabe26f823fca82c7848e9a75661f4ec5d5c1989e"
                           "f", 128);
    byte_t credential_identifier[4];
    ecc_hex2bin(credential_identifier, "31323334", 8);
    byte_t password[25];
    ecc_hex2bin(password, "436f7272656374486f72736542617474657279537461706c65", 50);
    byte_t envelope_nonce[32];
    ecc_hex2bin(envelope_nonce, "ac13171b2f17bc2c74997f0fce1e1f35bec6b91fe2e12dbd323d2"
                                "3ba7a38dfec", 64);
    byte_t masking_nonce[32];
    ecc_hex2bin(masking_nonce, "38fe59af0df2c79f57b8780278f5ae47355fe1f817119041951c80"
                               "f612fdfc6d", 64);
    byte_t server_private_key[32];
    ecc_hex2bin(server_private_key, "47451a85372f8b3537e249d7b54188091fb18edde78094b43"
                                    "e2ba42b5eb89f0d", 64);
    byte_t server_public_key[32];
    ecc_hex2bin(server_public_key, "b2fe7af9f48cc502d016729d2fe25cdd433f2c4bc904660b2a"
                                   "382c9b79df1a78", 64);
    byte_t server_nonce[32];
    ecc_hex2bin(server_nonce, "71cd9960ecef2fe0d0f7494986fa3d8b2bb01963537e60efb13981e"
                              "138e3d4a1", 64);
    byte_t client_nonce[32];
    ecc_hex2bin(client_nonce, "da7e07376d6d6f034cfa9bb537d11b8c6b4238c334333d1f0aebb38"
                              "0cae6a6cc", 64);
    byte_t server_keyshare[32];
    ecc_hex2bin(server_keyshare, "c8c39f573135474c51660b02425bca633e339cec4e1acc69c94d"
                                 "d48497fe4028", 64);
    byte_t client_keyshare[32];
    ecc_hex2bin(client_keyshare, "0c3a00c961fead8a16f818929cc976f0475e4f723519318b96f4"
                                 "947a7a5f9663", 64);
    byte_t server_private_keyshare[32];
    ecc_hex2bin(server_private_keyshare, "2e842960258a95e28bcfef489cffd19d8ec99cc1375d"
                                         "840f96936da7dbb0b40d", 64);
    byte_t client_private_keyshare[32];
    ecc_hex2bin(client_private_keyshare, "22c919134c9bdd9dc0c5ef3450f18b54820f43f646a9"
                                         "5223bf4a85b2018c2001", 64);
    byte_t blind_registration[32];
    ecc_hex2bin(blind_registration, "76cfbfe758db884bebb33582331ba9f159720ca8784a2a070"
                                    "a265d9c2d6abe01", 64);
    byte_t blind_login[32];
    ecc_hex2bin(blind_login, "6ecc102d2e7a7cf49617aad7bbe188556792d4acd60a1a8a8d2b65d4"
                             "b0790308", 64);

    byte_t registration_request[ecc_opaque_ristretto255_sha512_REGISTRATIONREQUESTSIZE];
    ecc_opaque_ristretto255_sha512_CreateRegistrationRequestWithBlind(
        registration_request,
        password, sizeof password,
        blind_registration
    );
    char registration_request_hex[2 * ecc_opaque_ristretto255_sha512_REGISTRATIONREQUESTSIZE + 1];
    ecc_bin2hex(registration_request_hex, registration_request, sizeof registration_request);
    assert_string_equal(registration_request_hex, "62235332ae15911d69812e9eeb6ac8fe4fa0ffc7590831d"
                                                  "5c5e1631e01049276");

    byte_t registration_response[ecc_opaque_ristretto255_sha512_REGISTRATIONRESPONSESIZE];
    byte_t oprf_key[32];
    ecc_opaque_ristretto255_sha512_CreateRegistrationResponse(
        registration_response,
        oprf_key,
        registration_request,
        server_public_key,
        credential_identifier, sizeof credential_identifier,
        oprf_seed
    );
    char registration_response_hex[2 * ecc_opaque_ristretto255_sha512_REGISTRATIONRESPONSESIZE + 1];
    ecc_bin2hex(registration_response_hex, registration_response, sizeof registration_response);
    assert_string_equal(registration_response_hex, "6268d13fea98ebc8e6b88d0b3cc8a78d2ac8fa8efc741c"
                                                   "d2e966940c52c31c71b2fe7af9f48cc502d016729d2fe25cdd433f2c4bc904660b2a3"
                                                   "82c9b79df1a78");
    char oprf_key_hex[64];
    ecc_bin2hex(oprf_key_hex, oprf_key, sizeof oprf_key);
    assert_string_equal(oprf_key_hex, "6c246eaa55e47d0490ffa8a6f784e803eed9384a250458def36a2acebf15c905");

    byte_t record[ecc_opaque_ristretto255_sha512_REGISTRATIONUPLOADSIZE];
    byte_t export_key[64];
    ecc_opaque_ristretto255_sha512_FinalizeRequestWithNonce(
        record,
        export_key,
        password, sizeof password,
        blind_registration,
        registration_response,
        NULL, 0,
        NULL, 0,
        ecc_opaque_ristretto255_sha512_MHF_IDENTITY,
        envelope_nonce
    );

    char record_hex[2 * ecc_opaque_ristretto255_sha512_REGISTRATIONUPLOADSIZE + 1];
    ecc_bin2hex(record_hex, record, sizeof record);
    assert_string_equal(record_hex, "8e5e5c04b2154336fa52ac691eb6df5f59ec7315b8467b0b"
                                    "ba1ed4f413043b449afea0ddedbbce5c083c5d5d02aa5218bcc7100f541d841bb5974"
                                    "f084f7aa0b929399feb39efd17e13ce1035cbb23251da3b5126a574b239c7b73519d8"
                                    "847e2fac13171b2f17bc2c74997f0fce1e1f35bec6b91fe2e12dbd323d23ba7a38dfe"
                                    "c8e8bde8d4eb9e171240b3d2dfb43ef93efe5cd15412614b3df11ecb58890047e2fa3"
                                    "1c283e7c58c40495226cfa0ed7756e493431b85c464aad7fdaaf1ab41ac7");

    byte_t client_state[ecc_opaque_ristretto255_sha512_CLIENTSTATESIZE] = {0};
    byte_t ke1[ecc_opaque_ristretto255_sha512_KE1SIZE];
    ecc_opaque_ristretto255_sha512_3DH_ClientInitWithSecrets(
        ke1,
        client_state,
        password, sizeof password,
        blind_login,
        client_nonce,
        client_private_keyshare,
        client_keyshare
    );

    char ke1_hex[2 * ecc_opaque_ristretto255_sha512_KE1SIZE + 1];
    ecc_bin2hex(ke1_hex, ke1, sizeof ke1);
    assert_string_equal(ke1_hex, "1670c409ebb699a6012629451d218d42a34eddba1d2978536c45e199c60a0b4e"
                                 "da7e07376d6d6f034cfa9bb537d11b8c6b4238c334333d1f0aebb380cae6a6cc0c3a0"
                                 "0c961fead8a16f818929cc976f0475e4f723519318b96f4947a7a5f9663");

    byte_t server_state[ecc_opaque_ristretto255_sha512_SERVERSTATESIZE] = {0};
    byte_t ke2[ecc_opaque_ristretto255_sha512_KE2SIZE];
    ecc_opaque_ristretto255_sha512_3DH_ServerInitWithSecrets(
        ke2,
        server_state,
        NULL, 0,
        server_private_key,
        server_public_key,
        NULL, 0,
        record,
        credential_identifier, sizeof credential_identifier,
        oprf_seed,
        ke1,
        context, sizeof context,
        masking_nonce,
        server_nonce,
        server_private_keyshare,
        server_keyshare
    );

    char ke2_hex[2 * ecc_opaque_ristretto255_sha512_KE2SIZE + 1];
    ecc_bin2hex(ke2_hex, ke2, sizeof ke2);
    assert_string_equal(ke2_hex, "36b4d06f413b72004392d7359cd6a998c667533203d6a671afe81ca09a282f72"
                                 "38fe59af0df2c79f57b8780278f5ae47355fe1f817119041951c80f612fdfc6d378cc"
                                 "6b0113bf0b6afd9e0728e62ba793d5d25bb97794c154d036bf09c98c472368bffc4e3"
                                 "5b7dc48f5a32dd3fede3b9e563f7a170d0e082d02c0a105cdf1ee0ea1928202076ff3"
                                 "7ce174f2c669d52d8adc424e925a3bc9a4ca5ce16d9b7a1791ff7e47a0d2fa42424e5"
                                 "476f8cfa7bb20b2796ad877295a996ffcb049313f4e971cd9960ecef2fe0d0f749498"
                                 "6fa3d8b2bb01963537e60efb13981e138e3d4a1c8c39f573135474c51660b02425bca"
                                 "633e339cec4e1acc69c94dd48497fe402848f3b062916ea7666973222944dabe1027e"
                                 "5bea84b1b5d46dab64b1c6eda3170d4c9adba8afa61eb4153061d528b39102f32ecda"
                                 "7d7625dbc229e6630a607e03");

    byte_t ke3[ecc_opaque_ristretto255_sha512_KE3SIZE];
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
        ke2,
        ecc_opaque_ristretto255_sha512_MHF_IDENTITY,
        context, sizeof context
    );
    char ke3_hex[2 * ecc_opaque_ristretto255_sha512_KE3SIZE + 1];
    ecc_bin2hex(ke3_hex, ke3, sizeof ke3);
    assert_string_equal(ke3_hex, "4e23f0f84a5261918a7fc23bf1978a935cf4e320d56984079f8c7f4a54847b9e"
                                 "979f519928c5898927cf6aa8d51ac42dc2d0f5840956caa3a34dbc55ce74415f");
    assert_int_equal(client_finish_ret, 0);

    byte_t server_session_key[64];
    int server_finish_ret = ecc_opaque_ristretto255_sha512_3DH_ServerFinish(
        server_session_key,
        server_state,
        ke3
    );
    assert_int_equal(server_finish_ret, 0);

    assert_memory_equal(client_session_key, server_session_key, 64);
    assert_memory_equal(export_key, export_key2, 64);

    char session_key_hex[129];
    ecc_bin2hex(session_key_hex, client_session_key, sizeof client_session_key);
    assert_string_equal(session_key_hex, "d2dea308255aa3cecf72bcd6ac96ff7ab2e8bad0494b90180ad340b7"
                                 "d8942a36ee358e76c372790d4a5c1ac900997ea2abbf35f2d65510f8dfd668e593b8e1fe");
    char export_key_hex[129];
    ecc_bin2hex(export_key_hex, export_key, sizeof export_key);
    assert_string_equal(export_key_hex, "403a270110164ae0de7ea77c6824343211e8c1663ccaedde908dc9acf"
                                         "661039a379c8ac7e4b0cb23a8d1375ae94a772f91536de131d9d86633cb9445f773dfac");
}

/*
static void test_opaque_ristretto255_sha512_vector2(void **state) {
    ECC_UNUSED(state);

    byte_t context[10];
    ecc_hex2bin(context, "4f50415155452d504f43", 20);
    byte_t client_identity[5];
    ecc_hex2bin(client_identity, "616c696365", 10);
    byte_t server_identity[3];
    ecc_hex2bin(server_identity, "626f62", 6);
    byte_t oprf_seed[64];
    ecc_hex2bin(oprf_seed, "db5c1c16e264b8933d5da56439e7cfed23ab7287b474fe3cdcd58df089a365a426ea849258d9f4bc13573601f2e727c90ecc19d448cf3145a662e0065f157ba5", 128);
    byte_t credential_identifier[4];
    ecc_hex2bin(credential_identifier, "31323334", 8);
    byte_t password[25];
    ecc_hex2bin(password, "436f7272656374486f72736542617474657279537461706c65", 50);
    byte_t envelope_nonce[32];
    ecc_hex2bin(envelope_nonce, "d0c7b0f0047682bd87a87e0c3553b9bcdce7e1ae3348570df20bf2747829b2d2", 64);
    byte_t masking_nonce[32];
    ecc_hex2bin(masking_nonce, "30635396b708ddb7fc10fb73c4e3a9258cd9c3f6f761b2c227853b5def228c85", 64);
    byte_t server_private_key[32];
    ecc_hex2bin(server_private_key, "eeb2fcc794f98501b16139771720a0713a2750b9e528adfd3662ad56a7e19b04", 64);
    byte_t server_public_key[32];
    ecc_hex2bin(server_public_key, "8aa90cb321a38759fc253c444f317782962ca18d33101eab2c8cda04405a181f", 64);
    byte_t server_nonce[32];
    ecc_hex2bin(server_nonce, "3fa57f7ef652185f89114109f5a61cc8c9216fdd7398246bb7a0c20e2fbca2d8", 64);
    byte_t client_nonce[32];
    ecc_hex2bin(client_nonce, "a6bcd29b5aecc3507fc1f8f7631af3d2f5105155222e48099e5e6085d8c1187a", 64);
    byte_t server_keyshare[32];
    ecc_hex2bin(server_keyshare, "ae070cdffe5bb4b1c373e71be8e7d8f356ee5de37881533f10397bcd84d35445", 64);
    byte_t client_keyshare[32];
    ecc_hex2bin(client_keyshare, "642e7eecf19b804a62817486663d6c6c239396f709b663a4350cda67d025687a", 64);
    byte_t server_private_keyshare[32];
    ecc_hex2bin(server_private_keyshare, "0974010a8528b813f5b33ae0d791df88516c8839c152b030697637878b2d8b0a", 64);
    byte_t client_private_keyshare[32];
    ecc_hex2bin(client_private_keyshare, "03b52f066898929f4aca48014b2b97365205ce691ee3444b0a7cecec3c7efb01", 64);
    byte_t blind_registration[32];
    ecc_hex2bin(blind_registration, "a66ffb41ccf1194a8d7dda900f8b6b0652e4c7fac4610066fe0489a804d3bb05", 64);
    byte_t blind_login[32];
    ecc_hex2bin(blind_login, "e6f161ac189e6873a19a54efca4baa0719e801e336d929d35ca28b5b4f60560e", 64);

    byte_t registration_request[ecc_opaque_ristretto255_sha512_REGISTRATIONREQUESTSIZE];
    ecc_opaque_ristretto255_sha512_CreateRegistrationRequestWithBlind(
        registration_request,
        password, sizeof password,
        blind_registration
    );
    char registration_request_hex[2 * ecc_opaque_ristretto255_sha512_REGISTRATIONREQUESTSIZE + 1];
    ecc_bin2hex(registration_request_hex, registration_request, sizeof registration_request);
    assert_string_equal(registration_request_hex, "d81b76a8a78b8b0758f7ceffaa5c3cb4ac76c0517759ad8077ed87857e585f79");

    byte_t registration_response[ecc_opaque_ristretto255_sha512_REGISTRATIONRESPONSESIZE];
    byte_t oprf_key[32];
    ecc_opaque_ristretto255_sha512_CreateRegistrationResponse(
        registration_response,
        oprf_key,
        registration_request,
        server_public_key,
        credential_identifier, sizeof credential_identifier,
        oprf_seed
    );
    char registration_response_hex[2 * ecc_opaque_ristretto255_sha512_REGISTRATIONRESPONSESIZE + 1];
    ecc_bin2hex(registration_response_hex, registration_response, sizeof registration_response);
    assert_string_equal(registration_response_hex, "a48835aa277db6d7d501addbd431100a548867e3f1ee6fd6ae4aacd817a66e4c8aa90cb321a38759fc253c444f317782962ca18d33101eab2c8cda04405a181f");
    char oprf_key_hex[64];
    ecc_bin2hex(oprf_key_hex, oprf_key, sizeof oprf_key);
    assert_string_equal(oprf_key_hex, "531b0c7b0a3f90060c28d3d96ef5fecf56e25b8e4bf71c14bc770804c3fb4507");

    byte_t record[ecc_opaque_ristretto255_sha512_REGISTRATIONUPLOADSIZE];
    byte_t export_key[64];
    ecc_opaque_ristretto255_sha512_FinalizeRequestWithNonce(
        record,
        export_key,
        password, sizeof password,
        blind_registration,
        registration_response,
        server_identity, sizeof server_identity,
        client_identity, sizeof client_identity,
        ecc_opaque_ristretto255_sha512_MHF_IDENTITY,
        envelope_nonce
    );

    char record_hex[2 * ecc_opaque_ristretto255_sha512_REGISTRATIONUPLOADSIZE + 1];
    ecc_bin2hex(record_hex, record, sizeof record);
    assert_string_equal(record_hex, "3036af4744effe59eb7ee5db0ebcb653bd4a1c7ad0c56c78"
                                    "af1288f1e8538d1cedbc931daab2331b192808768f149499a04c6dffa4eae66a6e0d3"
                                    "399547c8b9e9a743a3cd20f08ce07adf84b27c9ca879d730bcc41823cbd60411fbde6"
                                    "c7faf2d0c7b0f0047682bd87a87e0c3553b9bcdce7e1ae3348570df20bf2747829b2d"
                                    "24117867ef8aa569ed6fa8ad1b3749b0df472d431ce92da7775e44623d6c36f7e9396"
                                    "d16ac58060704e9d42b37f09642ed7ee49008b4b81dc65d282ddcec0ab97");

    byte_t client_state[ecc_opaque_ristretto255_sha512_CLIENTSTATESIZE] = {0};
    byte_t ke1[ecc_opaque_ristretto255_sha512_KE1SIZE];
    ecc_opaque_ristretto255_sha512_3DH_ClientInitWithSecrets(
        ke1,
        client_state,
        password, sizeof password,
        blind_login,
        client_nonce,
        client_private_keyshare,
        client_keyshare
    );

    char ke1_hex[2 * ecc_opaque_ristretto255_sha512_KE1SIZE + 1];
    ecc_bin2hex(ke1_hex, ke1, sizeof ke1);
    assert_string_equal(ke1_hex, "8a32b2985d824b0e42b7d3c5091774acd64386f8a762678422f0b5cbabeda12b"
                                 "a6bcd29b5aecc3507fc1f8f7631af3d2f5105155222e48099e5e6085d8c1187a642e7"
                                 "eecf19b804a62817486663d6c6c239396f709b663a4350cda67d025687a");

    byte_t server_state[ecc_opaque_ristretto255_sha512_SERVERSTATESIZE] = {0};
    byte_t ke2[ecc_opaque_ristretto255_sha512_KE2SIZE];
    ecc_opaque_ristretto255_sha512_3DH_ServerInitWithSecrets(
        ke2,
        server_state,
        server_identity, sizeof server_identity,
        server_private_key,
        server_public_key,
        client_identity, sizeof client_identity,
        record,
        credential_identifier, sizeof credential_identifier,
        oprf_seed,
        ke1,
        context, sizeof context,
        masking_nonce,
        server_nonce,
        server_private_keyshare,
        server_keyshare
    );

    char ke2_hex[2 * ecc_opaque_ristretto255_sha512_KE2SIZE + 1];
    ecc_bin2hex(ke2_hex, ke2, sizeof ke2);
    assert_string_equal(ke2_hex, "da642966461f20090d1e8d6b1f63ea70dc94fc6e0ea0bad46d011e906cc03c03"
                                 "30635396b708ddb7fc10fb73c4e3a9258cd9c3f6f761b2c227853b5def228c8594543"
                                 "768891810f779604eb9e07dcd37635def358e2f4531f464a4e0b3726c150d7872785c"
                                 "9b6a22f00fe3527d9e938d4b503047484723585ee390925ab9d97e30f0860caef1243"
                                 "0459d8ca24e5ff1a2029c363ed00f2f3cd09ead304f217290d8915183c2667959d420"
                                 "175bfca3bbec3d603844ca0d5b5892888f0de19dc3b83fa57f7ef652185f89114109f"
                                 "5a61cc8c9216fdd7398246bb7a0c20e2fbca2d8ae070cdffe5bb4b1c373e71be8e7d8"
                                 "f356ee5de37881533f10397bcd84d354454f08b6c37449cf70cac0babb85d5302dc59"
                                 "a0ae16b2e54865642b8bb985f48444d49ad89a6a0707dd46c2d53b8b73dff46ac7176"
                                 "a6167f39818f605e3c39d22c");

    byte_t ke3[ecc_opaque_ristretto255_sha512_KE3SIZE];
    byte_t client_session_key[64];
    byte_t export_key2[64];
    int client_finish_ret = ecc_opaque_ristretto255_sha512_3DH_ClientFinish(
        ke3,
        client_session_key,
        export_key2,
        client_state,
        password, sizeof password,
        client_identity, sizeof client_identity,
        server_identity, sizeof server_identity,
        ke2,
        ecc_opaque_ristretto255_sha512_MHF_IDENTITY,
        context, sizeof context
    );
    char ke3_hex[2 * ecc_opaque_ristretto255_sha512_KE3SIZE + 1];
    ecc_bin2hex(ke3_hex, ke3, sizeof ke3);
    assert_string_equal(ke3_hex, "b9487ca4b1308ce593d765739992e19c10d63c47f4f2d3eb4bfd0ffa101b6959"
                                 "114b4f6051305652e0f48ad219a696f3f12fad685f8d6e371dddc10fda2ec87e");
    assert_int_equal(client_finish_ret, 0);

    byte_t server_session_key[64];
    int server_finish_ret = ecc_opaque_ristretto255_sha512_3DH_ServerFinish(
        server_session_key,
        server_state,
        ke3
    );
    assert_int_equal(server_finish_ret, 0);

    assert_memory_equal(client_session_key, server_session_key, 64);
    assert_memory_equal(export_key, export_key2, 64);

    char session_key_hex[129];
    ecc_bin2hex(session_key_hex, client_session_key, sizeof client_session_key);
    assert_string_equal(session_key_hex, "021c0c3f15940f3e898f2925949aa8bc262248fae7b9ed7d33a2900e"
                                         "866548ed24760c2244a2c14bfc196a00ffd66ebf54839850b101bc5e617c37ccad45a68a");
    char export_key_hex[129];
    ecc_bin2hex(export_key_hex, export_key, sizeof export_key);
    assert_string_equal(export_key_hex, "258d525e93a07c17dd9e41afc4fbfe316152afad02c54a6d3d201fd77"
                                        "487903143ca2ef27718a1e48b2ade5dc614b027b8a46fd334b701df5d385aaef2b1bd16");
}

static void test_opaque_ristretto255_sha512_random1(void **state) {
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
        password, sizeof password,
        blind,
        registration_response,
        NULL, 0,
        NULL, 0,
        ecc_opaque_ristretto255_sha512_MHF_IDENTITY
    );

    // tinker with password
    //password[0] = 0;

    byte_t client_state[160] = {0};
    byte_t ke1[96];
    ecc_opaque_ristretto255_sha512_3DH_ClientInit(
        ke1,
        client_state,
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
        NULL, 0,
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
        ke2,
        ecc_opaque_ristretto255_sha512_MHF_IDENTITY,
        NULL, 0
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

//    ecc_log("client_session_key", client_session_key, sizeof client_session_key);
//    ecc_log("server_session_key", server_session_key, sizeof server_session_key);
    assert_memory_equal(client_session_key, server_session_key, 64);
    assert_memory_equal(export_key, export_key2, 64);
}*/

int main(void) {
    const struct CMUnitTest tests[] = {
        // vector tests
        cmocka_unit_test(test_opaque_ristretto255_sha512_vector1),
        // cmocka_unit_test(test_opaque_ristretto255_sha512_vector2),
        // protocol
        // cmocka_unit_test(test_opaque_ristretto255_sha512_random1),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
