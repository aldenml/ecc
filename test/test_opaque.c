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

// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-07#appendix-D.1.1
static void test_opaque_ristretto255_sha512_vector1(void **state) {
    ECC_UNUSED(state);

    byte_t context[10];
    ecc_hex2bin(context, "4f50415155452d504f43", 20);
    byte_t oprf_seed[64];
    ecc_hex2bin(oprf_seed, "5c4f99877d253be5817b4b03f37b6da680b0d5671d1ec5351fa61c5d82eab28b9de4c4e170f27e433ba377c71c49aa62ad26391ee1cac17011d8a7e9406657c8", 128);
    byte_t credential_identifier[4];
    ecc_hex2bin(credential_identifier, "31323334", 8);
    byte_t password[25];
    ecc_hex2bin(password, "436f7272656374486f72736542617474657279537461706c65", 50);
    byte_t envelope_nonce[32];
    ecc_hex2bin(envelope_nonce, "71b8f14b7a1059cdadc414c409064a22cf9e970b0ffc6f1fc6fdd539c4676775", 64);
    byte_t masking_nonce[32];
    ecc_hex2bin(masking_nonce, "54f9341ca183700f6b6acf28dbfe4a86afad788805de49f2d680ab86ff39ed7f", 64);
    byte_t server_private_key[32];
    ecc_hex2bin(server_private_key, "16eb9dc74a3df2033cd738bf2cfb7a3670c569d7749f284b2b241cb237e7d10f", 64);
    byte_t server_public_key[32];
    ecc_hex2bin(server_public_key, "18d5035fd0a9c1d6412226df037125901a43f4dff660c0549d402f672bcc0933", 64);
    byte_t server_nonce[32];
    ecc_hex2bin(server_nonce, "f9c5ec75a8cd571370add249e99cb8a8c43f6ef05610ac6e354642bf4fedbf69", 64);
    byte_t client_nonce[32];
    ecc_hex2bin(client_nonce, "804133133e7ee6836c8515752e24bb44d323fef4ead34cde967798f2e9784f69", 64);
    byte_t server_keyshare[32];
    ecc_hex2bin(server_keyshare, "6e77d4749eb304c4d74be9457c597546bc22aed699225499910fc913b3e90712", 64);
    byte_t client_keyshare[32];
    ecc_hex2bin(client_keyshare, "f67926bd036c5dc4971816b9376e9f64737f361ef8269c18f69f1ab555e96d4a", 64);
    byte_t server_private_keyshare[32];
    ecc_hex2bin(server_private_keyshare, "f8e3e31543dd6fc86833296726773d51158291ab9afd666bb55dce83474c1101", 64);
    byte_t client_private_keyshare[32];
    ecc_hex2bin(client_private_keyshare, "4230d62ea740b13e178185fc517cf2c313e6908c4cd9fb42154870ff3490c608", 64);
    byte_t blind_registration[32];
    ecc_hex2bin(blind_registration, "c62937d17dc9aa213c9038f84fe8c5bf3d953356db01c4d48acb7cae48e6a504", 64);
    byte_t blind_login[32];
    ecc_hex2bin(blind_login, "b5f458822ea11c900ad776e38e29d7be361f75b4d79b55ad74923299bf8d6503", 64);

    byte_t registration_request[ecc_opaque_ristretto255_sha512_REGISTRATIONREQUESTSIZE];
    ecc_opaque_ristretto255_sha512_CreateRegistrationRequestWithBlind(
        registration_request,
        password, sizeof password,
        blind_registration
    );
    char registration_request_hex[2 * ecc_opaque_ristretto255_sha512_REGISTRATIONREQUESTSIZE + 1];
    ecc_bin2hex(registration_request_hex, registration_request, sizeof registration_request);
    assert_string_equal(registration_request_hex, "ac7a6330f91d1e5c87365630c7be58641885d59ffe4d3f8a49c094271993331d");

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
    assert_string_equal(registration_response_hex, "5c7d3c70cf7478ead859bb879b37cce78baef3b9d81e04f4c790ce25f2830e2e18d5035fd0a9c1d6412226df037125901a43f4dff660c0549d402f672bcc0933");
    char oprf_key_hex[64];
    ecc_bin2hex(oprf_key_hex, oprf_key, sizeof oprf_key);
    assert_string_equal(oprf_key_hex, "3f76113135e6ca7e51ac5bb3e8774eb84709ad36b8907ec8f7bc353782871906");

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
    assert_string_equal(record_hex, "60c9b59f46e93a2dc8c5dd0dd101fad1838f4c4c026691e9"
                                    "d18d3de8f2b3940d7981498360f8f276df1dfb852a93ec4f4a0189dec5a96363296a6"
                                    "93fc8a51fb052ae8318dac48be7e3c3cd290f7b8c12b807617b7f9399417deed00158"
                                    "281ac771b8f14b7a1059cdadc414c409064a22cf9e970b0ffc6f1fc6fdd539c467677"
                                    "50a343dd3f683692f4ed987ff286a4ece0813a4942e23477920608f261e1ab6f8727f"
                                    "532c9fd0cde8ec492cb76efdc855da76d0b6ccbe8a4dc0ba2709d63c4517");

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
    assert_string_equal(ke1_hex, "e4e7ce5bf96ddb2924faf816774b26a0ec7a6dd9d3a5bced1f4a3675c3cfd14c"
                                 "804133133e7ee6836c8515752e24bb44d323fef4ead34cde967798f2e9784f69f6792"
                                 "6bd036c5dc4971816b9376e9f64737f361ef8269c18f69f1ab555e96d4a");

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
    assert_string_equal(ke2_hex, "1af11be29a90322dc16462d0861b1eb617611fe2f05e5e9860c164592d4f7f62"
                                 "54f9341ca183700f6b6acf28dbfe4a86afad788805de49f2d680ab86ff39ed7f76011"
                                 "9ed2f12f6ec4983f2c598068057af146fd09133c75b229145b7580d53cac4ba581155"
                                 "2e6786837a3e03d9f7971df0dad4a04fd6a6d4164101c91137a87f4afde7dae72daf2"
                                 "620082f46413bbb3071767d549833bcc523acc645b571a66318b0b1f8bf4b23de3542"
                                 "8373aa1d3a45c1e89eff88f03f9446e5dfc23b6f8394f9c5ec75a8cd571370add249e"
                                 "99cb8a8c43f6ef05610ac6e354642bf4fedbf696e77d4749eb304c4d74be9457c5975"
                                 "46bc22aed699225499910fc913b3e907120638f222a1a08460f4e40d0686830d3d608"
                                 "ce89789489161438bf6809dbbce3a6ddb0ce8702576843b58465d6cedd4e965f3f81b"
                                 "92992ecec0e2137b66eff0b4");

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
    assert_string_equal(ke3_hex, "1c0c743ff88f1a4ff07350eef61e899ae25d7fb23d555926b218bac4c1963071"
                                 "5038c56cca247630be8a8e66f3ff18b89c1bc97e1e2192fd7f14f2f60ed084a3");
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
    assert_string_equal(session_key_hex, "05d03f4143e5866844f7ae921d3b48f3d611e930a6c4be0993a98290"
                                 "085110c5a27a2e5f92aeed861b90de068a51a952aa75bf97589be7c7104a4c30cc357506");
    char export_key_hex[129];
    ecc_bin2hex(export_key_hex, export_key, sizeof export_key);
    assert_string_equal(export_key_hex, "8408f92d282c7f4b0f5462e5206bd92937a4d53b0dcdef90afffd015c"
                                         "5dee44dc4dc5ad35d1681c97e2b66de09203ac359a69f1d45f8c97dbc907589177ccc24");
}

// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-07#appendix-D.1.2
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
}

int main() {
    const struct CMUnitTest tests[] = {
        // vector tests
        cmocka_unit_test(test_opaque_ristretto255_sha512_vector1),
        cmocka_unit_test(test_opaque_ristretto255_sha512_vector2),
        // protocol
        cmocka_unit_test(test_opaque_ristretto255_sha512_random1),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
