/*
 * Copyright (c) 2021-2023, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#include "ecc_test.h"

// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-09#appendix-D.1.1.1
static void test_opaque_ristretto255_sha512(void **state) {
    ECC_UNUSED(state);

    ecc_json_t json = ecc_json_load("../test/data/opaque/ristretto255_sha512.json");

    const int n = ecc_json_array_size(json, "vectors");

    for (int i = 0; i < n; i++) {
        ecc_json_t item = ecc_json_array_item(json, "vectors", i);

        byte_t Context[1024];
        int ContextLen;
        ecc_json_hex(Context, &ContextLen, item, "config.Context");
        ecc_log("Context", Context, ContextLen);

        byte_t blind_login[32];
        int blind_login_len;
        ecc_json_hex(blind_login, &blind_login_len, item, "inputs.blind_login");
        ecc_log("blind_login", blind_login, blind_login_len);

        byte_t blind_registration[32];
        int blind_registration_len;
        ecc_json_hex(blind_registration, &blind_registration_len, item, "inputs.blind_registration");
        ecc_log("blind_registration", blind_registration, blind_registration_len);

        byte_t client_identity[1024];
        int client_identity_len;
        ecc_json_hex(client_identity, &client_identity_len, item, "inputs.client_identity");
        ecc_log("client_identity", client_identity, client_identity_len);

        byte_t client_keyshare[32];
        int client_keyshare_len;
        ecc_json_hex(client_keyshare, &client_keyshare_len, item, "inputs.client_keyshare");
        ecc_log("client_keyshare", client_keyshare, client_keyshare_len);

        byte_t client_nonce[32];
        int client_nonce_len;
        ecc_json_hex(client_nonce, &client_nonce_len, item, "inputs.client_nonce");
        ecc_log("client_nonce", client_nonce, client_nonce_len);

        byte_t client_private_keyshare[32];
        int client_private_keyshare_len;
        ecc_json_hex(client_private_keyshare, &client_private_keyshare_len, item, "inputs.client_private_keyshare");
        ecc_log("client_private_keyshare", client_private_keyshare, client_private_keyshare_len);

        byte_t credential_identifier[1024];
        int credential_identifier_len;
        ecc_json_hex(credential_identifier, &credential_identifier_len, item, "inputs.credential_identifier");
        ecc_log("credential_identifier", credential_identifier, credential_identifier_len);

        byte_t envelope_nonce[32];
        int envelope_nonce_len;
        ecc_json_hex(envelope_nonce, &envelope_nonce_len, item, "inputs.envelope_nonce");
        ecc_log("envelope_nonce", envelope_nonce, envelope_nonce_len);

        byte_t masking_nonce[32];
        int masking_nonce_len;
        ecc_json_hex(masking_nonce, &masking_nonce_len, item, "inputs.masking_nonce");
        ecc_log("masking_nonce", masking_nonce, masking_nonce_len);

        byte_t oprf_seed[64];
        int oprf_seed_len;
        ecc_json_hex(oprf_seed, &oprf_seed_len, item, "inputs.oprf_seed");
        ecc_log("oprf_seed", oprf_seed, oprf_seed_len);

        byte_t password[1024];
        int password_len;
        ecc_json_hex(password, &password_len, item, "inputs.password");
        ecc_log("password", password, password_len);

        byte_t server_identity[1024];
        int server_identity_len;
        ecc_json_hex(server_identity, &server_identity_len, item, "inputs.server_identity");
        ecc_log("server_identity", server_identity, server_identity_len);

        byte_t server_keyshare[32];
        int server_keyshare_len;
        ecc_json_hex(server_keyshare, &server_keyshare_len, item, "inputs.server_keyshare");
        ecc_log("server_keyshare", server_keyshare, server_keyshare_len);

        byte_t server_nonce[32];
        int server_nonce_len;
        ecc_json_hex(server_nonce, &server_nonce_len, item, "inputs.server_nonce");
        ecc_log("server_nonce", server_nonce, server_nonce_len);

        byte_t server_private_key[32];
        int server_private_key_len;
        ecc_json_hex(server_private_key, &server_private_key_len, item, "inputs.server_private_key");
        ecc_log("server_private_key", server_private_key, server_private_key_len);

        byte_t server_private_keyshare[32];
        int server_private_keyshare_len;
        ecc_json_hex(server_private_keyshare, &server_private_keyshare_len, item, "inputs.server_private_keyshare");
        ecc_log("server_private_keyshare", server_private_keyshare, server_private_keyshare_len);

        byte_t server_public_key[32];
        int server_public_key_len;
        ecc_json_hex(server_public_key, &server_public_key_len, item, "inputs.server_public_key");
        ecc_log("server_public_key", server_public_key, server_public_key_len);

        byte_t outputs_KE1[ecc_opaque_ristretto255_sha512_KE1SIZE];
        int outputs_KE1_len;
        ecc_json_hex(outputs_KE1, &outputs_KE1_len, item, "outputs.KE1");
        ecc_log("outputs_KE1", outputs_KE1, outputs_KE1_len);

        byte_t outputs_KE2[ecc_opaque_ristretto255_sha512_KE2SIZE];
        int outputs_KE2_len;
        ecc_json_hex(outputs_KE2, &outputs_KE2_len, item, "outputs.KE2");
        ecc_log("outputs_KE2", outputs_KE2, outputs_KE2_len);

        byte_t outputs_KE3[ecc_opaque_ristretto255_sha512_KE3SIZE];
        int outputs_KE3_len;
        ecc_json_hex(outputs_KE3, &outputs_KE3_len, item, "outputs.KE3");
        ecc_log("outputs_KE3", outputs_KE3, outputs_KE3_len);

        byte_t outputs_export_key[64];
        int outputs_export_key_len;
        ecc_json_hex(outputs_export_key, &outputs_export_key_len, item, "outputs.export_key");
        ecc_log("outputs_export_key", outputs_export_key, outputs_export_key_len);

        byte_t outputs_registration_request[ecc_opaque_ristretto255_sha512_REGISTRATIONREQUESTSIZE];
        int outputs_registration_request_len;
        ecc_json_hex(outputs_registration_request, &outputs_registration_request_len, item, "outputs.registration_request");
        ecc_log("outputs_registration_request", outputs_registration_request, outputs_registration_request_len);

        byte_t outputs_registration_response[ecc_opaque_ristretto255_sha512_REGISTRATIONRESPONSESIZE];
        int outputs_registration_response_len;
        ecc_json_hex(outputs_registration_response, &outputs_registration_response_len, item, "outputs.registration_response");
        ecc_log("outputs_registration_response", outputs_registration_response, outputs_registration_response_len);

        byte_t outputs_registration_upload[ecc_opaque_ristretto255_sha512_REGISTRATIONRECORDSIZE];
        int outputs_registration_upload_len;
        ecc_json_hex(outputs_registration_upload, &outputs_registration_upload_len, item, "outputs.registration_upload");
        ecc_log("outputs_registration_upload", outputs_registration_upload, outputs_registration_upload_len);

        byte_t outputs_session_key[64];
        int outputs_session_key_len;
        ecc_json_hex(outputs_session_key, &outputs_session_key_len, item, "outputs.session_key");
        ecc_log("outputs_session_key", outputs_session_key, outputs_session_key_len);

        byte_t registration_request[ecc_opaque_ristretto255_sha512_REGISTRATIONREQUESTSIZE];
        ecc_opaque_ristretto255_sha512_CreateRegistrationRequestWithBlind(
            registration_request,
            password, password_len,
            blind_registration
        );
        assert_memory_equal(registration_request, outputs_registration_request, sizeof outputs_registration_request);

        byte_t registration_response[ecc_opaque_ristretto255_sha512_REGISTRATIONRESPONSESIZE];
        ecc_opaque_ristretto255_sha512_CreateRegistrationResponse(
            registration_response,
            registration_request,
            server_public_key,
            credential_identifier, credential_identifier_len,
            oprf_seed
        );
        assert_memory_equal(registration_response, outputs_registration_response, sizeof outputs_registration_response);

        byte_t record[ecc_opaque_ristretto255_sha512_REGISTRATIONRECORDSIZE];
        byte_t export_key[64];
        ecc_opaque_ristretto255_sha512_FinalizeRegistrationRequestWithNonce(
            record,
            export_key,
            password, password_len,
            blind_registration,
            registration_response,
            server_identity, server_identity_len,
            client_identity, client_identity_len,
            ecc_opaque_ristretto255_sha512_MHF_IDENTITY,
            envelope_nonce
        );
        assert_memory_equal(record, outputs_registration_upload, sizeof outputs_registration_upload);

        byte_t client_state[ecc_opaque_ristretto255_sha512_CLIENTSTATESIZE] = {0};
        byte_t ke1[ecc_opaque_ristretto255_sha512_KE1SIZE];
        ecc_opaque_ristretto255_sha512_ClientInitWithSecrets(
            ke1,
            client_state,
            password, password_len,
            blind_login,
            client_nonce,
            client_private_keyshare,
            client_keyshare
        );
        assert_memory_equal(ke1, outputs_KE1, sizeof outputs_KE1);

        byte_t server_state[ecc_opaque_ristretto255_sha512_SERVERSTATESIZE] = {0};
        byte_t ke2[ecc_opaque_ristretto255_sha512_KE2SIZE];
        ecc_opaque_ristretto255_sha512_ServerInitWithSecrets(
            ke2,
            server_state,
            server_identity, server_identity_len,
            server_private_key,
            server_public_key,
            record,
            credential_identifier, credential_identifier_len,
            oprf_seed,
            ke1,
            client_identity, client_identity_len,
            Context, ContextLen,
            masking_nonce,
            server_nonce,
            server_private_keyshare,
            server_keyshare
        );
        assert_memory_equal(ke2, outputs_KE2, sizeof outputs_KE2);

        byte_t ke3[ecc_opaque_ristretto255_sha512_KE3SIZE];
        byte_t client_session_key[64];
        byte_t export_key2[64];
        int client_finish_ret = ecc_opaque_ristretto255_sha512_ClientFinish(
            ke3,
            client_session_key,
            export_key2,
            client_state,
            client_identity, client_identity_len,
            server_identity, server_identity_len,
            ke2,
            ecc_opaque_ristretto255_sha512_MHF_IDENTITY,
            Context, ContextLen
        );
        assert_memory_equal(ke3, outputs_KE3, sizeof outputs_KE3);
        assert_int_equal(client_finish_ret, 0);

        byte_t server_session_key[64];
        int server_finish_ret = ecc_opaque_ristretto255_sha512_ServerFinish(
            server_session_key,
            server_state,
            ke3
        );
        assert_int_equal(server_finish_ret, 0);

        assert_memory_equal(client_session_key, server_session_key, 64);
        assert_memory_equal(client_session_key, outputs_session_key, sizeof outputs_session_key);
        assert_memory_equal(export_key, export_key2, 64);
        assert_memory_equal(export_key, outputs_export_key, sizeof outputs_export_key);
    }

    ecc_json_destroy(json);
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

    byte_t registration_request[ecc_opaque_ristretto255_sha512_REGISTRATIONREQUESTSIZE];
    byte_t blind[32];
    ecc_opaque_ristretto255_sha512_CreateRegistrationRequest(
        registration_request,
        blind,
        password, 25
    );

    byte_t registration_response[ecc_opaque_ristretto255_sha512_REGISTRATIONRESPONSESIZE];
    ecc_opaque_ristretto255_sha512_CreateRegistrationResponse(
        registration_response,
        registration_request,
        server_public_key,
        credential_identifier, sizeof credential_identifier,
        oprf_seed
    );

    byte_t record[ecc_opaque_ristretto255_sha512_REGISTRATIONRECORDSIZE];
    byte_t export_key[64];
    ecc_opaque_ristretto255_sha512_FinalizeRegistrationRequest(
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

    byte_t client_state[ecc_opaque_ristretto255_sha512_CLIENTSTATESIZE] = {0};
    byte_t ke1[ecc_opaque_ristretto255_sha512_KE1SIZE];
    ecc_opaque_ristretto255_sha512_ClientInit(
        ke1,
        client_state,
        password, sizeof password
    );

    byte_t server_state[ecc_opaque_ristretto255_sha512_SERVERSTATESIZE] = {0};
    byte_t ke2[ecc_opaque_ristretto255_sha512_KE2SIZE];
    ecc_opaque_ristretto255_sha512_ServerInit(
        ke2,
        server_state,
        NULL, 0,
        server_private_key,
        server_public_key,
        record,
        credential_identifier, sizeof credential_identifier,
        oprf_seed,
        ke1,
        NULL, 0,
        NULL, 0
    );
//    ecc_log("ke2", ke2, sizeof ke2);

    byte_t ke3[ecc_opaque_ristretto255_sha512_KE3SIZE];
    byte_t client_session_key[64];
    byte_t export_key2[64];
    int client_finish_ret = ecc_opaque_ristretto255_sha512_ClientFinish(
        ke3,
        client_session_key,
        export_key2,
        client_state,
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
    int server_finish_ret = ecc_opaque_ristretto255_sha512_ServerFinish(
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

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_opaque_ristretto255_sha512),
        // protocol
        cmocka_unit_test(test_opaque_ristretto255_sha512_random1),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
