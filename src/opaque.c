/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#include "opaque.h"
#include <string.h>
#include <assert.h>
#include <sodium.h>
#include "util.h"
#include "hash.h"
#include "mac.h"
#include "kdf.h"
#include "ristretto255.h"
#include "oprf.h"

#define Nn ecc_opaque_ristretto255_sha512_Nn // 32
#define Nm ecc_opaque_ristretto255_sha512_Nm // 64
#define Nh ecc_opaque_ristretto255_sha512_Nh // 64
#define Nx ecc_opaque_ristretto255_sha512_Nx // 64
#define Npk ecc_opaque_ristretto255_sha512_Npk // 32
#define Nsk ecc_opaque_ristretto255_sha512_Nsk // 32
#define Noe ecc_opaque_ristretto255_sha512_Noe // 32
#define Nok ecc_opaque_ristretto255_sha512_Nok // 32
#define Ne ecc_opaque_ristretto255_sha512_Ne // 96

typedef struct {
    byte_t nonce[Nn];
    byte_t auth_tag[Nm];
} Envelope_t;

typedef struct {
    byte_t data[Noe];
} RegistrationRequest_t;

typedef struct {
    byte_t data[Noe];
    byte_t server_public_key[Npk];
} RegistrationResponse_t;

typedef struct {
    byte_t client_public_key[Npk];
    byte_t masking_key[Nh];
    Envelope_t envelope;
} RegistrationUpload_t;

typedef struct {
    byte_t data[Noe];
} CredentialRequest_t;

typedef struct {
    byte_t data[Noe];
    byte_t masking_nonce[Nn];
    byte_t masked_response[Npk + Ne];
} CredentialResponse_t;

typedef struct {
    CredentialRequest_t request;
    byte_t client_nonce[Nn];
    byte_t client_keyshare[Npk];
} KE1_t;

typedef struct {
    struct {
        CredentialResponse_t response;
        byte_t server_nonce[Nn];
        byte_t server_keyshare[Npk];
    } inner_ke2;
    byte_t server_mac[Nm];
} KE2_t;

typedef struct {
    byte_t client_mac[Nm];
} KE3_t;

typedef struct {
    byte_t blind[Nok];
    byte_t client_secret[Nsk];
    KE1_t ke1;
} ClientState_t;

typedef struct {
    byte_t expected_client_mac[Nm];
    byte_t session_key[Nx];
} ServerState_t;

static_assert(sizeof(Envelope_t) == ecc_opaque_ristretto255_sha512_Ne, "");
static_assert(sizeof(RegistrationRequest_t) == ecc_opaque_ristretto255_sha512_REGISTRATIONREQUESTSIZE, "");
static_assert(sizeof(RegistrationResponse_t) == ecc_opaque_ristretto255_sha512_REGISTRATIONRESPONSESIZE, "");
static_assert(sizeof(RegistrationUpload_t) == ecc_opaque_ristretto255_sha512_REGISTRATIONUPLOADSIZE, "");
static_assert(sizeof(CredentialRequest_t) == ecc_opaque_ristretto255_sha512_CREDENTIALREQUESTSIZE, "");
static_assert(sizeof(CredentialResponse_t) == ecc_opaque_ristretto255_sha512_CREDENTIALRESPONSESIZE, "");
static_assert(sizeof(KE1_t) == ecc_opaque_ristretto255_sha512_KE1SIZE, "");
static_assert(sizeof(KE2_t) == ecc_opaque_ristretto255_sha512_KE2SIZE, "");
static_assert(sizeof(KE3_t) == ecc_opaque_ristretto255_sha512_KE3SIZE, "");
static_assert(sizeof(ClientState_t) == ecc_opaque_ristretto255_sha512_CLIENTSTATESIZE, "");
static_assert(sizeof(ServerState_t) == ecc_opaque_ristretto255_sha512_SERVERSTATESIZE, "");

int ecc_opaque_ristretto255_sha512_CreateCleartextCredentials(
    byte_t *cleartext_credentials,
    const byte_t *server_public_key,
    const byte_t *client_public_key,
    const byte_t *server_identity, int server_identity_len,
    const byte_t *client_identity, int client_identity_len
) {
    // Steps:
    // 1. if server_identity == nil
    // 2.    server_identity = server_public_key
    // 3. if client_identity == nil
    // 4.    client_identity = client_public_key
    // 5. Create CleartextCredentials cleartext_credentials
    //    with (server_public_key, server_identity, client_identity)
    // 6. Output cleartext_credentials

    if (server_identity == NULL || server_identity_len == 0) {
        server_identity = server_public_key;
        server_identity_len = Npk;
    }
    if (client_identity == NULL || client_identity_len == 0) {
        client_identity = client_public_key;
        client_identity_len = Npk;
    }

    const int total_size = Npk + server_identity_len + client_identity_len;
    if (cleartext_credentials == NULL)
        return total_size;

    ecc_concat3(
        cleartext_credentials,
        server_public_key, Npk,
        server_identity, server_identity_len,
        client_identity, client_identity_len
    );

    return total_size;
}

void ecc_opaque_ristretto255_sha512_CreateEnvelopeWithNonce(
    byte_t *envelope_raw,
    byte_t *client_public_key,
    byte_t *masking_key,
    byte_t *export_key, // 64
    const byte_t *randomized_pwd,
    const byte_t *server_public_key,
    const byte_t *client_private_key,
    const byte_t *server_identity, int server_identity_len,
    const byte_t *client_identity, int client_identity_len,
    const byte_t *nonce // 32
) {
    // Steps:
    // 1. envelope_nonce = random(Nn)
    // 2. auth_key = Expand(randomized_pwd, concat(envelope_nonce, "AuthKey"), Nh)
    // 3. export_key = Expand(randomized_pwd, concat(envelope_nonce, "ExportKey"), Nh)
    // 4. masking_key = Expand(randomized_pwd, "MaskingKey", Nh)
    // 5. inner_env, client_public_key = BuildInnerEnvelope(randomized_pwd, envelope_nonce, client_private_key)
    // 6. cleartext_creds = CreateCleartextCredentials(server_public_key, client_public_key, server_identity, client_identity)
    // 7. auth_tag = MAC(auth_key, concat(envelope_nonce, inner_env, cleartext_creds))
    // 8. Create Envelope envelope with (envelope_nonce, inner_env, auth_tag)
    // 9. Output (envelope, client_public_key, masking_key, export_key)

    Envelope_t *envelope = (Envelope_t *) envelope_raw;

    // 1. envelope_nonce = random(Nn)
    const byte_t *envelope_nonce = nonce;

    // 2. auth_key = Expand(randomized_pwd, concat(envelope_nonce, "AuthKey"), Nh)
    byte_t auth_key_label[7] = "AuthKey";
    byte_t auth_key_info[Nn + 7];
    ecc_concat2(auth_key_info, envelope_nonce, Nn, auth_key_label, 7);
    byte_t auth_key[Nh];
    ecc_kdf_hkdf_sha512_expand(auth_key, randomized_pwd, auth_key_info, sizeof auth_key_info, Nh);

    // 3. export_key = Expand(randomized_pwd, concat(envelope_nonce, "ExportKey"), Nh)
    byte_t export_key_label[9] = "ExportKey";
    byte_t export_key_info[Nn + 9];
    ecc_concat2(export_key_info, envelope_nonce, Nn, export_key_label, 9);
    ecc_kdf_hkdf_sha512_expand(export_key, randomized_pwd, export_key_info, sizeof export_key_info, Nh);

    // 4. masking_key = Expand(randomized_pwd, "MaskingKey", Nh)
    byte_t masking_key_info[10] = "MaskingKey";
    ecc_kdf_hkdf_sha512_expand(masking_key, randomized_pwd, masking_key_info, sizeof masking_key_info, Nh);

    // 5. inner_env, client_public_key = BuildInnerEnvelope(randomized_pwd, envelope_nonce, client_private_key)
    ecc_opaque_ristretto255_sha512_BuildInnerEnvelope(
        NULL, client_public_key,
        randomized_pwd, envelope_nonce, client_private_key
    );

    // 6. cleartext_creds = CreateCleartextCredentials(server_public_key, client_public_key, server_identity, client_identity)
    byte_t cleartext_creds[512];
    const int cleartext_creds_len = ecc_opaque_ristretto255_sha512_CreateCleartextCredentials(
        cleartext_creds,
        server_public_key, client_public_key,
        server_identity, server_identity_len,
        client_identity, client_identity_len
    );

    // 7. auth_tag = MAC(auth_key, concat(envelope_nonce, inner_env, cleartext_creds))
    byte_t auth_tag_mac_input[512];
    const int auth_tag_mac_input_len = Nn + 0 + cleartext_creds_len;
    ecc_concat3(
        auth_tag_mac_input,
        envelope_nonce, Nn,
        NULL, 0,
        cleartext_creds, cleartext_creds_len
    );
    ecc_mac_hmac_sha512(
        envelope->auth_tag,
        auth_tag_mac_input, auth_tag_mac_input_len,
        auth_key
    );

    // 8. Create Envelope envelope with (envelope_nonce, inner_env, auth_tag)
    memcpy(envelope->nonce, envelope_nonce, Nn);
    // inner_env is nil
    // auth_tag is set in step 7

    // cleanup stack memory
    ecc_memzero(auth_key_info, sizeof auth_key_info);
    ecc_memzero(auth_key, sizeof auth_key);
    ecc_memzero(export_key_info, sizeof export_key_info);
    ecc_memzero(cleartext_creds, sizeof cleartext_creds);
    ecc_memzero(auth_tag_mac_input, sizeof auth_tag_mac_input);
}

void ecc_opaque_ristretto255_sha512_CreateEnvelope(
    byte_t *envelope_raw,
    byte_t *client_public_key,
    byte_t *masking_key,
    byte_t *export_key, // 64
    const byte_t *randomized_pwd,
    const byte_t *server_public_key,
    const byte_t *client_private_key,
    const byte_t *server_identity, int server_identity_len,
    const byte_t *client_identity, int client_identity_len
) {
    // 1. envelope_nonce = random(Nn)
    byte_t envelope_nonce[Nh];
    ecc_randombytes(envelope_nonce, Nh);

    ecc_opaque_ristretto255_sha512_CreateEnvelopeWithNonce(
        envelope_raw,
        client_public_key,
        masking_key,
        export_key,
        randomized_pwd,
        server_public_key, client_private_key,
        server_identity, server_identity_len,
        client_identity, client_identity_len,
        envelope_nonce
    );

    // cleanup stack memory
    ecc_memzero(envelope_nonce, sizeof envelope_nonce);
}

int ecc_opaque_ristretto255_sha512_RecoverEnvelope(
    byte_t *client_private_key,
    byte_t *export_key, // 64
    const byte_t *randomized_pwd,
    const byte_t *server_public_key,
    const byte_t *envelope_raw,
    const byte_t *server_identity, int server_identity_len,
    const byte_t *client_identity, int client_identity_len
) {
    // Steps:
    // 1. auth_key = Expand(randomized_pwd, concat(envelope.nonce, "AuthKey"), Nh)
    // 2. export_key = Expand(randomized_pwd, concat(envelope.nonce, "ExportKey", Nh)
    // 3. (client_private_key, client_public_key) =
    //     RecoverKeys(randomized_pwd, envelope.nonce, envelope.inner_env)
    // 4. cleartext_creds = CreateCleartextCredentials(server_public_key,
    //                       client_public_key, server_identity, client_identity)
    // 5. expected_tag = MAC(auth_key, concat(envelope.nonce, inner_env, cleartext_creds))
    // 6. If !ct_equal(envelope.auth_tag, expected_tag),
    //      raise EnvelopeRecoveryError
    // 7. Output (client_private_key, export_key)

    Envelope_t *envelope = (Envelope_t *) envelope_raw;

    // 1. auth_key = Expand(randomized_pwd, concat(envelope.nonce, "AuthKey"), Nh)
    byte_t auth_key_label[7] = "AuthKey";
    byte_t auth_key_info[Nn + 7];
    ecc_concat2(auth_key_info, envelope->nonce, Nn, auth_key_label, 7);
    byte_t auth_key[Nh];
    ecc_kdf_hkdf_sha512_expand(auth_key, randomized_pwd, auth_key_info, sizeof auth_key_info, Nh);

    // 2. export_key = Expand(randomized_pwd, concat(envelope.nonce, "ExportKey", Nh)
    byte_t export_key_label[9] = "ExportKey";
    byte_t export_key_info[Nn + 9];
    ecc_concat2(export_key_info, envelope->nonce, Nn, export_key_label, 9);
    ecc_kdf_hkdf_sha512_expand(export_key, randomized_pwd, export_key_info, sizeof export_key_info, Nh);

    // 3. (client_private_key, client_public_key) =
    //     RecoverKeys(randomized_pwd, envelope.nonce, envelope.inner_env)
    byte_t client_public_key[32];
    ecc_opaque_ristretto255_sha512_RecoverKeys(
        client_private_key,
        client_public_key,
        randomized_pwd,
        envelope->nonce,
        NULL
    );

    // 4. cleartext_creds = CreateCleartextCredentials(server_public_key,
    //                       client_public_key, server_identity, client_identity)
    byte_t cleartext_creds[512];
    const int cleartext_creds_len = ecc_opaque_ristretto255_sha512_CreateCleartextCredentials(
        cleartext_creds,
        server_public_key,
        client_public_key,
        server_identity, server_identity_len,
        client_identity, client_identity_len
    );

    // 5. expected_tag = MAC(auth_key, concat(envelope.nonce, inner_env, cleartext_creds))
    byte_t expected_tag_mac_input[512];
    const int expected_tag_mac_input_input_len = Nn + 0 + cleartext_creds_len;
    ecc_concat2(expected_tag_mac_input, envelope->nonce, Nn, cleartext_creds, cleartext_creds_len);
    byte_t expected_tag[64];
    ecc_mac_hmac_sha512(expected_tag, expected_tag_mac_input, expected_tag_mac_input_input_len, auth_key);

    // cleanup stack memory
    ecc_memzero(auth_key_info, sizeof auth_key_info);
    ecc_memzero(auth_key, sizeof auth_key);
    ecc_memzero(export_key_info, sizeof export_key_info);
    ecc_memzero(client_public_key, sizeof client_public_key);
    ecc_memzero(cleartext_creds, sizeof cleartext_creds);
    ecc_memzero(expected_tag_mac_input, sizeof expected_tag_mac_input);

    // 6. If !ct_equal(envelope.auth_tag, expected_tag),
    //      raise EnvelopeRecoveryError
    if (ecc_compare(envelope->auth_tag, expected_tag, 64)) {
        ecc_memzero(expected_tag, sizeof expected_tag);
        return -1;
    }

    // 7. Output (client_private_key, export_key)
    return 0;
}

void ecc_opaque_ristretto255_sha512_RecoverPublicKey(
    byte_t *public_key, // 32
    const byte_t *private_key // 32
) {
    ecc_ristretto255_scalarmult_base(public_key, private_key);
}

void ecc_opaque_ristretto255_sha512_GenerateAuthKeyPair(
    byte_t *private_key, byte_t *public_key
) {
    byte_t seed[32];
    ecc_randombytes(seed, sizeof seed);

    ecc_opaque_ristretto255_sha512_DeriveAuthKeyPair(
        private_key, public_key,
        seed, sizeof seed
    );

    // cleanup stack memory
    ecc_memzero(seed, sizeof seed);
}

void ecc_opaque_ristretto255_sha512_DeriveAuthKeyPair(
    byte_t *private_key, byte_t *public_key,
    const byte_t *seed, const int seed_len
) {
    // Steps:
    // 1. private_key = HashToScalar(seed, dst="OPAQUE-HashToScalar")
    // 2. public_key = ScalarBaseMult(private_key)
    // 3. Output (private_key, public_key)

    byte_t dst[19] = "OPAQUE-HashToScalar";
    ecc_oprf_ristretto255_sha512_HashToScalarWithDST(
        private_key,
        seed, seed_len,
        dst, sizeof dst
    );
    ecc_ristretto255_scalarmult_base(public_key, private_key);
}

void ecc_opaque_ristretto255_sha512_BuildInnerEnvelope(
    byte_t *inner_env,
    byte_t *client_public_key,
    const byte_t *randomized_pwd,
    const byte_t *nonce, // 32
    const byte_t *client_private_key
) {
    // Steps:
    // 1. seed = Expand(randomized_pwd, concat(nonce, "PrivateKey"), Nsk)
    // 2. _, client_public_key = DeriveAuthKeyPair(seed)
    // 3. Output (nil, client_public_key)

    // 1. seed = Expand(randomized_pwd, concat(nonce, "PrivateKey"), Nsk)
    byte_t seed_label[10] = "PrivateKey";
    byte_t seed_info[Nn + 10];
    ecc_concat2(seed_info, nonce, Nn, seed_label, 10);
    byte_t seed[Nsk];
    ecc_kdf_hkdf_sha512_expand(seed, randomized_pwd, seed_info, sizeof seed_info, Nsk);

    // 2. _, client_public_key = DeriveAuthKeyPair(seed)
    byte_t ignore_key[Npk];
    ecc_opaque_ristretto255_sha512_DeriveAuthKeyPair(
        ignore_key, client_public_key,
        seed, Nsk
    );

    // cleanup stack memory
    ecc_memzero(seed_info, sizeof seed_info);
    ecc_memzero(seed, sizeof seed);
    ecc_memzero(ignore_key, sizeof ignore_key);
}

void ecc_opaque_ristretto255_sha512_RecoverKeys(
    byte_t *client_private_key,
    byte_t *client_public_key,
    const byte_t *randomized_pwd,
    const byte_t *nonce,
    const byte_t *inner_env
) {
    // Steps:
    // 1. seed = Expand(randomized_pwd, concat(nonce, "PrivateKey"), Nsk)
    // 2. client_private_key, client_public_key = DeriveAuthKeyPair(seed)
    // 4. Output (client_private_key, client_public_key)

    // 1. seed = Expand(randomized_pwd, concat(nonce, "PrivateKey"), Nsk)
    byte_t seed_label[10] = "PrivateKey";
    byte_t seed_info[Nn + 10];
    ecc_concat2(seed_info, nonce, Nn, seed_label, 10);
    byte_t seed[Nsk];
    ecc_kdf_hkdf_sha512_expand(seed, randomized_pwd, seed_info, sizeof seed_info, Nsk);

    // 2. client_private_key, client_public_key = DeriveAuthKeyPair(seed)
    ecc_opaque_ristretto255_sha512_DeriveAuthKeyPair(
        client_private_key, client_public_key,
        seed, Nsk
    );

    // cleanup stack memory
    ecc_memzero(seed_info, sizeof seed_info);
    ecc_memzero(seed, sizeof seed);
}

void ecc_opaque_ristretto255_sha512_CreateRegistrationRequestWithBlind(
    byte_t *request_raw,
    const byte_t *password, const int password_len,
    const byte_t *blind
) {
    // Steps:
    // 1. (blind, M) = Blind(password)
    // 2. Create RegistrationRequest request with M
    // 3. Output (request, blind)

    ecc_oprf_ristretto255_sha512_BlindWithScalar(
        request_raw,
        password, password_len,
        blind
    );
}

void ecc_opaque_ristretto255_sha512_CreateRegistrationRequest(
    byte_t *request_raw,
    byte_t *blind, // 32
    const byte_t *password, const int password_len
) {
    ecc_ristretto255_scalar_random(blind);
    ecc_opaque_ristretto255_sha512_CreateRegistrationRequestWithBlind(request_raw, password, password_len, blind);
}

void ecc_opaque_ristretto255_sha512_CreateRegistrationResponseWithOprfKey(
    byte_t *response_raw,
    const byte_t *request_raw,
    const byte_t *server_public_key,
    const byte_t *credential_identifier, int credential_identifier_len,
    const byte_t *oprf_key
) {
    // Steps:
    // 1. ---
    // 2. ---
    // 3. Z = Evaluate(oprf_key, request.data)
    // 4. Create RegistrationResponse response with (Z, server_public_key)
    // 5. Output (response, oprf_key)

    RegistrationRequest_t *request = (RegistrationRequest_t *) request_raw;
    RegistrationResponse_t *response = (RegistrationResponse_t *) response_raw;

    // 3. Z = Evaluate(oprf_key, request.data)
    byte_t *Z = response->data;
    ecc_oprf_ristretto255_sha512_Evaluate(Z, oprf_key, request->data);

    // 4. Create RegistrationResponse response with (Z, server_public_key)
    // 5. Output (response, oprf_key)
    memcpy(response->server_public_key, server_public_key, 32);
}

void ecc_opaque_ristretto255_sha512_CreateRegistrationResponse(
    byte_t *response_raw,
    byte_t *oprf_key,
    const byte_t *request_raw,
    const byte_t *server_public_key,
    const byte_t *credential_identifier, int credential_identifier_len,
    const byte_t *oprf_seed
) {
    // Steps:
    // 1. ikm = Expand(oprf_seed, concat(credential_identifier, "OprfKey"), Nok)
    // 2. (oprf_key, _) = DeriveKeyPair(ikm)
    // 3. Z = Evaluate(oprf_key, request.data)
    // 4. Create RegistrationResponse response with (Z, server_public_key)
    // 5. Output (response, oprf_key)

    // 1. ikm = Expand(oprf_seed, concat(credential_identifier, "OprfKey"), Nok)
    // - concat(credential_identifier, "OprfKey")
    byte_t oprf_key_label[7] = "OprfKey";
    byte_t ikm_info[256];
    const int ikm_info_len = credential_identifier_len + (int) sizeof oprf_key_label;
    ecc_concat2(
        ikm_info,
        credential_identifier, credential_identifier_len,
        oprf_key_label, sizeof oprf_key_label
    );
    // - Expand(oprf_seed, ikm_info, Nok)
    byte_t ikm[Nok];
    ecc_kdf_hkdf_sha512_expand(ikm, oprf_seed, ikm_info, ikm_info_len, Nok);

    // 2. (oprf_key, _) = DeriveKeyPair(ikm)
    byte_t oprf_private_key[32];
    ecc_oprf_ristretto255_sha512_HashToScalar(oprf_private_key, ikm, sizeof ikm, 0x00);
    ecc_ristretto255_scalarmult_base(oprf_key, oprf_private_key);

    // 3. Z = Evaluate(oprf_key, request.data)
    // 4. Create RegistrationResponse response with (Z, server_public_key)
    // 5. Output (response, oprf_key)
    ecc_opaque_ristretto255_sha512_CreateRegistrationResponseWithOprfKey(
        response_raw,
        request_raw,
        server_public_key,
        credential_identifier, credential_identifier_len,
        oprf_key
    );

    // cleanup stack memory
    ecc_memzero(ikm_info, sizeof ikm_info);
    ecc_memzero(ikm, sizeof ikm);
    ecc_memzero(oprf_private_key, sizeof oprf_private_key);
}

void ecc_opaque_ristretto255_sha512_FinalizeRequest(
    byte_t *record_raw, // RegistrationUpload_t
    byte_t *export_key, // 64
    const byte_t *client_private_key,
    const byte_t *password, const int password_len,
    const byte_t *blind,
    const byte_t *response_raw, // RegistrationResponse_t
    const byte_t *server_identity, const int server_identity_len,
    const byte_t *client_identity, const int client_identity_len
) {
    // Steps:
    // 1. y = Finalize(password, blind, response.data)
    // 2. randomized_pwd = Extract("", Harden(y, params))
    // 3. (envelope, client_public_key, masking_key, export_key) =
    //     CreateEnvelope(randomized_pwd, response.server_public_key, client_private_key,
    //                    server_identity, client_identity)
    // 4. Create RegistrationUpload record with (client_public_key, masking_key, envelope)
    // 5. Output (record, export_key)

    RegistrationResponse_t *response = (RegistrationResponse_t *) response_raw;
    RegistrationUpload_t *record = (RegistrationUpload_t *) record_raw;

    // 1. y = Finalize(password, blind, response.data)
    byte_t y[64];
    ecc_oprf_ristretto255_sha512_Finalize(
        y,
        password, password_len,
        blind,
        response->data,
        0x00
    );

    // 2. randomized_pwd = Extract("", Harden(y, params))
    byte_t randomized_pwd[64];
    // TODO: harden
    ecc_kdf_hkdf_sha512_extract(randomized_pwd, NULL, 0, y, sizeof y);

    // 3. (envelope, client_public_key, masking_key, export_key) =
    //     CreateEnvelope(randomized_pwd, response.server_public_key, client_private_key,
    //                    server_identity, client_identity)
    byte_t client_public_key[32];
    byte_t masking_key[64];
    ecc_opaque_ristretto255_sha512_CreateEnvelope(
        (byte_t *) &record->envelope,
        client_public_key,
        masking_key,
        export_key,
        randomized_pwd,
        response->server_public_key,
        client_private_key,
        server_identity, server_identity_len,
        client_identity, client_identity_len
    );

    // 4. Create RegistrationUpload record with (client_public_key, masking_key, envelope)
    // 5. Output (record, export_key)

    memcpy(record->client_public_key, client_public_key, 32);
    memcpy(record->masking_key, masking_key, 64);

    // cleanup stack memory
    ecc_memzero(y, sizeof y);
    ecc_memzero(randomized_pwd, sizeof randomized_pwd);
    ecc_memzero(client_public_key, sizeof client_public_key);
    ecc_memzero(masking_key, sizeof masking_key);
}

void ecc_opaque_ristretto255_sha512_CreateCredentialRequest(
    byte_t *request_raw,
    byte_t *blind,
    const byte_t *password, int password_len
) {
    // Steps:
    // 1. (blind, M) = Blind(password)
    // 2. Create CredentialRequest request with M
    // 3. Output (request, blind)

    CredentialRequest_t *request = (CredentialRequest_t *) request_raw;
    ecc_oprf_ristretto255_sha512_Blind(request->data, blind, password, password_len);
}

void ecc_opaque_ristretto255_sha512_CreateCredentialResponse(
    byte_t *response_raw,
    const byte_t *request_raw,
    const byte_t *server_public_key,
    const byte_t *record_raw,
    const byte_t *credential_identifier, const int credential_identifier_len,
    const byte_t *oprf_seed
) {
    // Steps:
    // 1. ikm = Expand(oprf_seed, concat(credential_identifier, "OprfKey"), Nok)
    // 2. (oprf_key, _) = DeriveKeyPair(ikm)
    // 3. Z = Evaluate(oprf_key, request.data)
    // 4. masking_nonce = random(Nn)
    // 5. credential_response_pad = Expand(record.masking_key,
    //      concat(masking_nonce, "CredentialResponsePad"), Npk + Ne)
    // 6. masked_response = xor(credential_response_pad,
    //                          concat(server_public_key, record.envelope))
    // 7. Create CredentialResponse response with (Z, masking_nonce, masked_response)
    // 8. Output response

    CredentialRequest_t *request = (CredentialRequest_t *) request_raw;
    RegistrationUpload_t *record = (RegistrationUpload_t *) record_raw;

    // 1. ikm = Expand(oprf_seed, concat(credential_identifier, "OprfKey"), Nok)
    // - concat(credential_identifier, "OprfKey")
    const int ikm_info_len = credential_identifier_len + 7;
    byte_t ikm_info[256];
    byte_t oprf_key_label[7] = "OprfKey";
    ecc_concat2(ikm_info, credential_identifier, credential_identifier_len, oprf_key_label, 7);
    // - Expand(oprf_seed, ikm_info, Nok)
    byte_t ikm[Nok];
    ecc_kdf_hkdf_sha512_expand(ikm, oprf_seed, ikm_info, ikm_info_len, Nok);

    // 2. (oprf_key, _) = DeriveKeyPair(ikm)
    byte_t oprf_private_key[32];
    byte_t oprf_key[32];
    ecc_oprf_ristretto255_sha512_HashToScalar(oprf_private_key, ikm, sizeof ikm, 0x00);
    ecc_ristretto255_scalarmult_base(oprf_key, oprf_private_key);

    // 3. Z = Evaluate(oprf_key, request.data)
    byte_t Z[32];
    ecc_oprf_ristretto255_sha512_Evaluate(Z, oprf_key, request->data);

    // 4. masking_nonce = random(Nn)
    byte_t masking_nonce[Nn];
    ecc_randombytes(masking_nonce, Nn);

    // 5. credential_response_pad = Expand(record.masking_key,
    //      concat(masking_nonce, "CredentialResponsePad"), Npk + Ne)
    byte_t credential_response_pad_label[21] = "CredentialResponsePad";
    byte_t credential_response_pad_info[Nn + 21];
    ecc_concat2(credential_response_pad_info, masking_nonce, Nn, credential_response_pad_label, 21);
    byte_t credential_response_pad[Npk + Ne];
    ecc_kdf_hkdf_sha512_expand(credential_response_pad, record->masking_key, credential_response_pad_info, sizeof credential_response_pad_info, Npk + Ne);

    // 6. masked_response = xor(credential_response_pad,
    //                          concat(server_public_key, record.envelope))
    byte_t masked_response_xor[Npk + Ne];
    ecc_concat2(masked_response_xor, server_public_key, Npk, (byte_t *) &record->envelope, Ne);
    byte_t masked_response[Npk + Ne];
    ecc_strxor(masked_response, credential_response_pad, masked_response_xor, Npk + Ne);

    // 7. Create CredentialResponse response with (Z, masking_nonce, masked_response)
    // 8. Output response
    CredentialResponse_t *response = (CredentialResponse_t *) response_raw;
    memcpy(response->data, Z, sizeof Z);
    memcpy(response->masking_nonce, masking_nonce, sizeof masking_nonce);
    memcpy(response->masked_response, masked_response, sizeof masked_response);

    // cleanup stack memory
    ecc_memzero(ikm_info, sizeof ikm_info);
    ecc_memzero(ikm, sizeof ikm);
    ecc_memzero(oprf_private_key, sizeof oprf_private_key);
    ecc_memzero(oprf_key, sizeof oprf_key);
    ecc_memzero(Z, sizeof Z);
    ecc_memzero(masking_nonce, sizeof masking_nonce);
    ecc_memzero(credential_response_pad_info, sizeof credential_response_pad_info);
    ecc_memzero(credential_response_pad, sizeof credential_response_pad);
    ecc_memzero(masked_response_xor, sizeof masked_response_xor);
    ecc_memzero(masked_response, sizeof masked_response);
}

int ecc_opaque_ristretto255_sha512_RecoverCredentials(
    byte_t *client_private_key,
    byte_t *server_public_key,
    byte_t *export_key, // 64
    const byte_t *password, int password_len,
    const byte_t *blind,
    const byte_t *response,
    const byte_t *server_identity, int server_identity_len,
    const byte_t *client_identity, int client_identity_len
) {
    // Steps:
    // 1. y = Finalize(password, blind, response.data)
    // 2. randomized_pwd = Extract("", Harden(y, params))
    // 3. masking_key = Expand(randomized_pwd, "MaskingKey", Nh)
    // 4. credential_response_pad = Expand(masking_key,
    //      concat(response.masking_nonce, "CredentialResponsePad"), Npk + Ne)
    // 5. concat(server_public_key, envelope) = xor(credential_response_pad,
    //                                               response.masked_response)
    // 6. (client_private_key, export_key) =
    //     RecoverEnvelope(randomized_pwd, server_public_key, envelope,
    //                     server_identity, client_identity)
    // 7. Output (client_private_key, response.server_public_key, export_key)

    // 1. y = Finalize(password, blind, response.data)
    CredentialResponse_t *res = (CredentialResponse_t *) response;
    byte_t y[64];
    ecc_oprf_ristretto255_sha512_Finalize(
        y,
        password, password_len,
        blind,
        res->data,
        0x00
    );

    // 2. randomized_pwd = Extract("", Harden(y, params))
    byte_t randomized_pwd[64];
    // TODO: harden
    ecc_kdf_hkdf_sha512_extract(randomized_pwd, NULL, 0, y, sizeof y);

    // 3. masking_key = Expand(randomized_pwd, "MaskingKey", Nh)
    byte_t masking_key_info[10] = "MaskingKey";
    byte_t masking_key[Nh];
    ecc_kdf_hkdf_sha512_expand(masking_key, randomized_pwd, masking_key_info, sizeof masking_key_info, Nh);

    // 4. credential_response_pad = Expand(masking_key,
    //      concat(response.masking_nonce, "CredentialResponsePad"), Npk + Ne)
    byte_t credential_response_pad_label[21] = "CredentialResponsePad";
    byte_t credential_response_pad_info[Nn + 21];
    ecc_concat2(credential_response_pad_info, res->masking_nonce, Nn, credential_response_pad_label, 21);
    byte_t credential_response_pad[Npk + Ne];
    ecc_kdf_hkdf_sha512_expand(credential_response_pad, masking_key, credential_response_pad_info, sizeof credential_response_pad_info, Npk + Ne);

    // 5. concat(server_public_key, envelope) = xor(credential_response_pad,
    //                                               response.masked_response)
    byte_t xor_result[Npk + Ne];
    ecc_strxor(xor_result, credential_response_pad, res->masked_response, Npk + Ne);
    memcpy(server_public_key, xor_result, Npk);
    byte_t envelope[Ne];
    memcpy(envelope, &xor_result[Npk], Ne);

    // 6. (client_private_key, export_key) =
    //     RecoverEnvelope(randomized_pwd, server_public_key, envelope,
    //                     server_identity, client_identity)
    const int ret = ecc_opaque_ristretto255_sha512_RecoverEnvelope(
        client_private_key,
        export_key,
        randomized_pwd,
        server_public_key,
        envelope,
        server_identity, server_identity_len,
        client_identity, client_identity_len
    );

    // cleanup stack memory
    ecc_memzero(y, sizeof y);
    ecc_memzero(randomized_pwd, sizeof randomized_pwd);
    ecc_memzero(masking_key, sizeof masking_key);
    ecc_memzero(credential_response_pad_info, sizeof credential_response_pad_info);
    ecc_memzero(credential_response_pad, sizeof credential_response_pad);
    ecc_memzero(xor_result, sizeof xor_result);
    ecc_memzero(envelope, sizeof envelope);

    // 7. Output (client_private_key, response.server_public_key, export_key)
    return ret;
}

void ecc_opaque_ristretto255_sha512_3DH_Expand_Label(
    byte_t *out, // 64
    const byte_t *secret,
    const byte_t *label, const int label_len,
    const byte_t *context, const int context_len,
    int length
) {
    // Expand-Label(Secret, Label, Context, Length) =
    //     Expand(Secret, CustomLabel, Length)
    //
    // struct {
    //   uint16 length = Length;
    //   opaque label<8..255> = "OPAQUE-" + Label;
    //   uint8 context<0..255> = Context;
    // } CustomLabel;

    unsigned short slength = (unsigned short) length;
    byte_t opaque_prefix[7] = "OPAQUE-";

    const int info_len = 2 + 7 + label_len + context_len;
    byte_t info[512];
    ecc_concat4(
        info,
        (byte_t *) &slength, 2,
        opaque_prefix, sizeof opaque_prefix,
        label, label_len,
        context, context_len
    );
    ecc_kdf_hkdf_sha512_expand(out, secret, info, info_len, length);

    // cleanup stack memory
    ecc_memzero(info, sizeof info);
}

void ecc_opaque_ristretto255_sha512_3DH_Derive_Secret(
    byte_t *out, // 64
    const byte_t *secret,
    const byte_t *label, int label_len,
    const byte_t *transcript_hash, int transcript_hash_len
) {
    ecc_opaque_ristretto255_sha512_3DH_Expand_Label(
        out,
        secret,
        label, label_len,
        transcript_hash, transcript_hash_len,
        Nx
    );
}

int ecc_opaque_ristretto255_sha512_3DH_Preamble(
    byte_t *preamble,
    const byte_t *context, const int context_len,
    const byte_t *client_identity, const int client_identity_len,
    const byte_t *ke1, const int ke1_len,
    const byte_t *server_identity, const int server_identity_len,
    const byte_t *inner_ke2, const int inner_ke2_len
) {
    // Steps:
    // 1. preamble = concat("RFCXXXX",
    //                      I2OSP(len(context), 2), context,
    //                      I2OSP(len(client_identity), 2), client_identity,
    //                      ke1,
    //                      I2OSP(len(server_identity), 2), server_identity,
    //                      inner_ke2)
    // 2. Output preamble

    byte_t preamble_label[7] = "RFCXXXX"; // TODO: replace X with actual value

    byte_t *p = preamble;
    int n = 0;

    ecc_concat2(p + n, preamble_label, sizeof preamble_label, NULL, 0);
    n += sizeof preamble_label;
    ecc_I2OSP(p + n, context_len, 2);
    n += 2;
    ecc_concat2(p + n, context, context_len, NULL, 0);
    n += context_len;
    ecc_I2OSP(p + n, client_identity_len, 2);
    n += 2;
    ecc_concat2(p + n, client_identity, client_identity_len, NULL, 0);
    n += client_identity_len;
    ecc_concat2(p + n, ke1, ke1_len, NULL, 0);
    n += ke1_len;
    ecc_I2OSP(p + n, server_identity_len, 2);
    n += 2;
    ecc_concat2(p + n, server_identity, server_identity_len, NULL, 0);
    n += server_identity_len;
    ecc_concat2(p + n, inner_ke2, inner_ke2_len, NULL, 0);
    n += inner_ke2_len;

    return n;
}

void ecc_opaque_ristretto255_sha512_3DH_TripleDHIKM(
    byte_t *ikm, // 96
    const byte_t *sk1, const byte_t *pk1,
    const byte_t *sk2, const byte_t *pk2,
    const byte_t *sk3, const byte_t *pk3
) {
    // Steps:
    // 1. dh1 = sk1 * pk1
    // 2. dh2 = sk2 * pk2
    // 3. dh3 = sk3 * pk3
    // 4. Output concat(dh1, dh2, dh3)

    byte_t dh1[32];
    ecc_ristretto255_scalarmult(dh1, sk1, pk1);
    byte_t dh2[32];
    ecc_ristretto255_scalarmult(dh2, sk2, pk2);
    byte_t dh3[32];
    ecc_ristretto255_scalarmult(dh3, sk3, pk3);

    ecc_concat3(
        ikm,
        dh1, 32,
        dh2, 32,
        dh3, 32
    );

    // cleanup stack memory
    ecc_memzero(dh1, sizeof dh1);
    ecc_memzero(dh2, sizeof dh2);
    ecc_memzero(dh3, sizeof dh3);
}

void ecc_opaque_ristretto255_sha512_3DH_DeriveKeys(
    byte_t *km2, // 64
    byte_t *km3, // 64
    byte_t *session_key, // 64
    const byte_t *ikm, const int ikm_len,
    const byte_t *preamble, const int preamble_len
) {
    // Steps:
    // 1. prk = Extract("", ikm)
    // 2. handshake_secret = Derive-Secret(prk, "HandshakeSecret", Hash(preamble))
    // 3. session_key = Derive-Secret(prk, "SessionKey", Hash(preamble))
    // 4. Km2 = Derive-Secret(handshake_secret, "ServerMAC", "")
    // 5. Km3 = Derive-Secret(handshake_secret, "ClientMAC", "")
    // 6. Output (Km2, Km3, session_key)

    // 1. prk = Extract("", ikm)
    byte_t prk[64];
    ecc_kdf_hkdf_sha512_extract(prk, NULL, 0, ikm, ikm_len);

    // 2. handshake_secret = Derive-Secret(prk, "HandshakeSecret", Hash(preamble))
    byte_t preamble_secret_label[15] = "HandshakeSecret";
    byte_t preamble_hash[64];
    ecc_hash_sha512(preamble_hash, preamble, preamble_len);
    byte_t handshake_secret[64];
    ecc_opaque_ristretto255_sha512_3DH_Derive_Secret(
        handshake_secret,
        prk,
        preamble_secret_label, sizeof preamble_secret_label,
        preamble_hash, sizeof preamble_hash
    );

    // 3. session_key = Derive-Secret(prk, "SessionKey", Hash(preamble))
    byte_t session_key_label[10] = "SessionKey";
    ecc_opaque_ristretto255_sha512_3DH_Derive_Secret(
        session_key,
        prk,
        session_key_label, sizeof session_key_label,
        preamble_hash, sizeof preamble_hash
    );

    // 4. Km2 = Derive-Secret(handshake_secret, "ServerMAC", "")
    byte_t km2_label[9] = "ServerMAC";
    ecc_opaque_ristretto255_sha512_3DH_Derive_Secret(
        km2,
        handshake_secret,
        km2_label, sizeof km2_label,
        NULL, 0
    );

    // 5. Km3 = Derive-Secret(handshake_secret, "ClientMAC", "")
    byte_t km3_label[9] = "ClientMAC";
    ecc_opaque_ristretto255_sha512_3DH_Derive_Secret(
        km3,
        handshake_secret,
        km3_label, sizeof km3_label,
        NULL, 0
    );

    // cleanup stack memory
    ecc_memzero(prk, sizeof prk);
    ecc_memzero(preamble_hash, sizeof preamble_hash);
    ecc_memzero(handshake_secret, sizeof handshake_secret);
}

void ecc_opaque_ristretto255_sha512_3DH_ClientInit(
    byte_t *ke1_raw,
    const byte_t *state_raw,
    const byte_t *client_identity, int client_identity_len,
    const byte_t *password, int password_len
) {
    // Steps:
    // 1. request, blind = CreateCredentialRequest(password)
    // 2. state.blind = blind
    // 3. ke1 = Start(request)
    // 4. Output ke1

    ClientState_t *state = (ClientState_t *) state_raw;

    // 1. request, blind = CreateCredentialRequest(password)
    // 2. state.blind = blind
    CredentialRequest_t request;
    ecc_opaque_ristretto255_sha512_CreateCredentialRequest(
        (byte_t *) &request,
        state->blind,
        password, password_len
    );

    // 3. ke1 = Start(request)
    // 4. Output ke1
    ecc_opaque_ristretto255_sha512_3DH_Start(
        ke1_raw, state_raw, (byte_t *) &request
    );
}

int ecc_opaque_ristretto255_sha512_3DH_ClientFinish(
    byte_t *ke3_raw,
    byte_t *session_key,
    byte_t *export_key, // 64
    const byte_t *state_raw,
    const byte_t *password, int password_len,
    const byte_t *client_identity, int client_identity_len,
    const byte_t *server_identity, int server_identity_len,
    const byte_t *ke2_raw
) {
    // Steps:
    // 1. (client_private_key, server_public_key, export_key) =
    //     RecoverCredentials(password, state.blind, ke2.CredentialResponse,
    //                        server_identity, client_identity)
    // 2. (ke3, session_key) =
    //     ClientFinalize(client_identity, client_private_key, server_identity,
    //                     server_public_key, ke1, ke2)
    // 3. Output (ke3, session_key)

    ClientState_t *state = (ClientState_t *) state_raw;
    KE2_t *ke2 = (KE2_t *) ke2_raw;

    // 1. (client_private_key, server_public_key, export_key) =
    //     RecoverCredentials(password, state.blind, ke2.CredentialResponse,
    //                        server_identity, client_identity)
    byte_t client_private_key[32];
    byte_t server_public_key[32];
    const int recover_ret = ecc_opaque_ristretto255_sha512_RecoverCredentials(
        client_private_key,
        server_public_key,
        export_key,
        password, password_len,
        state->blind,
        (byte_t *) &ke2->inner_ke2.response,
        server_identity, server_identity_len,
        client_identity, client_identity_len
    );

    // 2. (ke3, session_key) =
    //     ClientFinalize(client_identity, client_private_key, server_identity,
    //                     server_public_key, ke1, ke2)
    const int finalize_ret = ecc_opaque_ristretto255_sha512_3DH_ClientFinalize(
        ke3_raw,
        session_key,
        state_raw,
        client_identity, client_identity_len,
        client_private_key,
        server_identity, server_identity_len,
        server_public_key,
        ke2_raw,
        NULL, 0
    );

    // cleanup stack memory
    ecc_memzero(client_private_key, sizeof client_private_key);
    ecc_memzero(server_public_key, sizeof server_public_key);

    // 3. Output (ke3, session_key)
    if (recover_ret == 0 && finalize_ret == 0)
        return 0;
    else
        return -1;
}

void ecc_opaque_ristretto255_sha512_3DH_Start(
    byte_t *ke1_raw,
    const byte_t *state_raw,
    const byte_t *credential_request
) {
    // Steps:
    // 1. client_nonce = random(Nn)
    // 2. client_secret, client_keyshare = GenerateAuthKeyPair()
    // 3. Create KE1 ke1 with (credential_request, client_nonce, client_keyshare)
    // 4. state.client_secret = client_secret
    // 5. Output (ke1, client_secret)

    ClientState_t *state = (ClientState_t *) state_raw;

    // 1. client_nonce = random(Nn)
    byte_t client_nonce[Nn];
    ecc_randombytes(client_nonce, Nn);

    // 2. client_secret, client_keyshare = GenerateAuthKeyPair()
    byte_t client_secret[32];
    byte_t client_keyshare[32];
    ecc_opaque_ristretto255_sha512_GenerateAuthKeyPair(client_secret, client_keyshare);

    // 3. Create KE1 ke1 with (credential_request, client_nonce, client_keyshare)
    KE1_t *ke1 = (KE1_t *) ke1_raw;
    memcpy(ke1->request.data, credential_request, 32);
    memcpy(ke1->client_nonce, client_nonce, 32);
    memcpy(ke1->client_keyshare, client_keyshare, 32);

    // 4. state.client_secret = client_secret
    // 5. Output (ke1, client_secret)
    memcpy(state->client_secret, client_secret, 32);
    // save KE1 in the client state
    memcpy(&state->ke1, ke1, sizeof(KE1_t));

    // cleanup stack memory
    ecc_memzero(client_nonce, sizeof client_nonce);
    ecc_memzero(client_secret, sizeof client_secret);
    ecc_memzero(client_keyshare, sizeof client_keyshare);
}

int ecc_opaque_ristretto255_sha512_3DH_ClientFinalize(
    byte_t *ke3_raw, // 64
    byte_t *session_key,
    const byte_t *state_raw,
    const byte_t *client_identity, int client_identity_len,
    const byte_t *client_private_key,
    const byte_t *server_identity, int server_identity_len,
    const byte_t *server_public_key,
    const byte_t *ke2_raw,
    const byte_t *context, int context_len
) {
    // Steps:
    // 1. ikm = TripleDHIKM(state.client_secret, ke2.server_keyshare,
    //     state.client_secret, server_public_key, client_private_key, ke2.server_keyshare)
    // 2. preamble = Preamble(client_identity, state.ke1, server_identity, ke2.inner_ke2)
    // 3. Km2, Km3, session_key = DeriveKeys(ikm, preamble)
    // 4. expected_server_mac = MAC(Km2, Hash(preamble))
    // 5. If !ct_equal(ke2.server_mac, expected_server_mac),
    //      raise HandshakeError
    // 6. client_mac = MAC(Km3, Hash(concat(preamble, expected_server_mac))
    // 7. Create KE3 ke3 with client_mac
    // 8. Output (ke3, session_key)

    ClientState_t *state = (ClientState_t *) state_raw;
    KE2_t *ke2 = (KE2_t *) ke2_raw;

    // 1. ikm = TripleDHIKM(state.client_secret, ke2.server_keyshare,
    //     state.client_secret, server_public_key, client_private_key, ke2.server_keyshare)
    byte_t ikm[96];
    ecc_opaque_ristretto255_sha512_3DH_TripleDHIKM(
        ikm,
        state->client_secret, ke2->inner_ke2.server_keyshare,
        state->client_secret, server_public_key,
        client_private_key, ke2->inner_ke2.server_keyshare
    );

    // 2. preamble = Preamble(client_identity, state.ke1, server_identity, ke2.inner_ke2)
    byte_t preamble[512];
    int preamble_len = ecc_opaque_ristretto255_sha512_3DH_Preamble(
        preamble,
        context, context_len,
        client_identity, client_identity_len,
        (byte_t *) &state->ke1, sizeof(KE1_t),
        server_identity, server_identity_len,
        (byte_t *) &ke2->inner_ke2, sizeof(KE2_t) - Nm
    );

    // 3. Km2, Km3, session_key = DeriveKeys(ikm, preamble)
    byte_t km2[64];
    byte_t km3[64];
    ecc_opaque_ristretto255_sha512_3DH_DeriveKeys(
        km2, km3,
        session_key,
        ikm, sizeof ikm,
        preamble, preamble_len
    );

    // 4. expected_server_mac = MAC(Km2, Hash(preamble))
    byte_t preamble_hash[64];
    ecc_hash_sha512(preamble_hash, preamble, preamble_len);
    byte_t expected_server_mac[64];
    ecc_mac_hmac_sha512(
        expected_server_mac,
        preamble_hash, sizeof preamble_hash,
        km2
    );

    // 5. If !ct_equal(ke2.server_mac, expected_server_mac),
    //      raise HandshakeError
    if (ecc_compare(ke2->server_mac, expected_server_mac, 64)) {
        // cleanup stack memory
        ecc_memzero(ikm, sizeof ikm);
        ecc_memzero(preamble, sizeof preamble);
        ecc_memzero(km2, sizeof km2);
        ecc_memzero(km3, sizeof km3);
        ecc_memzero(preamble_hash, sizeof preamble_hash);
        ecc_memzero(expected_server_mac, sizeof expected_server_mac);
        return -1;
    }

    // 6. client_mac = MAC(Km3, Hash(concat(preamble, expected_server_mac))
    byte_t client_mac_input[64];
    crypto_hash_sha512_state hst;
    crypto_hash_sha512_init(&hst);
    crypto_hash_sha512_update(&hst, preamble, preamble_len);
    crypto_hash_sha512_update(&hst, expected_server_mac, sizeof expected_server_mac);
    crypto_hash_sha512_final(&hst, client_mac_input);
    byte_t client_mac[64];
    ecc_mac_hmac_sha512(
        client_mac,
        client_mac_input, sizeof client_mac_input,
        km3
    );

    // 7. Create KE3 ke3 with client_mac
    // 8. Output (ke3, session_key)
    memcpy(ke3_raw, client_mac, sizeof client_mac);

    // cleanup stack memory
    ecc_memzero(ikm, sizeof ikm);
    ecc_memzero(preamble, sizeof preamble);
    ecc_memzero(km2, sizeof km2);
    ecc_memzero(km3, sizeof km3);
    ecc_memzero(preamble_hash, sizeof preamble_hash);
    ecc_memzero(expected_server_mac, sizeof expected_server_mac);
    ecc_memzero(client_mac_input, sizeof client_mac_input);
    ecc_memzero(client_mac, sizeof client_mac);

    return 0;
}

void ecc_opaque_ristretto255_sha512_3DH_ServerInit(
    byte_t *ke2_raw,
    const byte_t *state_raw,
    const byte_t *server_identity, int server_identity_len,
    const byte_t *server_private_key,
    const byte_t *server_public_key,
    const byte_t *record_raw,
    const byte_t *credential_identifier, int credential_identifier_len,
    const byte_t *oprf_seed,
    const byte_t *ke1_raw,
    const byte_t *context, int context_len
) {
    // Steps:
    // 1. response = CreateCredentialResponse(ke1.request, server_public_key, record,
    //     credential_identifier, oprf_seed)
    // 2. ke2 = Response(server_identity, server_private_key,
    //     client_identity, record.client_public_key, ke1, response)
    // 3. Output ke2

    KE1_t *ke1 = (KE1_t *) ke1_raw;
    RegistrationUpload_t *record = (RegistrationUpload_t *) record_raw;

    CredentialResponse_t response;
    ecc_opaque_ristretto255_sha512_CreateCredentialResponse(
        (byte_t *) &response,
        (byte_t *) &ke1->request,
        server_public_key,
        record_raw,
        credential_identifier, credential_identifier_len,
        oprf_seed
    );

    ecc_opaque_ristretto255_sha512_3DH_Response(
        ke2_raw,
        state_raw,
        server_identity, server_identity_len,
        server_private_key,
        NULL, 0,
        record->client_public_key,
        ke1_raw,
        (byte_t *) &response,
        context, context_len
    );
}

int ecc_opaque_ristretto255_sha512_3DH_ServerFinish(
    byte_t *session_key,
    const byte_t *state_raw,
    const byte_t *ke3_raw
) {
    // Steps:
    // 1. if !ct_equal(ke3.client_mac, state.expected_client_mac):
    // 2.    raise HandshakeError
    // 3. Output state.session_key

    ServerState_t *state = (ServerState_t *) state_raw;
    KE3_t *ke3 = (KE3_t *) ke3_raw;

    if (ecc_compare(ke3->client_mac, state->expected_client_mac, 64))
        return -1;

    memcpy(session_key, state->session_key, 64);

    return 0;
}

void ecc_opaque_ristretto255_sha512_3DH_Response(
    byte_t *ke2_raw,
    const byte_t *state_raw,
    const byte_t *server_identity, int server_identity_len,
    const byte_t *server_private_key,
    const byte_t *client_identity, int client_identity_len,
    const byte_t *client_public_key,
    const byte_t *ke1_raw,
    const byte_t *credential_response_raw,
    const byte_t *context, int context_len
) {
    // Steps:
    // 1. server_nonce = random(Nn)
    // 2. server_secret, server_keyshare = GenerateAuthKeyPair()
    // 3. Create inner_ke2 ike2 with (credential_response, server_nonce, server_keyshare)
    // 4. preamble = Preamble(client_identity, ke1, server_identity, ike2)
    // 5. ikm = TripleDHIKM(server_secret, ke1.client_keyshare, server_private_key, ke1.client_keyshare, server_secret, client_public_key)
    // 6. Km2, Km3, session_key = DeriveKeys(ikm, preamble)
    // 7. server_mac = MAC(Km2, Hash(preamble))
    // 8. expected_client_mac = MAC(Km3, Hash(concat(preamble, server_mac))
    // 9. Populate state with ServerState(expected_client_mac, session_key)
    // 10. Create KE2 ke2 with (ike2, server_mac)
    // 11. Output ke2

    // 1. server_nonce = random(Nn)
    byte_t server_nonce[Nn];
    ecc_randombytes(server_nonce, Nn);

    // 2. server_secret, server_keyshare = GenerateAuthKeyPair()
    byte_t server_secret[32];
    byte_t server_keyshare[32];
    ecc_opaque_ristretto255_sha512_GenerateAuthKeyPair(server_secret, server_keyshare);

    // 3. Create inner_ke2 ike2 with (credential_response, server_nonce, server_keyshare)
    KE2_t *ke2 = (KE2_t *) ke2_raw;
    memcpy(&ke2->inner_ke2.response, credential_response_raw, sizeof(CredentialResponse_t));
    memcpy(ke2->inner_ke2.server_nonce, server_nonce, 32);
    memcpy(ke2->inner_ke2.server_keyshare, server_keyshare, 32);

    // 4. preamble = Preamble(client_identity, ke1, server_identity, ike2)
    byte_t preamble[512];
    int preamble_len = ecc_opaque_ristretto255_sha512_3DH_Preamble(
        preamble,
        context, context_len,
        client_identity, client_identity_len,
        ke1_raw, sizeof(KE1_t),
        server_identity, server_identity_len,
        (byte_t *) &ke2->inner_ke2, sizeof(KE2_t) - Nm
    );

    // 5. ikm = TripleDHIKM(server_secret, ke1.client_keyshare, server_private_key, ke1.client_keyshare, server_secret, client_public_key)
    KE1_t *ke1 = (KE1_t *) ke1_raw;
    byte_t ikm[96];
    ecc_opaque_ristretto255_sha512_3DH_TripleDHIKM(
        ikm,
        server_secret, ke1->client_keyshare,
        server_private_key, ke1->client_keyshare,
        server_secret, client_public_key
    );

    // 6. Km2, Km3, session_key = DeriveKeys(ikm, preamble)
    byte_t km2[64];
    byte_t km3[64];
    byte_t session_key[64];
    ecc_opaque_ristretto255_sha512_3DH_DeriveKeys(
        km2, km3,
        session_key,
        ikm, sizeof ikm,
        preamble, preamble_len
    );

    // 7. server_mac = MAC(Km2, Hash(preamble))
    byte_t preamble_hash[64];
    ecc_hash_sha512(preamble_hash, preamble, preamble_len);
    byte_t server_mac[64];
    ecc_mac_hmac_sha512(
        server_mac,
        preamble_hash, sizeof preamble_hash,
        km2
    );

    // 8. expected_client_mac = MAC(Km3, Hash(concat(preamble, server_mac))
    byte_t expected_client_mac_input[64];
    crypto_hash_sha512_state hst;
    crypto_hash_sha512_init(&hst);
    crypto_hash_sha512_update(&hst, preamble, preamble_len);
    crypto_hash_sha512_update(&hst, server_mac, sizeof server_mac);
    crypto_hash_sha512_final(&hst, expected_client_mac_input);
    byte_t expected_client_mac[64];
    ecc_mac_hmac_sha512(
        expected_client_mac,
        expected_client_mac_input, sizeof expected_client_mac_input,
        km3
    );

    // 9. Populate state with ServerState(expected_client_mac, session_key)
    ServerState_t *state = (ServerState_t *) state_raw;
    memcpy(state->expected_client_mac, expected_client_mac, sizeof expected_client_mac);
    memcpy(state->session_key, session_key, sizeof session_key);

    // 10. Create KE2 ke2 with (ike2, server_mac)
    // 11. Output ke2
    memcpy(ke2->server_mac, server_mac, sizeof server_mac);

    // cleanup stack memory
    ecc_memzero(server_nonce, sizeof server_nonce);
    ecc_memzero(server_secret, sizeof server_secret);
    ecc_memzero(server_keyshare, sizeof server_keyshare);
    ecc_memzero(preamble, sizeof preamble);
    ecc_memzero(ikm, sizeof ikm);
    ecc_memzero(km2, sizeof km2);
    ecc_memzero(km3, sizeof km3);
    ecc_memzero(session_key, sizeof session_key);
    ecc_memzero(preamble_hash, sizeof preamble_hash);
    ecc_memzero(server_mac, sizeof server_mac);
    ecc_memzero(expected_client_mac_input, sizeof expected_client_mac_input);
    ecc_memzero(expected_client_mac, sizeof expected_client_mac);
}
