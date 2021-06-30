/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#include "opaque.h"
#include <string.h>
#include "util.h"
#include "kdf.h"
#include "h2c.h"
#include "ristretto255.h"
#include "oprf.h"

typedef struct {
    byte_t nonce[ecc_opaque_ristretto255_sha512_Nn];
    byte_t auth_tag[ecc_opaque_ristretto255_sha512_Nm];
    byte_t inner_env[ecc_opaque_ristretto255_sha512_Nsk];
} Envelope_t;

typedef struct {
    byte_t data[ecc_opaque_ristretto255_sha512_Noe];
} RegistrationRequest_t;

typedef struct {
    byte_t data[ecc_opaque_ristretto255_sha512_Noe];
    byte_t server_public_key[ecc_opaque_ristretto255_sha512_Npk];
} RegistrationResponse_t;

typedef struct {
    byte_t client_public_key[ecc_opaque_ristretto255_sha512_Npk];
    byte_t masking_key[ecc_opaque_ristretto255_sha512_Nh];
    Envelope_t envelope;
} RegistrationUpload_t;

void ecc_opaque_ristretto255_sha512_CreateRegistrationRequestWithBlind(
    byte_t *request,
    const byte_t *password, const int password_len,
    const byte_t *blind
) {
    // Steps:
    // 1. (blind, M) = Blind(password)
    // 2. Create RegistrationRequest request with M
    // 3. Output (request, blind)

    // no need to use RegistrationRequest_t and memcpy
    ecc_oprf_ristretto255_sha512_BlindWithScalar(request, password, password_len, blind);
}

void ecc_opaque_ristretto255_sha512_CreateRegistrationRequest(
    byte_t *request, byte_t *blind,
    const byte_t *password, const int password_len
) {
    ecc_ristretto255_scalar_random(blind);
    ecc_opaque_ristretto255_sha512_CreateRegistrationRequestWithBlind(request, password, password_len, blind);
}

void ecc_opaque_ristretto255_sha512_CreateRegistrationResponseWithOprfKey(
    byte_t *response,
    const byte_t *request,
    const byte_t *server_public_key,
    const byte_t *credential_identifier, int credential_identifier_len,
    const byte_t *oprf_key
) {
    RegistrationResponse_t res;

    // Steps:
    // 1. ---
    // 2. ---
    // 3. Z = Evaluate(oprf_key, request.data)
    // 4. Create RegistrationResponse response with (Z, server_public_key)
    // 5. Output (response, oprf_key)

    // 3. Z = Evaluate(oprf_key, request.data)
    const byte_t *request_data = request;
    byte_t *Z = res.data;
    ecc_oprf_ristretto255_sha512_Evaluate(Z, oprf_key, request_data);

    // 4. Create RegistrationResponse response with (Z, server_public_key)
    // 5. Output (response, oprf_key)
    memcpy(res.server_public_key, server_public_key, sizeof res.server_public_key);
    memcpy(response, &res, sizeof res);

    // cleanup stack memory
    ecc_memzero((byte_t *) &res, sizeof res);
}

void ecc_opaque_ristretto255_sha512_CreateRegistrationResponse(
    byte_t *response, byte_t *oprf_key,
    const byte_t *request,
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
    const int ikm_info_len = credential_identifier_len + 7;
    byte_t ikm_info[256];
    byte_t oprf_key_label[7] = "OprfKey";
    ecc_concat2(ikm_info, credential_identifier, credential_identifier_len, oprf_key_label, 7);
    // - Expand(oprf_seed, ikm_info, Nok)
    const int ikm_len = ecc_opaque_ristretto255_sha512_Nok;
    byte_t ikm[ikm_len];
    ecc_kdf_hkdf_sha512_expand(ikm, oprf_seed, ikm_info, ikm_info_len, ikm_len);

    // 2. (oprf_key, _) = DeriveKeyPair(ikm)
    byte_t oprf_private_key[32];
    ecc_oprf_ristretto255_sha512_HashToScalar(oprf_private_key, ikm, ikm_len, 0x00);
    ecc_ristretto255_scalarmult_base(oprf_key, oprf_private_key);

    // 3. Z = Evaluate(oprf_key, request.data)
    // 4. Create RegistrationResponse response with (Z, server_public_key)
    // 5. Output (response, oprf_key)
    ecc_opaque_ristretto255_sha512_CreateRegistrationResponseWithOprfKey(
        response,
        request,
        server_public_key,
        credential_identifier, credential_identifier_len,
        oprf_key
    );

    // cleanup stack memory
    ecc_memzero(ikm_info, sizeof ikm_info);
    ecc_memzero(ikm, ikm_len);
    ecc_memzero(oprf_private_key, sizeof oprf_private_key);
}

void ecc_opaque_ristretto255_sha512_FinalizeRequest(
    byte_t *record, byte_t *export_key,
    const byte_t *client_private_key,
    const byte_t *password, const int password_len,
    const byte_t *blind,
    const byte_t *response,
    const byte_t *server_identity,
    const byte_t *client_identity
) {
    // Steps:
    // 1. y = Finalize(password, blind, response.data)
    // 2. randomized_pwd = Extract("", Harden(y, params))
    // 3. (envelope, client_public_key, masking_key, export_key) =
    //     CreateEnvelope(randomized_pwd, response.server_public_key, client_private_key,
    //                    server_identity, client_identity)
    // 4. Create RegistrationUpload record with (client_public_key, masking_key, envelope)
    // 5. Output (record, export_key)

    // 1. y = Finalize(password, blind, response.data)
    RegistrationResponse_t *res = (RegistrationResponse_t *) response;
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
    byte_t randomized_pwd_salt[0];
    // TODO: harden
    ecc_kdf_hkdf_sha512_extract(randomized_pwd, randomized_pwd_salt, 0, y, sizeof y);

    memcpy(record, randomized_pwd, 64);

    // TODO: next steps
}

void ecc_opaque_ristretto255_sha512_CreateCredentialResponse(
    byte_t *response,
    const byte_t *request,
    const byte_t *server_public_key,
    const byte_t *record,
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

    // 1. ikm = Expand(oprf_seed, concat(credential_identifier, "OprfKey"), Nok)
    // - concat(credential_identifier, "OprfKey")
    const int ikm_info_len = credential_identifier_len + 7;
    byte_t ikm_info[256];
    byte_t oprf_key_label[7] = "OprfKey";
    ecc_concat2(ikm_info, credential_identifier, credential_identifier_len, oprf_key_label, 7);
    // - Expand(oprf_seed, ikm_info, Nok)
    const int ikm_len = ecc_opaque_ristretto255_sha512_Nok;
    byte_t ikm[ikm_len];
    ecc_kdf_hkdf_sha512_expand(ikm, oprf_seed, ikm_info, ikm_info_len, ikm_len);

    // 2. (oprf_key, _) = DeriveKeyPair(ikm)
    byte_t oprf_private_key[32];
    byte_t oprf_key[32];
    ecc_oprf_ristretto255_sha512_HashToScalar(oprf_private_key, ikm, ikm_len, 0x00);
    ecc_ristretto255_scalarmult_base(oprf_key, oprf_private_key);

    // TODO: next steps
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
    ecc_oprf_ristretto255_sha512_HashToScalarWithDST(private_key, seed, seed_len, dst, sizeof dst);
    ecc_ristretto255_scalarmult_base(public_key, private_key);
}
