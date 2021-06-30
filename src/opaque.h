/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#ifndef ECC_OPAQUE_H
#define ECC_OPAQUE_H

#include "export.h"

#define ecc_opaque_ristretto255_sha512_Nn 32
#define ecc_opaque_ristretto255_sha512_Nm 64
#define ecc_opaque_ristretto255_sha512_Nh 64
#define ecc_opaque_ristretto255_sha512_Npk 32
#define ecc_opaque_ristretto255_sha512_Nsk 32
#define ecc_opaque_ristretto255_sha512_Noe 32
#define ecc_opaque_ristretto255_sha512_Nok 32

// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-05#section-5.1.1.1
ECC_EXPORT
void ecc_opaque_ristretto255_sha512_CreateRegistrationRequestWithBlind(
    byte_t *request,
    const byte_t *password, int password_len,
    const byte_t *blind
);

ECC_EXPORT
void ecc_opaque_ristretto255_sha512_CreateRegistrationRequest(
    byte_t *request, byte_t *blind,
    const byte_t *password, int password_len
);

// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-05#section-5.1.1.2
/**
 * In order to make this method not to use dynamic memory allocation, there is a
 * limit of credential_identifier_len <= 200.
 *
 * @param response
 * @param request
 * @param server_public_key
 * @param credential_identifier
 * @param credential_identifier_len
 * @param oprf_seed
 */
ECC_EXPORT
void ecc_opaque_ristretto255_sha512_CreateRegistrationResponseWithOprfKey(
    byte_t *response,
    const byte_t *request,
    const byte_t *server_public_key,
    const byte_t *credential_identifier, int credential_identifier_len,
    const byte_t *oprf_key
);

// TODO: try hard to unit test this function
// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-05#section-5.1.1.2
/**
 * In order to make this method not to use dynamic memory allocation, there is a
 * limit of credential_identifier_len <= 200.
 *
 * @param response
 * @param request
 * @param server_public_key
 * @param credential_identifier
 * @param credential_identifier_len
 * @param oprf_seed
 */
ECC_EXPORT
void ecc_opaque_ristretto255_sha512_CreateRegistrationResponse(
    byte_t *response, byte_t *oprf_key,
    const byte_t *request,
    const byte_t *server_public_key,
    const byte_t *credential_identifier, int credential_identifier_len,
    const byte_t *oprf_seed
);

ECC_EXPORT
void ecc_opaque_ristretto255_sha512_FinalizeRequest(
    byte_t *record, byte_t *export_key,
    const byte_t *client_private_key,
    const byte_t *password, int password_len,
    const byte_t *blind,
    const byte_t *response,
    const byte_t *server_identity,
    const byte_t *client_identity
);

/**
 * In order to make this method not to use dynamic memory allocation, there is a
 * limit of credential_identifier_len <= 200.
 *
 * @param response
 * @param request
 * @param server_public_key
 * @param credential_identifier
 * @param credential_identifier_len
 * @param oprf_seed
 */
ECC_EXPORT
void ecc_opaque_ristretto255_sha512_CreateCredentialResponse(
    byte_t *response,
    const byte_t *request,
    const byte_t *server_public_key,
    const byte_t *record,
    const byte_t *credential_identifier, int credential_identifier_len,
    const byte_t *oprf_seed
);

// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-05#section-4.3.1

ECC_EXPORT
void ecc_opaque_ristretto255_sha512_DeriveAuthKeyPair(
    byte_t *private_key, byte_t *public_key,
    const byte_t *seed, int seed_len
);

#endif // ECC_OPAQUE_H
