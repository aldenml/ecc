/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#ifndef ECC_OPAQUE_H
#define ECC_OPAQUE_H

#include "export.h"

// See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-05
//
// This implements only the following configuration:
//
// OPRF(ristretto255, SHA-512), HKDF-SHA-512, HMAC-SHA-512, SHA-512,
// MHF=Identity, internal, ristretto255
//
// In the future, I will add an option to use the MHF=Scrypt(32768,8,1).
// The reason is not added is because I want to avoid dynamic memory
// allocation. I have yet to adapt an existing implementation with some
// restrictions to avoid malloc/free calls.
//
// In order to work with stack allocated memory (i.e. fixed and not dynamic
// allocation), it's necessary to add the restriction on length of the
// identities to less than 200 bytes.
//
// The OPAQUE workflow consist of two steps, registration and authentication
// (you should read the draft/standard for a deep understanding).
//
// A high level overview.
//
// The registration flow is shown below:
//
//       creds                                   parameters
//         |                                         |
//         v                                         v
//       Client                                    Server
//       ------------------------------------------------
//                   registration request
//                ------------------------->
//                   registration response
//                <-------------------------
//                         record
//                ------------------------->
//      ------------------------------------------------
//         |                                         |
//         v                                         v
//     export_key                                 record
//
// The authenticated key exchange flow is shown below:
//
//       creds                             (parameters, record)
//         |                                         |
//         v                                         v
//       Client                                    Server
//       ------------------------------------------------
//                      AKE message 1
//                ------------------------->
//                      AKE message 2
//                <-------------------------
//                      AKE message 3
//                ------------------------->
//      ------------------------------------------------
//         |                                         |
//         v                                         v
//   (export_key, session_key)                  session_key

/**
 * The size all random nonces used in this protocol.
 */
#define ecc_opaque_ristretto255_sha512_Nn 32
/**
 * The output size of the "MAC=HMAC-SHA-512" function in bytes.
 */
#define ecc_opaque_ristretto255_sha512_Nm 64
/**
 * The output size of the "Hash=SHA-512" function in bytes.
 */
#define ecc_opaque_ristretto255_sha512_Nh 64
/**
 * The size of pseudorandom keys.
 */
#define ecc_opaque_ristretto255_sha512_Nx 64
/**
 * The size of public keys used in the AKE.
 */
#define ecc_opaque_ristretto255_sha512_Npk 32
/**
 * The size of private keys used in the AKE.
 */
#define ecc_opaque_ristretto255_sha512_Nsk 32
/**
 * The size of a serialized OPRF group element.
 */
#define ecc_opaque_ristretto255_sha512_Noe 32
/**
 * The size of an OPRF private key.
 */
#define ecc_opaque_ristretto255_sha512_Nok 32

// Since there is only one configuration supported, it is
// possible to specify all the internal structures sizes.

/**
 * Envelope size (Ne = Nn + Nm).
 */
#define ecc_opaque_ristretto255_sha512_Ne 96
#define ecc_opaque_ristretto255_sha512_REGISTRATIONREQUESTSIZE \
    ecc_opaque_ristretto255_sha512_Noe
#define ecc_opaque_ristretto255_sha512_REGISTRATIONRESPONSESIZE \
    ecc_opaque_ristretto255_sha512_Noe +                        \
    ecc_opaque_ristretto255_sha512_Npk
#define ecc_opaque_ristretto255_sha512_REGISTRATIONUPLOADSIZE \
    ecc_opaque_ristretto255_sha512_Npk +                      \
    ecc_opaque_ristretto255_sha512_Nh +                       \
    ecc_opaque_ristretto255_sha512_Ne
#define ecc_opaque_ristretto255_sha512_CREDENTIALREQUESTSIZE  \
    ecc_opaque_ristretto255_sha512_Noe
#define ecc_opaque_ristretto255_sha512_CREDENTIALRESPONSESIZE \
    ecc_opaque_ristretto255_sha512_Noe +                      \
    ecc_opaque_ristretto255_sha512_Nn +                       \
    ecc_opaque_ristretto255_sha512_Npk +                      \
    ecc_opaque_ristretto255_sha512_Ne
#define ecc_opaque_ristretto255_sha512_KE1SIZE             \
    ecc_opaque_ristretto255_sha512_CREDENTIALREQUESTSIZE + \
    ecc_opaque_ristretto255_sha512_Nn +                    \
    ecc_opaque_ristretto255_sha512_Npk
#define ecc_opaque_ristretto255_sha512_KE2SIZE              \
    ecc_opaque_ristretto255_sha512_CREDENTIALRESPONSESIZE + \
    ecc_opaque_ristretto255_sha512_Nn +                     \
    ecc_opaque_ristretto255_sha512_Npk +                    \
    ecc_opaque_ristretto255_sha512_Nm
#define ecc_opaque_ristretto255_sha512_KE3SIZE  \
    ecc_opaque_ristretto255_sha512_Nm
#define ecc_opaque_ristretto255_sha512_CLIENTSTATESIZE \
    ecc_opaque_ristretto255_sha512_Nok +               \
    ecc_opaque_ristretto255_sha512_Nsk +               \
    ecc_opaque_ristretto255_sha512_KE1SIZE
#define ecc_opaque_ristretto255_sha512_SERVERSTATESIZE \
    ecc_opaque_ristretto255_sha512_Nm +               \
    ecc_opaque_ristretto255_sha512_Nx

/**
 * Constructs a "CleartextCredentials" structure given application
 * credential information.
 *
 * Since the identities are not length fixed, it's not possible to create
 * a static structure for this record. Instead the function returns the
 * length of the record once it's created.
 *
 * If you pass NULL for `cleartext_credentials` it will return the total
 * size of memory necessary to hold the result.
 *
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-05#section-4
 *
 * @param cleartext_credentials
 * @param server_public_key
 * @param client_public_key
 * @param server_identity
 * @param server_identity_len
 * @param client_identity
 * @param client_identity_len
 * @return
 */
ECC_OPAQUE_EXPORT
ECC_EXPORT
int ecc_opaque_ristretto255_sha512_CreateCleartextCredentials(
    byte_t *cleartext_credentials,
    const byte_t *server_public_key,
    const byte_t *client_public_key,
    const byte_t *server_identity, int server_identity_len,
    const byte_t *client_identity, int client_identity_len
);

/**
 * Same as calling `ecc_opaque_ristretto255_sha512_CreateEnvelope` with an
 * specified `nonce`.
 *
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-05#section-4.2
 *
 * @param envelope_raw
 * @param client_public_key
 * @param masking_key
 * @param export_key
 * @param randomized_pwd
 * @param server_public_key
 * @param client_private_key
 * @param server_identity
 * @param server_identity_len
 * @param client_identity
 * @param client_identity_len
 * @param nonce
 */
ECC_OPAQUE_EXPORT
ECC_EXPORT
void ecc_opaque_ristretto255_sha512_CreateEnvelopeWithNonce(
    byte_t *envelope_raw,
    byte_t *client_public_key,
    byte_t *masking_key,
    byte_t *export_key,
    const byte_t *randomized_pwd,
    const byte_t *server_public_key,
    const byte_t *client_private_key,
    const byte_t *server_identity, int server_identity_len,
    const byte_t *client_identity, int client_identity_len,
    const byte_t *nonce
);

/**
 * Creates an "Envelope" at registration.
 *
 * In order to work with stack allocated memory (i.e. fixed and not dynamic
 * allocation), it's necessary to add the restriction on length of the
 * identities to less than 200 bytes.
 *
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-05#section-4.2
 *
 * @param envelope
 * @param client_public_key
 * @param masking_key
 * @param export_key
 * @param randomized_pwd
 * @param server_public_key
 * @param client_private_key
 * @param server_identity
 * @param server_identity_len
 * @param client_identity
 * @param client_identity_len
 */
ECC_OPAQUE_EXPORT
ECC_EXPORT
void ecc_opaque_ristretto255_sha512_CreateEnvelope(
    byte_t *envelope,
    byte_t *client_public_key,
    byte_t *masking_key,
    byte_t *export_key,
    const byte_t *randomized_pwd,
    const byte_t *server_public_key,
    const byte_t *client_private_key,
    const byte_t *server_identity, int server_identity_len,
    const byte_t *client_identity, int client_identity_len
);

/**
 * This functions attempts to recover the credentials from the input. On
 * success returns 0, else -1.
 *
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-05#section-4.2
 *
 * @param client_private_key
 * @param export_key
 * @param randomized_pwd
 * @param server_public_key
 * @param envelope_raw
 * @param server_identity
 * @param server_identity_len
 * @param client_identity
 * @param client_identity_len
 * @return on success returns 0, else -1.
 */
ECC_OPAQUE_EXPORT
ECC_EXPORT
int ecc_opaque_ristretto255_sha512_RecoverEnvelope(
    byte_t *client_private_key,
    byte_t *export_key,
    const byte_t *randomized_pwd,
    const byte_t *server_public_key,
    const byte_t *envelope_raw,
    const byte_t *server_identity, int server_identity_len,
    const byte_t *client_identity, int client_identity_len
);

/**
 * Recover the public key related to the input "private_key".
 *s
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-05#section-2
 *
 * @param public_key
 * @param private_key
 */
ECC_OPAQUE_EXPORT
ECC_EXPORT
void ecc_opaque_ristretto255_sha512_RecoverPublicKey(
    byte_t *public_key,
    const byte_t *private_key
);

ECC_OPAQUE_EXPORT
ECC_EXPORT
void ecc_opaque_ristretto255_sha512_GenerateAuthKeyPair(
    byte_t *private_key, byte_t *public_key
);

ECC_OPAQUE_EXPORT
ECC_EXPORT
void ecc_opaque_ristretto255_sha512_DeriveAuthKeyPair(
    byte_t *private_key, byte_t *public_key,
    const byte_t *seed, int seed_len
);

ECC_OPAQUE_EXPORT
ECC_EXPORT
void ecc_opaque_ristretto255_sha512_BuildInnerEnvelope(
    byte_t *inner_env,
    byte_t *client_public_key,
    const byte_t *randomized_pwd,
    const byte_t *nonce,
    const byte_t *client_private_key
);

ECC_OPAQUE_EXPORT
ECC_EXPORT
void ecc_opaque_ristretto255_sha512_RecoverKeys(
    byte_t *client_private_key,
    byte_t *client_public_key,
    const byte_t *randomized_pwd,
    const byte_t *nonce,
    const byte_t *inner_env
);

// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-05#section-5.1.1.1
ECC_OPAQUE_EXPORT
ECC_EXPORT
void ecc_opaque_ristretto255_sha512_CreateRegistrationRequestWithBlind(
    byte_t *request_raw,
    const byte_t *password, int password_len,
    const byte_t *blind
);

ECC_OPAQUE_EXPORT
ECC_EXPORT
void ecc_opaque_ristretto255_sha512_CreateRegistrationRequest(
    byte_t *request,
    byte_t *blind, // 32
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
ECC_OPAQUE_EXPORT
ECC_EXPORT
void ecc_opaque_ristretto255_sha512_CreateRegistrationResponseWithOprfKey(
    byte_t *response_raw,
    const byte_t *request_raw,
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
ECC_OPAQUE_EXPORT
ECC_EXPORT
void ecc_opaque_ristretto255_sha512_CreateRegistrationResponse(
    byte_t *response_raw,
    byte_t *oprf_key,
    const byte_t *request_raw,
    const byte_t *server_public_key,
    const byte_t *credential_identifier, int credential_identifier_len,
    const byte_t *oprf_seed
);

ECC_OPAQUE_EXPORT
ECC_EXPORT
void ecc_opaque_ristretto255_sha512_FinalizeRequest(
    byte_t *record_raw, // RegistrationUpload_t
    byte_t *export_key,
    const byte_t *client_private_key,
    const byte_t *password, int password_len,
    const byte_t *blind,
    const byte_t *response_raw, // RegistrationResponse_t
    const byte_t *server_identity, int server_identity_len,
    const byte_t *client_identity, int client_identity_len
);

ECC_OPAQUE_EXPORT
ECC_EXPORT
void ecc_opaque_ristretto255_sha512_CreateCredentialRequest(
    byte_t *request_raw,
    byte_t *blind,
    const byte_t *password, int password_len
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
ECC_OPAQUE_EXPORT
ECC_EXPORT
void ecc_opaque_ristretto255_sha512_CreateCredentialResponse(
    byte_t *response_raw,
    const byte_t *request_raw,
    const byte_t *server_public_key,
    const byte_t *record_raw,
    const byte_t *credential_identifier, int credential_identifier_len,
    const byte_t *oprf_seed
);

ECC_OPAQUE_EXPORT
ECC_EXPORT
int ecc_opaque_ristretto255_sha512_RecoverCredentials(
    byte_t *client_private_key,
    byte_t *server_public_key,
    byte_t *export_key,
    const byte_t *password, int password_len,
    const byte_t *blind,
    const byte_t *response,
    const byte_t *server_identity, int server_identity_len,
    const byte_t *client_identity, int client_identity_len
);

ECC_OPAQUE_EXPORT
ECC_EXPORT
void ecc_opaque_ristretto255_sha512_3DH_Expand_Label(
    byte_t *out,
    const byte_t *secret,
    const byte_t *label, int label_len,
    const byte_t *context, int context_len,
    int length
);

ECC_OPAQUE_EXPORT
ECC_EXPORT
void ecc_opaque_ristretto255_sha512_3DH_Derive_Secret(
    byte_t *out,
    const byte_t *secret,
    const byte_t *label, int label_len,
    const byte_t *transcript_hash, int transcript_hash_len
);

ECC_OPAQUE_EXPORT
ECC_EXPORT
int ecc_opaque_ristretto255_sha512_3DH_Preamble(
    byte_t *preamble,
    const byte_t *context, int context_len,
    const byte_t *client_identity, int client_identity_len,
    const byte_t *ke1,
    const byte_t *server_identity, int server_identity_len,
    const byte_t *inner_ke2
);

ECC_OPAQUE_EXPORT
ECC_EXPORT
void ecc_opaque_ristretto255_sha512_3DH_TripleDHIKM(
    byte_t *ikm,
    const byte_t *sk1, const byte_t *pk1,
    const byte_t *sk2, const byte_t *pk2,
    const byte_t *sk3, const byte_t *pk3
);

ECC_OPAQUE_EXPORT
ECC_EXPORT
void ecc_opaque_ristretto255_sha512_3DH_DeriveKeys(
    byte_t *km2, byte_t *km3,
    byte_t *session_key,
    const byte_t *ikm, int ikm_len,
    const byte_t *preamble, int preamble_len
);

ECC_OPAQUE_EXPORT
ECC_EXPORT
void ecc_opaque_ristretto255_sha512_3DH_ClientInit(
    byte_t *ke1_raw,
    const byte_t *state_raw,
    const byte_t *client_identity, int client_identity_len,
    const byte_t *password, int password_len
);

ECC_OPAQUE_EXPORT
ECC_EXPORT
int ecc_opaque_ristretto255_sha512_3DH_ClientFinish(
    byte_t *ke3_raw,
    byte_t *session_key,
    byte_t *export_key,
    const byte_t *state_raw,
    const byte_t *password, int password_len,
    const byte_t *client_identity, int client_identity_len,
    const byte_t *server_identity, int server_identity_len,
    const byte_t *ke1_raw,
    const byte_t *ke2_raw
);

ECC_OPAQUE_EXPORT
ECC_EXPORT
void ecc_opaque_ristretto255_sha512_3DH_Start(
    byte_t *ke1,
    const byte_t *state,
    const byte_t *credential_request
);

ECC_OPAQUE_EXPORT
ECC_EXPORT
int ecc_opaque_ristretto255_sha512_3DH_ClientFinalize(
    byte_t *ke3,
    byte_t *session_key,
    const byte_t *state,
    const byte_t *client_identity, int client_identity_len,
    const byte_t *client_private_key,
    const byte_t *server_identity, int server_identity_len,
    const byte_t *server_public_key,
    const byte_t *ke1, const byte_t *ke2
);

ECC_OPAQUE_EXPORT
ECC_EXPORT
void ecc_opaque_ristretto255_sha512_3DH_ServerInit(
    byte_t *ke2_raw,
    const byte_t *state_raw,
    const byte_t *server_identity, int server_identity_len,
    const byte_t *server_private_key, const byte_t *server_public_key,
    const byte_t *record_raw,
    const byte_t *credential_identifier, int credential_identifier_len,
    const byte_t *oprf_seed,
    const byte_t *ke1_raw
);

ECC_OPAQUE_EXPORT
ECC_EXPORT
int ecc_opaque_ristretto255_sha512_3DH_ServerFinish(
    byte_t *session_key,
    const byte_t *state_raw,
    const byte_t *ke3_raw
);

ECC_OPAQUE_EXPORT
ECC_EXPORT
void ecc_opaque_ristretto255_sha512_3DH_Response(
    byte_t *ke2_raw,
    const byte_t *state_raw,
    const byte_t *server_identity, int server_identity_len,
    const byte_t *server_private_key,
    const byte_t *client_identity, int client_identity_len,
    const byte_t *client_public_key,
    const byte_t *ke1_raw,
    const byte_t *credential_response_raw
);

#endif // ECC_OPAQUE_H
