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

// const
/**
 * The size all random nonces used in this protocol.
 */
#define ecc_opaque_ristretto255_sha512_Nn 32

// const
/**
 * The output size of the "MAC=HMAC-SHA-512" function in bytes.
 */
#define ecc_opaque_ristretto255_sha512_Nm 64

// const
/**
 * The output size of the "Hash=SHA-512" function in bytes.
 */
#define ecc_opaque_ristretto255_sha512_Nh 64

// const
/**
 * The size of pseudorandom keys.
 */
#define ecc_opaque_ristretto255_sha512_Nx 64

// const
/**
 * The size of public keys used in the AKE.
 */
#define ecc_opaque_ristretto255_sha512_Npk 32

// const
/**
 * The size of private keys used in the AKE.
 */
#define ecc_opaque_ristretto255_sha512_Nsk 32

// const
/**
 * The size of a serialized OPRF group element.
 */
#define ecc_opaque_ristretto255_sha512_Noe 32

// const
/**
 * The size of an OPRF private key.
 */
#define ecc_opaque_ristretto255_sha512_Nok 32

// Since there is only one configuration supported, it is
// possible to specify all the internal structures sizes.

// const
/**
 * Envelope size (Ne = Nn + Nm).
 */
#define ecc_opaque_ristretto255_sha512_Ne 96

// const
/**
 *
 */
#define ecc_opaque_ristretto255_sha512_REGISTRATIONREQUESTSIZE 32

// const
/**
 *
 */
#define ecc_opaque_ristretto255_sha512_REGISTRATIONRESPONSESIZE 64

// const
/**
 *
 */
#define ecc_opaque_ristretto255_sha512_REGISTRATIONUPLOADSIZE 192

// const
/**
 *
 */
#define ecc_opaque_ristretto255_sha512_CREDENTIALREQUESTSIZE 32

// const
/**
 *
 */
#define ecc_opaque_ristretto255_sha512_CREDENTIALRESPONSESIZE 192

// const
/**
 *
 */
#define ecc_opaque_ristretto255_sha512_KE1SIZE 96

// const
/**
 *
 */
#define ecc_opaque_ristretto255_sha512_KE2SIZE 320

// const
/**
 *
 */
#define ecc_opaque_ristretto255_sha512_KE3SIZE 64

// const
/**
 *
 */
#define ecc_opaque_ristretto255_sha512_CLIENTSTATESIZE 160

// const
/**
 *
 */
#define ecc_opaque_ristretto255_sha512_SERVERSTATESIZE 128

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
 * @param[out] cleartext_credentials a CleartextCredentials structure, size:cleartext_credentials_len
 * @param cleartext_credentials_len the length of `cleartext_credentials`
 * @param server_public_key the encoded server public key for the AKE protocol, size:ecc_opaque_ristretto255_sha512_Npk
 * @param client_public_key the encoded client public key for the AKE protocol, size:ecc_opaque_ristretto255_sha512_Npk
 * @param server_identity the optional encoded server identity, size:server_identity_len
 * @param server_identity_len the length of `server_identity`
 * @param client_identity the optional encoded client identity, size:client_identity_len
 * @param client_identity_len the length of `client_identity`
 * @return the size of the serialized structure
 */
ECC_EXPORT
int ecc_opaque_ristretto255_sha512_CreateCleartextCredentials(
    byte_t *cleartext_credentials, int cleartext_credentials_len,
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
 * @param[out] envelope_raw size:ecc_opaque_ristretto255_sha512_Ne
 * @param[out] client_public_key size:ecc_opaque_ristretto255_sha512_Npk
 * @param[out] masking_key size:ecc_opaque_ristretto255_sha512_Nh
 * @param[out] export_key size:ecc_opaque_ristretto255_sha512_Nh
 * @param randomized_pwd size:64
 * @param server_public_key size:ecc_opaque_ristretto255_sha512_Npk
 * @param client_private_key size:ecc_opaque_ristretto255_sha512_Nsk
 * @param server_identity size:server_identity_len
 * @param server_identity_len
 * @param client_identity size:client_identity_len
 * @param client_identity_len
 * @param nonce size:ecc_opaque_ristretto255_sha512_Nn
 */
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
 * @param[out] envelope size:ecc_opaque_ristretto255_sha512_Ne
 * @param[out] client_public_key size:ecc_opaque_ristretto255_sha512_Npk
 * @param[out] masking_key size:ecc_opaque_ristretto255_sha512_Nh
 * @param[out] export_key size:ecc_opaque_ristretto255_sha512_Nh
 * @param randomized_pwd size:64
 * @param server_public_key size:ecc_opaque_ristretto255_sha512_Npk
 * @param client_private_key size:ecc_opaque_ristretto255_sha512_Nsk
 * @param server_identity size:server_identity_len
 * @param server_identity_len
 * @param client_identity size:client_identity_len
 * @param client_identity_len
 */
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
 * @param[out] client_private_key size:ecc_opaque_ristretto255_sha512_Nsk
 * @param[out] export_key size:ecc_opaque_ristretto255_sha512_Nh
 * @param randomized_pwd size:64
 * @param server_public_key size:ecc_opaque_ristretto255_sha512_Npk
 * @param envelope_raw size:ecc_opaque_ristretto255_sha512_Ne
 * @param server_identity size:server_identity_len
 * @param server_identity_len
 * @param client_identity size:client_identity_len
 * @param client_identity_len
 * @return on success returns 0, else -1.
 */
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
 *
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-05#section-2
 *
 * @param[out] public_key size:ecc_opaque_ristretto255_sha512_Npk
 * @param private_key size:ecc_opaque_ristretto255_sha512_Nsk
 */
ECC_EXPORT
void ecc_opaque_ristretto255_sha512_RecoverPublicKey(
    byte_t *public_key,
    const byte_t *private_key
);

/**
 * Returns a randomly generated private and public key pair.
 *
 * This is implemented by generating a random "seed", then
 * calling internally DeriveAuthKeyPair.
 *
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-05#section-2
 *
 * @param[out] private_key a private key, size:ecc_opaque_ristretto255_sha512_Nsk
 * @param[out] public_key the associated public key, size:ecc_opaque_ristretto255_sha512_Npk
 */
ECC_EXPORT
void ecc_opaque_ristretto255_sha512_GenerateAuthKeyPair(
    byte_t *private_key, byte_t *public_key
);

/**
 * Derive a private and public authentication key pair deterministically
 * from the input "seed".
 *
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-05#section-4.3.1
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-05#section-2
 *
 * @param[out] private_key a private key, size:ecc_opaque_ristretto255_sha512_Nsk
 * @param[out] public_key the associated public key, size:ecc_opaque_ristretto255_sha512_Npk
 * @param seed pseudo-random byte sequence used as a seed, size:seed_len
 * @param seed_len the length of `seed`
 */
ECC_EXPORT
void ecc_opaque_ristretto255_sha512_DeriveAuthKeyPair(
    byte_t *private_key, byte_t *public_key,
    const byte_t *seed, int seed_len
);

/**
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-05#section-4.3.1
 *
 * @param[out] inner_env size:0
 * @param[out] client_public_key size:ecc_opaque_ristretto255_sha512_Npk
 * @param randomized_pwd size:64
 * @param nonce size:ecc_opaque_ristretto255_sha512_Nn
 * @param client_private_key size:ecc_opaque_ristretto255_sha512_Nsk
 */
ECC_EXPORT
void ecc_opaque_ristretto255_sha512_BuildInnerEnvelope(
    byte_t *inner_env,
    byte_t *client_public_key,
    const byte_t *randomized_pwd,
    const byte_t *nonce,
    const byte_t *client_private_key
);

/**
 *
 * @param[out] client_private_key size:ecc_opaque_ristretto255_sha512_Nsk
 * @param[out] client_public_key size:ecc_opaque_ristretto255_sha512_Npk
 * @param randomized_pwd size:64
 * @param nonce size:ecc_opaque_ristretto255_sha512_Nn
 * @param inner_env size:0
 */
ECC_EXPORT
void ecc_opaque_ristretto255_sha512_RecoverKeys(
    byte_t *client_private_key,
    byte_t *client_public_key,
    const byte_t *randomized_pwd,
    const byte_t *nonce,
    const byte_t *inner_env
);

/**
 * Same as calling CreateRegistrationRequest with a specified blind.
 *
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-05#section-5.1.1.1
 *
 * @param[out] request_raw a RegistrationRequest structure, size:ecc_opaque_ristretto255_sha512_REGISTRATIONREQUESTSIZE
 * @param password an opaque byte string containing the client's password, size:password_len
 * @param password_len the length of `password`
 * @param blind the OPRF scalar value to use, size:ecc_opaque_ristretto255_sha512_Noe
 */
ECC_EXPORT
void ecc_opaque_ristretto255_sha512_CreateRegistrationRequestWithBlind(
    byte_t *request_raw,
    const byte_t *password, int password_len,
    const byte_t *blind
);

/**
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-05#section-5.1.1.1
 *
 * @param[out] request_raw a RegistrationRequest structure, size:ecc_opaque_ristretto255_sha512_REGISTRATIONREQUESTSIZE
 * @param[out] blind an OPRF scalar value, size:ecc_opaque_ristretto255_sha512_Noe
 * @param password an opaque byte string containing the client's password, size:password_len
 * @param password_len the length of `password`
 */
ECC_EXPORT
void ecc_opaque_ristretto255_sha512_CreateRegistrationRequest(
    byte_t *request_raw,
    byte_t *blind, // 32
    const byte_t *password, int password_len
);

/**
 * Same as calling CreateRegistrationResponse with an specific oprf_seed.
 *
 * In order to make this method not to use dynamic memory allocation, there is a
 * limit of credential_identifier_len <= 200.
 *
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-05#section-5.1.1.2
 *
 * @param[out] response size:ecc_opaque_ristretto255_sha512_REGISTRATIONRESPONSESIZE
 * @param request size:ecc_opaque_ristretto255_sha512_REGISTRATIONREQUESTSIZE
 * @param server_public_key size:ecc_opaque_ristretto255_sha512_Npk
 * @param credential_identifier size:credential_identifier_len
 * @param credential_identifier_len
 * @param oprf_key size:32
 */
ECC_EXPORT
void ecc_opaque_ristretto255_sha512_CreateRegistrationResponseWithOprfKey(
    byte_t *response_raw,
    const byte_t *request_raw,
    const byte_t *server_public_key,
    const byte_t *credential_identifier, int credential_identifier_len,
    const byte_t *oprf_key
);

/**
 * In order to make this method not to use dynamic memory allocation, there is a
 * limit of credential_identifier_len <= 200.
 *
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-05#section-5.1.1.2
 *
 * @param[out] response_raw a RegistrationResponse structure, size:ecc_opaque_ristretto255_sha512_REGISTRATIONRESPONSESIZE
 * @param[out] oprf_key the per-client OPRF key known only to the server, size:32
 * @param request_raw a RegistrationRequest structure, size:ecc_opaque_ristretto255_sha512_REGISTRATIONREQUESTSIZE
 * @param server_public_key the server's public key, size:ecc_opaque_ristretto255_sha512_Npk
 * @param credential_identifier an identifier that uniquely represents the credential being registered, size:credential_identifier_len
 * @param credential_identifier_len the length of `credential_identifier`
 * @param oprf_seed the server-side seed of Nh bytes used to generate an oprf_key, size:ecc_opaque_ristretto255_sha512_Nh
 */
ECC_EXPORT
void ecc_opaque_ristretto255_sha512_CreateRegistrationResponse(
    byte_t *response_raw,
    byte_t *oprf_key,
    const byte_t *request_raw,
    const byte_t *server_public_key,
    const byte_t *credential_identifier, int credential_identifier_len,
    const byte_t *oprf_seed
);

/**
 * To create the user record used for further authentication, the client
 * executes the following function. Since this works in the internal key mode, the
 * "client_private_key" is null.
 *
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-05#section-5.1.1.3
 *
 * @param[out] record_raw a RegistrationUpload structure, size:ecc_opaque_ristretto255_sha512_REGISTRATIONUPLOADSIZE
 * @param[out] export_key an additional client key, size:ecc_opaque_ristretto255_sha512_Nh
 * @param client_private_key the client's private key (always null, internal mode), size:0
 * @param password an opaque byte string containing the client's password, size:password_len
 * @param password_len the length of `password`
 * @param blind the OPRF scalar value used for blinding, size:ecc_opaque_ristretto255_sha512_Noe
 * @param response_raw a RegistrationResponse structure, size:ecc_opaque_ristretto255_sha512_REGISTRATIONRESPONSESIZE
 * @param server_identity the optional encoded server identity, size:server_identity_len
 * @param server_identity_len the length of `server_identity`
 * @param client_identity the optional encoded client identity, size:client_identity_len
 * @param client_identity_len the length of `client_identity`
 */
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

/**
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-05#section-6.1.2.1
 *
 * @param[out] request_raw a CredentialRequest structure, size:ecc_opaque_ristretto255_sha512_CREDENTIALREQUESTSIZE
 * @param[out] blind an OPRF scalar value, size:ecc_opaque_ristretto255_sha512_Noe
 * @param password an opaque byte string containing the client's password, size:password_len
 * @param password_len the length of `password`
 */
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
 * There are two scenarios to handle for the construction of a
 * CredentialResponse object: either the record for the client exists
 * (corresponding to a properly registered client), or it was never
 * created (corresponding to a client that has yet to register).
 *
 * In the case of a record that does not exist, the server SHOULD invoke
 * the CreateCredentialResponse function where the record argument is
 * configured so that:
 *
 *  - record.masking_key is set to a random byte string of length Nh, and
 *  - record.envelope is set to the byte string consisting only of
 *    zeros, of length Ne
 *
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-05#section-6.1.2.2
 *
 * @param[out] response size:ecc_opaque_ristretto255_sha512_CREDENTIALRESPONSESIZE
 * @param request size:ecc_opaque_ristretto255_sha512_CREDENTIALREQUESTSIZE
 * @param server_public_key size:ecc_opaque_ristretto255_sha512_Npk
 * @param credential_identifier size:credential_identifier_len
 * @param credential_identifier_len
 * @param oprf_seed size:ecc_opaque_ristretto255_sha512_Nh
 */
ECC_EXPORT
void ecc_opaque_ristretto255_sha512_CreateCredentialResponse(
    byte_t *response_raw,
    const byte_t *request_raw,
    const byte_t *server_public_key,
    const byte_t *record_raw,
    const byte_t *credential_identifier, int credential_identifier_len,
    const byte_t *oprf_seed
);

/**
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-05#section-6.1.2.3
 *
 * @param[out] client_private_key size:ecc_opaque_ristretto255_sha512_Nsk
 * @param[out] server_public_key size:ecc_opaque_ristretto255_sha512_Npk
 * @param[out] export_key size:ecc_opaque_ristretto255_sha512_Nh
 * @param password size:password_len
 * @param password_len
 * @param blind size:ecc_opaque_ristretto255_sha512_Noe
 * @param response size:ecc_opaque_ristretto255_sha512_CREDENTIALRESPONSESIZE
 * @param server_identity size:server_identity_len
 * @param server_identity_len
 * @param client_identity size:client_identity_len
 * @param client_identity_len
 * @return on success returns 0, else -1.
 */
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

/**
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-05#section-6.2.2.1
 *
 * @param[out] out size:length
 * @param secret size:64
 * @param label size:label_len
 * @param label_len
 * @param context size:context_len
 * @param context_len
 * @param length
 */
ECC_EXPORT
void ecc_opaque_ristretto255_sha512_3DH_Expand_Label(
    byte_t *out,
    const byte_t *secret,
    const byte_t *label, int label_len,
    const byte_t *context, int context_len,
    int length
);

/**
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-05#section-6.2.2.1
 *
 * @param[out] out size:ecc_opaque_ristretto255_sha512_Nx
 * @param secret size:64
 * @param label size:label_len
 * @param label_len
 * @param transcript_hash size:transcript_hash_len
 * @param transcript_hash_len
 */
ECC_EXPORT
void ecc_opaque_ristretto255_sha512_3DH_Derive_Secret(
    byte_t *out,
    const byte_t *secret,
    const byte_t *label, int label_len,
    const byte_t *transcript_hash, int transcript_hash_len
);

/**
 * The OPAQUE-3DH key schedule requires a preamble.
 *
 * OPAQUE-3DH can optionally include shared "context" information in the
 * transcript, such as configuration parameters or application-specific
 * info, e.g. "appXYZ-v1.2.3".
 *
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-05#section-6.2.2.1
 *
 * @param[out] preamble the protocol transcript with identities and messages, size:preamble_len
 * @param preamble_len
 * @param context optional shared context information, size:context_len
 * @param context_len the length of `context`
 * @param client_identity the optional encoded client identity, size:client_identity_len
 * @param client_identity_len the length of `client_identity`
 * @param ke1 a KE1 message structure, size:ke1_len
 * @param ke1_len the length of `ke1`
 * @param server_identity the optional encoded server identity, size:server_identity_len
 * @param server_identity_len the length of `server_identity`
 * @param inner_ke2 an inner_ke2 structure as defined in KE2, size:inner_ke2_len
 * @param inner_ke2_len the length of `inner_ke2`
 * @return the protocol transcript with identities and messages
 */
ECC_EXPORT
int ecc_opaque_ristretto255_sha512_3DH_Preamble(
    byte_t *preamble,
    int preamble_len,
    const byte_t *context, int context_len,
    const byte_t *client_identity, int client_identity_len,
    const byte_t *ke1, int ke1_len,
    const byte_t *server_identity, int server_identity_len,
    const byte_t *inner_ke2, int inner_ke2_len
);

/**
 * Computes the OPAQUE-3DH shared secret derived during the key
 * exchange protocol.
 *
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-05#section-6.2.2.2
 *
 * @param[out] ikm size:96
 * @param sk1 size:32
 * @param pk1 size:32
 * @param sk2 size:32
 * @param pk2 size:32
 * @param sk3 size:32
 * @param pk3 size:32
 */
ECC_EXPORT
void ecc_opaque_ristretto255_sha512_3DH_TripleDHIKM(
    byte_t *ikm,
    const byte_t *sk1, const byte_t *pk1,
    const byte_t *sk2, const byte_t *pk2,
    const byte_t *sk3, const byte_t *pk3
);

/**
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-05#section-6.2.2.2
 *
 * @param[out] km2 size:64
 * @param[out] km3 size:64
 * @param[out] session_key size:64
 * @param ikm size:ikm_len
 * @param ikm_len
 * @param preamble size:preamble_len
 * @param preamble_len
 */
ECC_EXPORT
void ecc_opaque_ristretto255_sha512_3DH_DeriveKeys(
    byte_t *km2,
    byte_t *km3,
    byte_t *session_key,
    const byte_t *ikm, int ikm_len,
    const byte_t *preamble, int preamble_len
);

/**
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-05#section-6.2.3
 *
 * @param[out] ke1_raw a KE1 message structure, size:ecc_opaque_ristretto255_sha512_KE1SIZE
 * @param state_raw a ClientState structure, size:ecc_opaque_ristretto255_sha512_CLIENTSTATESIZE
 * @param client_identity the optional encoded client identity, which is null if not specified, size:client_identity_len
 * @param client_identity_len the length of `client_identity`
 * @param password an opaque byte string containing the client's password, size:password_len
 * @param password_len the length of `password`
 */
ECC_EXPORT
void ecc_opaque_ristretto255_sha512_3DH_ClientInit(
    byte_t *ke1_raw,
    const byte_t *state_raw,
    const byte_t *client_identity, int client_identity_len,
    const byte_t *password, int password_len
);

/**
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-05#section-6.2.3
 *
 * @param[out] ke3_raw a KE3 message structure, size:ecc_opaque_ristretto255_sha512_KE3SIZE
 * @param[out] session_key the session's shared secret, size:64
 * @param[out] export_key an additional client key, size:64
 * @param state_raw a ClientState structure, size:ecc_opaque_ristretto255_sha512_CLIENTSTATESIZE
 * @param password an opaque byte string containing the client's password, size:password_len
 * @param password_len the length of `password`
 * @param client_identity the optional encoded client identity, which is set
 * to client_public_key if not specified, size:client_identity_len
 * @param client_identity_len the length of `client_identity`
 * @param server_identity the optional encoded server identity, which is set
 * to server_public_key if not specified, size:server_identity_len
 * @param server_identity_len the length of `server_identity`
 * @param ke2_raw a KE2 message structure, size:ecc_opaque_ristretto255_sha512_KE2SIZE
 * @return 0 if is able to recover credentials and authenticate with the server, else -1
 */
ECC_EXPORT
int ecc_opaque_ristretto255_sha512_3DH_ClientFinish(
    byte_t *ke3_raw,
    byte_t *session_key,
    byte_t *export_key,
    const byte_t *state_raw,
    const byte_t *password, int password_len,
    const byte_t *client_identity, int client_identity_len,
    const byte_t *server_identity, int server_identity_len,
    const byte_t *ke2_raw
);

/**
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-05#section-6.2.3.1
 *
 * @param[out] ke1_raw size:ecc_opaque_ristretto255_sha512_KE1SIZE
 * @param state_raw size:ecc_opaque_ristretto255_sha512_CLIENTSTATESIZE
 * @param credential_request size:ecc_opaque_ristretto255_sha512_CREDENTIALREQUESTSIZE
 */
ECC_EXPORT
void ecc_opaque_ristretto255_sha512_3DH_Start(
    byte_t *ke1_raw,
    const byte_t *state_raw,
    const byte_t *credential_request
);

/**
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-05#section-6.2.3.1
 * @param[out] ke3_raw size:ecc_opaque_ristretto255_sha512_KE3SIZE
 * @param[out] session_key size:64
 * @param state_raw size:ecc_opaque_ristretto255_sha512_CLIENTSTATESIZE
 * @param client_identity size:client_identity_len
 * @param client_identity_len
 * @param client_private_key size:ecc_opaque_ristretto255_sha512_Nsk
 * @param server_identity size:server_identity_len
 * @param server_identity_len
 * @param server_public_key size:ecc_opaque_ristretto255_sha512_Npk
 * @param ke2_raw size:ecc_opaque_ristretto255_sha512_KE2SIZE
 * @return 0 if success, else -1
 */
ECC_EXPORT
int ecc_opaque_ristretto255_sha512_3DH_ClientFinalize(
    byte_t *ke3_raw,
    byte_t *session_key,
    const byte_t *state_raw,
    const byte_t *client_identity, int client_identity_len,
    const byte_t *client_private_key,
    const byte_t *server_identity, int server_identity_len,
    const byte_t *server_public_key,
    const byte_t *ke2_raw,
    const byte_t *context, int context_len
);

/**
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-05#section-6.2.4
 *
 * @param[out] ke2_raw a KE2 structure, size:ecc_opaque_ristretto255_sha512_KE2SIZE
 * @param state_raw a ServerState structure, size:ecc_opaque_ristretto255_sha512_SERVERSTATESIZE
 * @param server_identity the optional encoded server identity, which is set to
 * server_public_key if null, size:server_identity_len
 * @param server_identity_len the length of `server_identity`
 * @param server_private_key the server's private key, size:ecc_opaque_ristretto255_sha512_Nsk
 * @param server_public_key the server's public key, size:ecc_opaque_ristretto255_sha512_Npk
 * @param record_raw the client's RegistrationUpload structure, size:ecc_opaque_ristretto255_sha512_REGISTRATIONUPLOADSIZE
 * @param credential_identifier an identifier that uniquely represents the credential
 * being registered, size:credential_identifier_len
 * @param credential_identifier_len the length of `credential_identifier`
 * @param oprf_seed the server-side seed of Nh bytes used to generate an oprf_key, size:ecc_opaque_ristretto255_sha512_Nh
 * @param ke1_raw a KE1 message structure, size:ecc_opaque_ristretto255_sha512_KE1SIZE
 * @param context the application specific context, size:context_len
 * @param context_len the length of `context`
 */
ECC_EXPORT
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
);

/**
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-05#section-6.2.4
 *
 * @param[out] session_key the shared session secret if and only if KE3 is valid, size:64
 * @param state_raw a ServerState structure, size:ecc_opaque_ristretto255_sha512_SERVERSTATESIZE
 * @param ke3_raw a KE3 structure, size:ecc_opaque_ristretto255_sha512_KE3SIZE
 * @return 0 if the user was authenticated, else -1
 */
ECC_EXPORT
int ecc_opaque_ristretto255_sha512_3DH_ServerFinish(
    byte_t *session_key,
    const byte_t *state_raw,
    const byte_t *ke3_raw
);

/**
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-05#section-6.2.4
 *
 * @param[out] ke2_raw size:ecc_opaque_ristretto255_sha512_KE2SIZE
 * @param state_raw size:ecc_opaque_ristretto255_sha512_SERVERSTATESIZE
 * @param server_identity size:server_identity_len
 * @param server_identity_len
 * @param server_private_key size:ecc_opaque_ristretto255_sha512_Nsk
 * @param client_identity size:client_identity_len
 * @param client_identity_len
 * @param client_public_key size:ecc_opaque_ristretto255_sha512_Npk
 * @param ke1_raw size:ecc_opaque_ristretto255_sha512_KE1SIZE
 * @param credential_response_raw size:ecc_opaque_ristretto255_sha512_CREDENTIALRESPONSESIZE
 * @param context size:context_len
 * @param context_len
 */
ECC_EXPORT
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
);

#endif // ECC_OPAQUE_H
