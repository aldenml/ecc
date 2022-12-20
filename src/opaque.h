/*
 * Copyright (c) 2021-2022, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#ifndef ECC_OPAQUE_H
#define ECC_OPAQUE_H

#include "export.h"

// See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-09
//
// This implements only the following configuration:
//
// OPRF(ristretto255, SHA-512), HKDF-SHA-512, HMAC-SHA-512, SHA-512,
// MHF=Identity or Scrypt(32768,8,1), internal, ristretto255
//
// In order to work with stack allocated memory (i.e. fixed and not dynamic
// allocation), it's necessary to add the restriction on the length of the
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
#define ecc_opaque_ristretto255_sha512_IDENTITYMAXSIZE 200

// const
/**
 *
 */
#define ecc_opaque_ristretto255_sha512_CLEARTEXTCREDENTIALSSIZE 440

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

// const
/**
 * Use Identity for the Memory Hard Function (MHF).
 */
#define ecc_opaque_ristretto255_sha512_MHF_IDENTITY 0

// const
/**
 * Use Scrypt(32768,8,1) for the Memory Hard Function (MHF).
 */
#define ecc_opaque_ristretto255_sha512_MHF_SCRYPT 1

/**
 * Derive a private and public key pair deterministically from a seed.
 *
 * @param[out] private_key a private key, size:ecc_opaque_ristretto255_sha512_Nsk
 * @param[out] public_key the associated public key, size:ecc_opaque_ristretto255_sha512_Npk
 * @param seed pseudo-random byte sequence used as a seed, size:ecc_opaque_ristretto255_sha512_Nok
 */
ECC_EXPORT
void ecc_opaque_ristretto255_sha512_DeriveKeyPair(
    byte_t *private_key,
    byte_t *public_key,
    const byte_t *seed
);

/**
 * Constructs a "CleartextCredentials" structure given application
 * credential information.
 *
 * @param[out] cleartext_credentials a CleartextCredentials structure, size:ecc_opaque_ristretto255_sha512_CLEARTEXTCREDENTIALSSIZE
 * @param server_public_key the encoded server public key for the AKE protocol, size:ecc_opaque_ristretto255_sha512_Npk
 * @param client_public_key the encoded client public key for the AKE protocol, size:ecc_opaque_ristretto255_sha512_Npk
 * @param server_identity the optional encoded server identity, size:server_identity_len
 * @param server_identity_len the length of `server_identity`
 * @param client_identity the optional encoded client identity, size:client_identity_len
 * @param client_identity_len the length of `client_identity`
 */
ECC_EXPORT
void ecc_opaque_ristretto255_sha512_CreateCleartextCredentials(
    byte_t *cleartext_credentials,
    const byte_t *server_public_key,
    const byte_t *client_public_key,
    const byte_t *server_identity, int server_identity_len,
    const byte_t *client_identity, int client_identity_len
);

/**
 * Same as calling `ecc_opaque_ristretto255_sha512_EnvelopeStore` with an
 * specified `nonce`.
 *
 * @param[out] envelope size:ecc_opaque_ristretto255_sha512_Ne
 * @param[out] client_public_key size:ecc_opaque_ristretto255_sha512_Npk
 * @param[out] masking_key size:ecc_opaque_ristretto255_sha512_Nh
 * @param[out] export_key size:ecc_opaque_ristretto255_sha512_Nh
 * @param randomized_pwd size:64
 * @param server_public_key size:ecc_opaque_ristretto255_sha512_Npk
 * @param server_identity size:server_identity_len
 * @param server_identity_len the length of `server_identity`
 * @param client_identity size:client_identity_len
 * @param client_identity_len the length of `client_identity`
 * @param nonce size:ecc_opaque_ristretto255_sha512_Nn
 */
ECC_EXPORT
void ecc_opaque_ristretto255_sha512_EnvelopeStoreWithNonce(
    byte_t *envelope,
    byte_t *client_public_key,
    byte_t *masking_key,
    byte_t *export_key,
    const byte_t *randomized_pwd,
    const byte_t *server_public_key,
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
 * @param[out] envelope size:ecc_opaque_ristretto255_sha512_Ne
 * @param[out] client_public_key size:ecc_opaque_ristretto255_sha512_Npk
 * @param[out] masking_key size:ecc_opaque_ristretto255_sha512_Nh
 * @param[out] export_key size:ecc_opaque_ristretto255_sha512_Nh
 * @param randomized_pwd size:64
 * @param server_public_key size:ecc_opaque_ristretto255_sha512_Npk
 * @param server_identity size:server_identity_len
 * @param server_identity_len the length of `server_identity`
 * @param client_identity size:client_identity_len
 * @param client_identity_len the length of `client_identity`
 */
ECC_EXPORT
void ecc_opaque_ristretto255_sha512_EnvelopeStore(
    byte_t *envelope,
    byte_t *client_public_key,
    byte_t *masking_key,
    byte_t *export_key,
    const byte_t *randomized_pwd,
    const byte_t *server_public_key,
    const byte_t *server_identity, int server_identity_len,
    const byte_t *client_identity, int client_identity_len
);

/**
 * This functions attempts to recover the credentials from the input. On
 * success returns 0, else -1.
 *
 * @param[out] client_private_key size:ecc_opaque_ristretto255_sha512_Nsk
 * @param[out] export_key size:ecc_opaque_ristretto255_sha512_Nh
 * @param randomized_pwd size:64
 * @param server_public_key size:ecc_opaque_ristretto255_sha512_Npk
 * @param envelope_raw size:ecc_opaque_ristretto255_sha512_Ne
 * @param server_identity size:server_identity_len
 * @param server_identity_len the length of `server_identity`
 * @param client_identity size:client_identity_len
 * @param client_identity_len the length of `client_identity`
 * @return on success returns 0, else -1.
 */
ECC_EXPORT
int ecc_opaque_ristretto255_sha512_EnvelopeRecover(
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
 * @param[out] private_key a private key, size:ecc_opaque_ristretto255_sha512_Nsk
 * @param[out] public_key the associated public key, size:ecc_opaque_ristretto255_sha512_Npk
 * @param seed pseudo-random byte sequence used as a seed, size:ecc_opaque_ristretto255_sha512_Nok
 */
ECC_EXPORT
void ecc_opaque_ristretto255_sha512_DeriveAuthKeyPair(
    byte_t *private_key, byte_t *public_key,
    const byte_t *seed
);

/**
 * Same as calling CreateRegistrationRequest with a specified blind.
 *
 * @param[out] request a RegistrationRequest structure, size:ecc_opaque_ristretto255_sha512_REGISTRATIONREQUESTSIZE
 * @param password an opaque byte string containing the client's password, size:password_len
 * @param password_len the length of `password`
 * @param blind the OPRF scalar value to use, size:ecc_opaque_ristretto255_sha512_Noe
 */
ECC_EXPORT
void ecc_opaque_ristretto255_sha512_CreateRegistrationRequestWithBlind(
    byte_t *request,
    const byte_t *password, int password_len,
    const byte_t *blind
);

/**
 *
 * @param[out] request a RegistrationRequest structure, size:ecc_opaque_ristretto255_sha512_REGISTRATIONREQUESTSIZE
 * @param[out] blind an OPRF scalar value, size:ecc_opaque_ristretto255_sha512_Noe
 * @param password an opaque byte string containing the client's password, size:password_len
 * @param password_len the length of `password`
 */
ECC_EXPORT
void ecc_opaque_ristretto255_sha512_CreateRegistrationRequest(
    byte_t *request,
    byte_t *blind, // 32
    const byte_t *password, int password_len
);

/**
 * Same as calling CreateRegistrationResponse with a specific oprf_seed.
 *
 * In order to make this method not to use dynamic memory allocation, there is a
 * limit of credential_identifier_len <= 200.
 *
 * @param[out] response size:ecc_opaque_ristretto255_sha512_REGISTRATIONRESPONSESIZE
 * @param request size:ecc_opaque_ristretto255_sha512_REGISTRATIONREQUESTSIZE
 * @param server_public_key size:ecc_opaque_ristretto255_sha512_Npk
 * @param credential_identifier size:credential_identifier_len
 * @param credential_identifier_len the length of `credential_identifier`
 * @param oprf_key size:32
 */
ECC_EXPORT
void ecc_opaque_ristretto255_sha512_CreateRegistrationResponseWithOprfKey(
    byte_t *response,
    const byte_t *request,
    const byte_t *server_public_key,
    const byte_t *credential_identifier, int credential_identifier_len,
    const byte_t *oprf_key
);

/**
 * In order to make this method not to use dynamic memory allocation, there is a
 * limit of credential_identifier_len <= 200.
 *
 * @param[out] response a RegistrationResponse structure, size:ecc_opaque_ristretto255_sha512_REGISTRATIONRESPONSESIZE
 * @param[out] oprf_key the per-client OPRF key known only to the server, size:ecc_opaque_ristretto255_sha512_Nsk
 * @param request a RegistrationRequest structure, size:ecc_opaque_ristretto255_sha512_REGISTRATIONREQUESTSIZE
 * @param server_public_key the server's public key, size:ecc_opaque_ristretto255_sha512_Npk
 * @param credential_identifier an identifier that uniquely represents the credential being registered, size:credential_identifier_len
 * @param credential_identifier_len the length of `credential_identifier`
 * @param oprf_seed the server-side seed of Nh bytes used to generate an oprf_key, size:ecc_opaque_ristretto255_sha512_Nh
 */
ECC_EXPORT
void ecc_opaque_ristretto255_sha512_CreateRegistrationResponse(
    byte_t *response,
    byte_t *oprf_key,
    const byte_t *request,
    const byte_t *server_public_key,
    const byte_t *credential_identifier, int credential_identifier_len,
    const byte_t *oprf_seed
);

/**
 * Same as calling `ecc_opaque_ristretto255_sha512_FinalizeRequest` with an
 * specified `nonce`.
 *
 * To create the user record used for further authentication, the client
 * executes the following function. Since this works in the internal key mode, the
 * "client_private_key" is null.
 *
 * @param[out] record a RegistrationUpload structure, size:ecc_opaque_ristretto255_sha512_REGISTRATIONUPLOADSIZE
 * @param[out] export_key an additional client key, size:ecc_opaque_ristretto255_sha512_Nh
 * @param password an opaque byte string containing the client's password, size:password_len
 * @param password_len the length of `password`
 * @param blind the OPRF scalar value used for blinding, size:ecc_opaque_ristretto255_sha512_Noe
 * @param response a RegistrationResponse structure, size:ecc_opaque_ristretto255_sha512_REGISTRATIONRESPONSESIZE
 * @param server_identity the optional encoded server identity, size:server_identity_len
 * @param server_identity_len the length of `server_identity`
 * @param client_identity the optional encoded client identity, size:client_identity_len
 * @param client_identity_len the length of `client_identity`
 * @param mhf the memory hard function to use
 * @param nonce size:ecc_opaque_ristretto255_sha512_Nn
 */
ECC_EXPORT
void ecc_opaque_ristretto255_sha512_FinalizeRequestWithNonce(
    byte_t *record, // RegistrationUpload_t
    byte_t *export_key,
    const byte_t *password, int password_len,
    const byte_t *blind,
    const byte_t *response, // RegistrationResponse_t
    const byte_t *server_identity, int server_identity_len,
    const byte_t *client_identity, int client_identity_len,
    int mhf,
    const byte_t *nonce
);

/**
 * To create the user record used for further authentication, the client
 * executes the following function. Since this works in the internal key mode, the
 * "client_private_key" is null.
 *
 * @param[out] record a RegistrationUpload structure, size:ecc_opaque_ristretto255_sha512_REGISTRATIONUPLOADSIZE
 * @param[out] export_key an additional client key, size:ecc_opaque_ristretto255_sha512_Nh
 * @param password an opaque byte string containing the client's password, size:password_len
 * @param password_len the length of `password`
 * @param blind the OPRF scalar value used for blinding, size:ecc_opaque_ristretto255_sha512_Noe
 * @param response a RegistrationResponse structure, size:ecc_opaque_ristretto255_sha512_REGISTRATIONRESPONSESIZE
 * @param server_identity the optional encoded server identity, size:server_identity_len
 * @param server_identity_len the length of `server_identity`
 * @param client_identity the optional encoded client identity, size:client_identity_len
 * @param client_identity_len the length of `client_identity`
 * @param mhf the memory hard function to use
 */
ECC_EXPORT
void ecc_opaque_ristretto255_sha512_FinalizeRequest(
    byte_t *record, // RegistrationUpload_t
    byte_t *export_key,
    const byte_t *password, int password_len,
    const byte_t *blind,
    const byte_t *response, // RegistrationResponse_t
    const byte_t *server_identity, int server_identity_len,
    const byte_t *client_identity, int client_identity_len,
    int mhf
);

/**
 *
 * @param[out] request a CredentialRequest structure, size:ecc_opaque_ristretto255_sha512_CREDENTIALREQUESTSIZE
 * @param password an opaque byte string containing the client's password, size:password_len
 * @param password_len the length of `password`
 * @param blind an OPRF scalar value, size:ecc_opaque_ristretto255_sha512_Noe
 */
ECC_EXPORT
void ecc_opaque_ristretto255_sha512_CreateCredentialRequestWithBlind(
    byte_t *request,
    const byte_t *password, int password_len,
    const byte_t *blind
);

/**
 *
 * @param[out] request a CredentialRequest structure, size:ecc_opaque_ristretto255_sha512_CREDENTIALREQUESTSIZE
 * @param[out] blind an OPRF scalar value, size:ecc_opaque_ristretto255_sha512_Noe
 * @param password an opaque byte string containing the client's password, size:password_len
 * @param password_len the length of `password`
 */
ECC_EXPORT
void ecc_opaque_ristretto255_sha512_CreateCredentialRequest(
    byte_t *request,
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
 * @param[out] response_raw size:ecc_opaque_ristretto255_sha512_CREDENTIALRESPONSESIZE
 * @param request_raw size:ecc_opaque_ristretto255_sha512_CREDENTIALREQUESTSIZE
 * @param server_public_key size:ecc_opaque_ristretto255_sha512_Npk
 * @param record_raw size:ecc_opaque_ristretto255_sha512_REGISTRATIONUPLOADSIZE
 * @param credential_identifier size:credential_identifier_len
 * @param credential_identifier_len the length of `credential_identifier`
 * @param oprf_seed size:ecc_opaque_ristretto255_sha512_Nh
 * @param masking_nonce size:ecc_opaque_ristretto255_sha512_Nn
 */
ECC_EXPORT
void ecc_opaque_ristretto255_sha512_CreateCredentialResponseWithMasking(
    byte_t *response_raw,
    const byte_t *request_raw,
    const byte_t *server_public_key,
    const byte_t *record_raw,
    const byte_t *credential_identifier, int credential_identifier_len,
    const byte_t *oprf_seed,
    const byte_t *masking_nonce
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
 * @param[out] response_raw size:ecc_opaque_ristretto255_sha512_CREDENTIALRESPONSESIZE
 * @param request_raw size:ecc_opaque_ristretto255_sha512_CREDENTIALREQUESTSIZE
 * @param server_public_key size:ecc_opaque_ristretto255_sha512_Npk
 * @param record_raw size:ecc_opaque_ristretto255_sha512_REGISTRATIONUPLOADSIZE
 * @param credential_identifier size:credential_identifier_len
 * @param credential_identifier_len the length of `credential_identifier`
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
 *
 * @param[out] client_private_key size:ecc_opaque_ristretto255_sha512_Nsk
 * @param[out] server_public_key size:ecc_opaque_ristretto255_sha512_Npk
 * @param[out] export_key size:ecc_opaque_ristretto255_sha512_Nh
 * @param password size:password_len
 * @param password_len the length of `password`
 * @param blind size:ecc_opaque_ristretto255_sha512_Noe
 * @param response size:ecc_opaque_ristretto255_sha512_CREDENTIALRESPONSESIZE
 * @param server_identity size:server_identity_len
 * @param server_identity_len the length of `server_identity`
 * @param client_identity size:client_identity_len
 * @param client_identity_len the length of `client_identity`
 * @param mhf the memory hard function to use
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
    const byte_t *client_identity, int client_identity_len,
    int mhf
);

/**
 *
 * @param[out] out size:length
 * @param secret size:64
 * @param label size:label_len
 * @param label_len the length of `label`
 * @param context size:context_len
 * @param context_len the length of `context`
 * @param length the length of the output
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
 *
 * @param[out] out size:ecc_opaque_ristretto255_sha512_Nx
 * @param secret size:64
 * @param label size:label_len
 * @param label_len the length of `label`
 * @param transcript_hash size:transcript_hash_len
 * @param transcript_hash_len the length of `transcript_hash`
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
 * @param[out] preamble the protocol transcript with identities and messages, size:preamble_len
 * @param preamble_len the length of `preamble`
 * @param context optional shared context information, size:context_len
 * @param context_len the length of `context`
 * @param client_identity the optional encoded client identity, size:client_identity_len
 * @param client_identity_len the length of `client_identity`
 * @param client_public_key size:ecc_opaque_ristretto255_sha512_Npk
 * @param ke1 a KE1 message structure, size:ecc_opaque_ristretto255_sha512_KE1SIZE
 * @param server_identity the optional encoded server identity, size:server_identity_len
 * @param server_identity_len the length of `server_identity`
 * @param server_public_key size:ecc_opaque_ristretto255_sha512_Npk
 * @param ke2 a ke2 structure as defined in KE2, size:ecc_opaque_ristretto255_sha512_KE2SIZE
 * @return the protocol transcript with identities and messages
 */
ECC_EXPORT
int ecc_opaque_ristretto255_sha512_3DH_Preamble(
    byte_t *preamble,
    int preamble_len,
    const byte_t *context, int context_len,
    const byte_t *client_identity, int client_identity_len,
    const byte_t *client_public_key,
    const byte_t *ke1,
    const byte_t *server_identity, int server_identity_len,
    const byte_t *server_public_key,
    const byte_t *ke2
);

/**
 * Computes the OPAQUE-3DH shared secret derived during the key
 * exchange protocol.
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
 *
 * @param[out] km2 size:64
 * @param[out] km3 size:64
 * @param[out] session_key size:64
 * @param ikm size:ikm_len
 * @param ikm_len the length of `ikm`
 * @param preamble size:preamble_len
 * @param preamble_len the length of `preamble`
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
 *
 * @param[out] ke1 a KE1 message structure, size:ecc_opaque_ristretto255_sha512_KE1SIZE
 * @param[in,out] state a ClientState structure, size:ecc_opaque_ristretto255_sha512_CLIENTSTATESIZE
 * @param password an opaque byte string containing the client's password, size:password_len
 * @param password_len the length of `password`
 * @param blind size:ecc_opaque_ristretto255_sha512_Noe
 * @param client_nonce size:ecc_opaque_ristretto255_sha512_Nn
 * @param client_secret size:ecc_opaque_ristretto255_sha512_Nsk
 * @param client_keyshare size:ecc_opaque_ristretto255_sha512_Npk
 */
ECC_EXPORT
void ecc_opaque_ristretto255_sha512_3DH_ClientInitWithSecrets(
    byte_t *ke1,
    byte_t *state,
    const byte_t *password, int password_len,
    const byte_t *blind,
    const byte_t *client_nonce,
    const byte_t *client_secret,
    const byte_t *client_keyshare
);

/**
 *
 * @param[out] ke1 a KE1 message structure, size:ecc_opaque_ristretto255_sha512_KE1SIZE
 * @param[in,out] state a ClientState structure, size:ecc_opaque_ristretto255_sha512_CLIENTSTATESIZE
 * @param password an opaque byte string containing the client's password, size:password_len
 * @param password_len the length of `password`
 */
ECC_EXPORT
void ecc_opaque_ristretto255_sha512_3DH_ClientInit(
    byte_t *ke1,
    byte_t *state,
    const byte_t *password, int password_len
);

/**
 *
 * @param[out] ke3_raw a KE3 message structure, size:ecc_opaque_ristretto255_sha512_KE3SIZE
 * @param[out] session_key the session's shared secret, size:64
 * @param[out] export_key an additional client key, size:64
 * @param[in,out] state_raw a ClientState structure, size:ecc_opaque_ristretto255_sha512_CLIENTSTATESIZE
 * @param password an opaque byte string containing the client's password, size:password_len
 * @param password_len the length of `password`
 * @param client_identity the optional encoded client identity, which is set
 * to client_public_key if not specified, size:client_identity_len
 * @param client_identity_len the length of `client_identity`
 * @param server_identity the optional encoded server identity, which is set
 * to server_public_key if not specified, size:server_identity_len
 * @param server_identity_len the length of `server_identity`
 * @param ke2 a KE2 message structure, size:ecc_opaque_ristretto255_sha512_KE2SIZE
 * @param mhf the memory hard function to use
 * @param context the application specific context, size:context_len
 * @param context_len the length of `context`
 * @return 0 if is able to recover credentials and authenticate with the server, else -1
 */
ECC_EXPORT
int ecc_opaque_ristretto255_sha512_3DH_ClientFinish(
    byte_t *ke3_raw,
    byte_t *session_key,
    byte_t *export_key,
    byte_t *state_raw,
    const byte_t *password, int password_len,
    const byte_t *client_identity, int client_identity_len,
    const byte_t *server_identity, int server_identity_len,
    const byte_t *ke2,
    int mhf,
    const byte_t *context, int context_len
);

/**
 *
 * @param[out] ke1 size:ecc_opaque_ristretto255_sha512_KE1SIZE
 * @param[in,out] state size:ecc_opaque_ristretto255_sha512_CLIENTSTATESIZE
 * @param credential_request size:ecc_opaque_ristretto255_sha512_CREDENTIALREQUESTSIZE
 * @param client_nonce size:ecc_opaque_ristretto255_sha512_Nn
 * @param client_secret size:ecc_opaque_ristretto255_sha512_Nsk
 * @param client_keyshare size:ecc_opaque_ristretto255_sha512_Npk
 */
ECC_EXPORT
void ecc_opaque_ristretto255_sha512_3DH_StartWithSecrets(
    byte_t *ke1,
    byte_t *state,
    const byte_t *credential_request,
    const byte_t *client_nonce,
    const byte_t *client_secret,
    const byte_t *client_keyshare
);

/**
 *
 * @param[out] ke1 size:ecc_opaque_ristretto255_sha512_KE1SIZE
 * @param[in,out] state size:ecc_opaque_ristretto255_sha512_CLIENTSTATESIZE
 * @param credential_request size:ecc_opaque_ristretto255_sha512_CREDENTIALREQUESTSIZE
 */
ECC_EXPORT
void ecc_opaque_ristretto255_sha512_3DH_Start(
    byte_t *ke1,
    byte_t *state,
    const byte_t *credential_request
);

/**
 *
 * @param[out] ke3_raw size:ecc_opaque_ristretto255_sha512_KE3SIZE
 * @param[out] session_key size:64
 * @param[in,out] state_raw size:ecc_opaque_ristretto255_sha512_CLIENTSTATESIZE
 * @param client_identity size:client_identity_len
 * @param client_identity_len the length of `client_identity`
 * @param client_private_key size:ecc_opaque_ristretto255_sha512_Nsk
 * @param server_identity size:server_identity_len
 * @param server_identity_len the lenght of `server_identity`
 * @param server_public_key size:ecc_opaque_ristretto255_sha512_Npk
 * @param ke2_raw size:ecc_opaque_ristretto255_sha512_KE2SIZE
 * @param context the application specific context, size:context_len
 * @param context_len the length of `context`
 * @return 0 if success, else -1
 */
ECC_EXPORT
int ecc_opaque_ristretto255_sha512_3DH_ClientFinalize(
    byte_t *ke3_raw,
    byte_t *session_key,
    byte_t *state_raw,
    const byte_t *client_identity, int client_identity_len,
    const byte_t *client_private_key,
    const byte_t *server_identity, int server_identity_len,
    const byte_t *server_public_key,
    const byte_t *ke2_raw,
    const byte_t *context, int context_len
);

/**
 *
 * @param[out] ke2_raw a KE2 structure, size:ecc_opaque_ristretto255_sha512_KE2SIZE
 * @param[in,out] state_raw a ServerState structure, size:ecc_opaque_ristretto255_sha512_SERVERSTATESIZE
 * @param server_identity the optional encoded server identity, which is set to
 * server_public_key if null, size:server_identity_len
 * @param server_identity_len the length of `server_identity`
 * @param server_private_key the server's private key, size:ecc_opaque_ristretto255_sha512_Nsk
 * @param server_public_key the server's public key, size:ecc_opaque_ristretto255_sha512_Npk
 * @param client_identity the optional encoded server identity, which is set to
 * client_public_key if null, size:client_identity_len
 * @param client_identity_len the length of `client_identity`
 * @param record_raw the client's RegistrationUpload structure, size:ecc_opaque_ristretto255_sha512_REGISTRATIONUPLOADSIZE
 * @param credential_identifier an identifier that uniquely represents the credential
 * being registered, size:credential_identifier_len
 * @param credential_identifier_len the length of `credential_identifier`
 * @param oprf_seed the server-side seed of Nh bytes used to generate an oprf_key, size:ecc_opaque_ristretto255_sha512_Nh
 * @param ke1_raw a KE1 message structure, size:ecc_opaque_ristretto255_sha512_KE1SIZE
 * @param context the application specific context, size:context_len
 * @param context_len the length of `context`
 * @param masking_nonce size:ecc_opaque_ristretto255_sha512_Nn
 * @param server_nonce size:ecc_opaque_ristretto255_sha512_Nn
 * @param server_secret size:ecc_opaque_ristretto255_sha512_Nsk
 * @param server_keyshare size:ecc_opaque_ristretto255_sha512_Npk
 */
ECC_EXPORT
void ecc_opaque_ristretto255_sha512_3DH_ServerInitWithSecrets(
    byte_t *ke2_raw,
    byte_t *state_raw,
    const byte_t *server_identity, int server_identity_len,
    const byte_t *server_private_key,
    const byte_t *server_public_key,
    const byte_t *client_identity, int client_identity_len,
    const byte_t *record_raw,
    const byte_t *credential_identifier, int credential_identifier_len,
    const byte_t *oprf_seed,
    const byte_t *ke1_raw,
    const byte_t *context, int context_len,
    const byte_t *masking_nonce,
    const byte_t *server_nonce,
    const byte_t *server_secret,
    const byte_t *server_keyshare
);

/**
 *
 * @param[out] ke2_raw a KE2 structure, size:ecc_opaque_ristretto255_sha512_KE2SIZE
 * @param[in,out] state_raw a ServerState structure, size:ecc_opaque_ristretto255_sha512_SERVERSTATESIZE
 * @param server_identity the optional encoded server identity, which is set to
 * server_public_key if null, size:server_identity_len
 * @param server_identity_len the length of `server_identity`
 * @param server_private_key the server's private key, size:ecc_opaque_ristretto255_sha512_Nsk
 * @param server_public_key the server's public key, size:ecc_opaque_ristretto255_sha512_Npk
 * @param client_identity the optional encoded server identity, which is set to
 * client_public_key if null, size:client_identity_len
 * @param client_identity_len the length of `client_identity`
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
    byte_t *state_raw,
    const byte_t *server_identity, int server_identity_len,
    const byte_t *server_private_key,
    const byte_t *server_public_key,
    const byte_t *client_identity, int client_identity_len,
    const byte_t *record_raw,
    const byte_t *credential_identifier, int credential_identifier_len,
    const byte_t *oprf_seed,
    const byte_t *ke1_raw,
    const byte_t *context, int context_len
);

/**
 *
 * @param[out] session_key the shared session secret if and only if KE3 is valid, size:64
 * @param[in,out] state_raw a ServerState structure, size:ecc_opaque_ristretto255_sha512_SERVERSTATESIZE
 * @param ke3_raw a KE3 structure, size:ecc_opaque_ristretto255_sha512_KE3SIZE
 * @return 0 if the user was authenticated, else -1
 */
ECC_EXPORT
int ecc_opaque_ristretto255_sha512_3DH_ServerFinish(
    byte_t *session_key,
    byte_t *state_raw,
    const byte_t *ke3_raw
);

/**
 *
 * @param[out] ke2_raw size:ecc_opaque_ristretto255_sha512_KE2SIZE
 * @param[in,out] state_raw size:ecc_opaque_ristretto255_sha512_SERVERSTATESIZE
 * @param server_identity size:server_identity_len
 * @param server_identity_len the length of `server_identity`
 * @param server_private_key size:ecc_opaque_ristretto255_sha512_Nsk
 * @param server_public_key size:ecc_opaque_ristretto255_sha512_Npk
 * @param client_identity size:client_identity_len
 * @param client_identity_len the length of `client_identity`
 * @param client_public_key size:ecc_opaque_ristretto255_sha512_Npk
 * @param ke1_raw size:ecc_opaque_ristretto255_sha512_KE1SIZE
 * @param credential_response_raw size:ecc_opaque_ristretto255_sha512_CREDENTIALRESPONSESIZE
 * @param context size:context_len
 * @param context_len the length of `context`
 * @param server_nonce size:ecc_opaque_ristretto255_sha512_Nn
 * @param server_secret size:ecc_opaque_ristretto255_sha512_Nsk
 * @param server_keyshare size:ecc_opaque_ristretto255_sha512_Npk
 */
ECC_EXPORT
void ecc_opaque_ristretto255_sha512_3DH_ResponseWithSecrets(
    byte_t *ke2_raw,
    byte_t *state_raw,
    const byte_t *server_identity, int server_identity_len,
    const byte_t *server_private_key,
    const byte_t *server_public_key,
    const byte_t *client_identity, int client_identity_len,
    const byte_t *client_public_key,
    const byte_t *ke1_raw,
    const byte_t *credential_response_raw,
    const byte_t *context, int context_len,
    const byte_t *server_nonce,
    const byte_t *server_secret,
    const byte_t *server_keyshare
);

/**
 *
 * @param[out] ke2_raw size:ecc_opaque_ristretto255_sha512_KE2SIZE
 * @param[in,out] state_raw size:ecc_opaque_ristretto255_sha512_SERVERSTATESIZE
 * @param server_identity size:server_identity_len
 * @param server_identity_len the length of `server_identity`
 * @param server_private_key size:ecc_opaque_ristretto255_sha512_Nsk
 * @param server_public_key size:ecc_opaque_ristretto255_sha512_Npk
 * @param client_identity size:client_identity_len
 * @param client_identity_len the length of `client_identity`
 * @param client_public_key size:ecc_opaque_ristretto255_sha512_Npk
 * @param ke1_raw size:ecc_opaque_ristretto255_sha512_KE1SIZE
 * @param credential_response_raw size:ecc_opaque_ristretto255_sha512_CREDENTIALRESPONSESIZE
 * @param context size:context_len
 * @param context_len the length of `context`
 */
ECC_EXPORT
void ecc_opaque_ristretto255_sha512_3DH_Response(
    byte_t *ke2_raw,
    byte_t *state_raw,
    const byte_t *server_identity, int server_identity_len,
    const byte_t *server_private_key,
    const byte_t *server_public_key,
    const byte_t *client_identity, int client_identity_len,
    const byte_t *client_public_key,
    const byte_t *ke1_raw,
    const byte_t *credential_response_raw,
    const byte_t *context, int context_len
);

#endif // ECC_OPAQUE_H
