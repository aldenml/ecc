/*
 * Copyright (c) 2021-2023, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#ifndef ECC_OPAQUE_H
#define ECC_OPAQUE_H

#include "export.h"

// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-12
// https://github.com/cfrg/draft-irtf-cfrg-opaque

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
 * The size of a serialized OPRF scalar.
 */
#define ecc_opaque_ristretto255_sha512_Ns 32

// const
/**
 * The size of an OPRF private key.
 */
#define ecc_opaque_ristretto255_sha512_Nok 32

// Since there is only one configuration supported, it is
// possible to specify all the internal structures sizes.

// const
/**
 * <pre>
 * struct {
 *   uint8 nonce[Nn];
 *   uint8 auth_tag[Nm];
 * } Envelope;
 * </pre>
 *
 * nonce: A randomly-sampled nonce of length Nn, used to protect this Envelope.
 * auth_tag: An authentication tag protecting the contents of the envelope, covering the envelope nonce and CleartextCredentials.
 */
#define ecc_opaque_ristretto255_sha512_Ne 96

// const
/**
 * In order to avoid dynamic memory allocation, this limit is necessary.
 */
#define ecc_opaque_ristretto255_sha512_PASSWORDMAXSIZE 200

// const
/**
 * In order to avoid dynamic memory allocation, this limit is necessary.
 */
#define ecc_opaque_ristretto255_sha512_IDENTITYMAXSIZE 200

// const
/**
 *
 */
#define ecc_opaque_ristretto255_sha512_CLEARTEXTCREDENTIALSSIZE 434

// const
/**
 * <pre>
 * struct {
 *   uint8 blinded_message[Noe];
 * } RegistrationRequest;
 * </pre>
 *
 * blinded_message: A serialized OPRF group element.
 */
#define ecc_opaque_ristretto255_sha512_REGISTRATIONREQUESTSIZE 32

// const
/**
 * <pre>
 * typedef struct {
 *   uint8 evaluated_message[Noe];
 *   uint8 server_public_key[Npk];
 * } RegistrationResponse;
 * </pre>
 *
 * evaluated_message: A serialized OPRF group element.
 * server_public_key: The server's encoded public key that will be used for the online AKE stage.
 */
#define ecc_opaque_ristretto255_sha512_REGISTRATIONRESPONSESIZE 64

// const
/**
 * <pre>
 * struct {
 *   uint8 client_public_key[Npk];
 *   uint8 masking_key[Nh];
 *   Envelope envelope;
 * } RegistrationRecord;
 * </pre>
 *
 * client_public_key: The client's encoded public key, corresponding to the private key client_private_key.
 * masking_key: An encryption key used by the server to preserve confidentiality of the envelope during login to defend against client enumeration attacks.
 * envelope: The client's Envelope structure.
 */
#define ecc_opaque_ristretto255_sha512_REGISTRATIONRECORDSIZE 192

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
 * <pre>
 * struct {
 *   CredentialRequest credential_request;
 *   AuthRequest auth_request;
 * } KE1;
 * </pre>
 *
 * credential_request: A CredentialRequest structure.
 * auth_request: An AuthRequest structure.
 */
#define ecc_opaque_ristretto255_sha512_KE1SIZE 96

// const
/**
 * <pre>
 * struct {
 *   CredentialResponse credential_response;
 *   AuthResponse auth_response;
 * } KE2;
 * </pre>
 *
 * credential_response: A CredentialResponse structure.
 * auth_response: An AuthResponse structure.
 */
#define ecc_opaque_ristretto255_sha512_KE2SIZE 320

// const
/**
 * <pre>
 * struct {
 *   uint8 client_mac[Nm];
 * } KE3;
 * </pre>
 *
 * client_mac: An authentication tag computed over the handshake transcript of fixed size Nm, computed using Km2.
 */
#define ecc_opaque_ristretto255_sha512_KE3SIZE 64

// const
/**
 * <pre>
 * struct {
 *   uint8 password[PASSWORDMAXSIZE];
 *   uint8 password_len;
 *   uint8 blind[Nok];
 *   ClientAkeState_t client_ake_state;
 * } ClientState;
 * </pre>
 *
 * password: The client's password.
 * blind: The random blinding inverter returned by Blind().
 * client_ake_state: a ClientAkeState structure.
 */
#define ecc_opaque_ristretto255_sha512_CLIENTSTATESIZE 361

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

// const
/**
 * Use Argon2id(t=3,p=1,m=2^16) for the Memory Hard Function (MHF). With this
 * option, the salt should always be of length ecc_opaque_ristretto255_sha512_MHF_ARGON2ID_SALTSIZE.
 */
#define ecc_opaque_ristretto255_sha512_MHF_ARGON2ID 2

// const
/**
 * The length of the salt when using ecc_opaque_ristretto255_sha512_MHF_ARGON2ID.
 */
#define ecc_opaque_ristretto255_sha512_MHF_ARGON2ID_SALTSIZE 16

/**
 * Derive a private and public key pair deterministically from a seed.
 *
 * @param[out] private_key a private key, size:ecc_opaque_ristretto255_sha512_Nsk
 * @param[out] public_key the associated public key, size:ecc_opaque_ristretto255_sha512_Npk
 * @param seed pseudo-random byte sequence used as a seed, size:ecc_opaque_ristretto255_sha512_Nn
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
 * @param randomized_password a randomized password, size:64
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
    const byte_t *randomized_password,
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
 * @param randomized_password a randomized password, size:64
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
    const byte_t *randomized_password,
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
 * @param randomized_password a randomized password, size:64
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
    const byte_t *randomized_password,
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
 * @param[out] private_key a private key, size:ecc_opaque_ristretto255_sha512_Nsk
 * @param[out] public_key the associated public key, size:ecc_opaque_ristretto255_sha512_Npk
 * @param seed size:ecc_opaque_ristretto255_sha512_Nn
 */
ECC_EXPORT
void ecc_opaque_ristretto255_sha512_GenerateAuthKeyPairWithSeed(
    byte_t *private_key, byte_t *public_key,
    const byte_t *seed
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
 * @param seed pseudo-random byte sequence used as a seed, size:ecc_opaque_ristretto255_sha512_Nn
 */
ECC_EXPORT
void ecc_opaque_ristretto255_sha512_DeriveDiffieHellmanKeyPair(
    byte_t *private_key, byte_t *public_key,
    const byte_t *seed
);

/**
 * Same as calling CreateRegistrationRequest with a specified blind.
 *
 * @param[out] request a RegistrationRequest structure, size:ecc_opaque_ristretto255_sha512_REGISTRATIONREQUESTSIZE
 * @param password an opaque byte string containing the client's password, size:password_len
 * @param password_len the length of `password`
 * @param blind the OPRF scalar value to use, size:ecc_opaque_ristretto255_sha512_Ns
 */
ECC_EXPORT
void ecc_opaque_ristretto255_sha512_CreateRegistrationRequestWithBlind(
    byte_t *request,
    const byte_t *password, int password_len,
    const byte_t *blind
);

/**
 * To begin the registration flow, the client executes this function.
 *
 * @param[out] request a RegistrationRequest structure, size:ecc_opaque_ristretto255_sha512_REGISTRATIONREQUESTSIZE
 * @param[out] blind an OPRF scalar value, size:ecc_opaque_ristretto255_sha512_Ns
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
 * To process the client's registration request, the server executes
 * this function.
 *
 * @param[out] response a RegistrationResponse structure, size:ecc_opaque_ristretto255_sha512_REGISTRATIONRESPONSESIZE
 * @param request a RegistrationRequest structure, size:ecc_opaque_ristretto255_sha512_REGISTRATIONREQUESTSIZE
 * @param server_public_key the server's public key, size:ecc_opaque_ristretto255_sha512_Npk
 * @param credential_identifier an identifier that uniquely represents the credential, size:credential_identifier_len
 * @param credential_identifier_len the length of `credential_identifier`
 * @param oprf_seed the seed of Nh bytes used by the server to generate an oprf_key, size:ecc_opaque_ristretto255_sha512_Nh
 */
ECC_EXPORT
void ecc_opaque_ristretto255_sha512_CreateRegistrationResponse(
    byte_t *response,
    const byte_t *request,
    const byte_t *server_public_key,
    const byte_t *credential_identifier, int credential_identifier_len,
    const byte_t *oprf_seed
);

/**
 * Same as calling `ecc_opaque_ristretto255_sha512_FinalizeRegistrationRequest` with an
 * specified `nonce`.
 *
 * @param[out] record a RegistrationUpload structure, size:ecc_opaque_ristretto255_sha512_REGISTRATIONRECORDSIZE
 * @param[out] export_key an additional client key, size:ecc_opaque_ristretto255_sha512_Nh
 * @param password an opaque byte string containing the client's password, size:password_len
 * @param password_len the length of `password`
 * @param blind an OPRF scalar value, size:ecc_opaque_ristretto255_sha512_Ns
 * @param response a RegistrationResponse structure, size:ecc_opaque_ristretto255_sha512_REGISTRATIONRESPONSESIZE
 * @param server_identity the optional encoded server identity, size:server_identity_len
 * @param server_identity_len the length of `server_identity`
 * @param client_identity the optional encoded client identity, size:client_identity_len
 * @param client_identity_len the length of `client_identity`
 * @param mhf the memory hard function to use
 * @param mhf_salt the salt to use in the memory hard function computation, size:mhf_salt_len
 * @param mhf_salt_len the length of `mhf_salt`
 * @param nonce size:ecc_opaque_ristretto255_sha512_Nn
 */
ECC_EXPORT
void ecc_opaque_ristretto255_sha512_FinalizeRegistrationRequestWithNonce(
    byte_t *record,
    byte_t *export_key,
    const byte_t *password, int password_len,
    const byte_t *blind,
    const byte_t *response,
    const byte_t *server_identity, int server_identity_len,
    const byte_t *client_identity, int client_identity_len,
    int mhf,
    const byte_t *mhf_salt, int mhf_salt_len,
    const byte_t *nonce
);

/**
 * To create the user record used for subsequent authentication and complete the
 * registration flow, the client executes the following function.
 *
 * @param[out] record a RegistrationUpload structure, size:ecc_opaque_ristretto255_sha512_REGISTRATIONRECORDSIZE
 * @param[out] export_key an additional client key, size:ecc_opaque_ristretto255_sha512_Nh
 * @param password an opaque byte string containing the client's password, size:password_len
 * @param password_len the length of `password`
 * @param blind an OPRF scalar value, size:ecc_opaque_ristretto255_sha512_Ns
 * @param response a RegistrationResponse structure, size:ecc_opaque_ristretto255_sha512_REGISTRATIONRESPONSESIZE
 * @param server_identity the optional encoded server identity, size:server_identity_len
 * @param server_identity_len the length of `server_identity`
 * @param client_identity the optional encoded client identity, size:client_identity_len
 * @param client_identity_len the length of `client_identity`
 * @param mhf the memory hard function to use
 * @param mhf_salt the salt to use in the memory hard function computation, size:mhf_salt_len
 * @param mhf_salt_len the length of `mhf_salt`
 */
ECC_EXPORT
void ecc_opaque_ristretto255_sha512_FinalizeRegistrationRequest(
    byte_t *record,
    byte_t *export_key,
    const byte_t *password, int password_len,
    const byte_t *blind,
    const byte_t *response,
    const byte_t *server_identity, int server_identity_len,
    const byte_t *client_identity, int client_identity_len,
    int mhf,
    const byte_t *mhf_salt, int mhf_salt_len
);

/**
 *
 * @param[out] request a CredentialRequest structure, size:ecc_opaque_ristretto255_sha512_CREDENTIALREQUESTSIZE
 * @param password an opaque byte string containing the client's password, size:password_len
 * @param password_len the length of `password`
 * @param blind an OPRF scalar value, size:ecc_opaque_ristretto255_sha512_Ns
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
 * @param[out] blind an OPRF scalar value, size:ecc_opaque_ristretto255_sha512_Ns
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
 * @param record_raw size:ecc_opaque_ristretto255_sha512_REGISTRATIONRECORDSIZE
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
 * @param record_raw size:ecc_opaque_ristretto255_sha512_REGISTRATIONRECORDSIZE
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
 * @param mhf_salt the salt to use in the memory hard function computation, size:mhf_salt_len
 * @param mhf_salt_len the length of `mhf_salt`
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
    int mhf,
    const byte_t *mhf_salt, int mhf_salt_len
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
 * @param blind size:ecc_opaque_ristretto255_sha512_Ns
 * @param client_nonce size:ecc_opaque_ristretto255_sha512_Nn
 * @param seed size:ecc_opaque_ristretto255_sha512_Nn
 */
ECC_EXPORT
void ecc_opaque_ristretto255_sha512_GenerateKE1WithSeed(
    byte_t *ke1,
    byte_t *state,
    const byte_t *password, int password_len,
    const byte_t *blind,
    const byte_t *client_nonce,
    const byte_t *seed
);

/**
 *
 * @param[out] ke1 a KE1 message structure, size:ecc_opaque_ristretto255_sha512_KE1SIZE
 * @param[in,out] state a ClientState structure, size:ecc_opaque_ristretto255_sha512_CLIENTSTATESIZE
 * @param password an opaque byte string containing the client's password, size:password_len
 * @param password_len the length of `password`
 */
ECC_EXPORT
void ecc_opaque_ristretto255_sha512_GenerateKE1(
    byte_t *ke1,
    byte_t *state,
    const byte_t *password, int password_len
);

/**
 *
 * @param[out] ke3_raw a KE3 message structure, size:ecc_opaque_ristretto255_sha512_KE3SIZE
 * @param[out] session_key the session's shared secret, size:64
 * @param[out] export_key an additional client key, size:64
 * @param[in,out] state a ClientState structure, size:ecc_opaque_ristretto255_sha512_CLIENTSTATESIZE
 * @param client_identity the optional encoded client identity, which is set
 * to client_public_key if not specified, size:client_identity_len
 * @param client_identity_len the length of `client_identity`
 * @param server_identity the optional encoded server identity, which is set
 * to server_public_key if not specified, size:server_identity_len
 * @param server_identity_len the length of `server_identity`
 * @param ke2 a KE2 message structure, size:ecc_opaque_ristretto255_sha512_KE2SIZE
 * @param mhf the memory hard function to use
 * @param mhf_salt the salt to use in the memory hard function computation, size:mhf_salt_len
 * @param mhf_salt_len the length of `mhf_salt`
 * @param context the application specific context, size:context_len
 * @param context_len the length of `context`
 * @return 0 if is able to recover credentials and authenticate with the server, else -1
 */
ECC_EXPORT
int ecc_opaque_ristretto255_sha512_GenerateKE3(
    byte_t *ke3_raw,
    byte_t *session_key,
    byte_t *export_key,
    byte_t *state,
    const byte_t *client_identity, int client_identity_len,
    const byte_t *server_identity, int server_identity_len,
    const byte_t *ke2,
    int mhf,
    const byte_t *mhf_salt, int mhf_salt_len,
    const byte_t *context, int context_len
);

/**
 *
 * @param[out] ke1 size:ecc_opaque_ristretto255_sha512_KE1SIZE
 * @param[in,out] state size:ecc_opaque_ristretto255_sha512_CLIENTSTATESIZE
 * @param credential_request size:ecc_opaque_ristretto255_sha512_CREDENTIALREQUESTSIZE
 * @param client_nonce size:ecc_opaque_ristretto255_sha512_Nn
 * @param seed size:ecc_opaque_ristretto255_sha512_Nn
 */
ECC_EXPORT
void ecc_opaque_ristretto255_sha512_3DH_StartWithSeed(
    byte_t *ke1,
    byte_t *state,
    const byte_t *credential_request,
    const byte_t *client_nonce,
    const byte_t *seed
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
 * @param record_raw the client's RegistrationUpload structure, size:ecc_opaque_ristretto255_sha512_REGISTRATIONRECORDSIZE
 * @param credential_identifier an identifier that uniquely represents the credential
 * being registered, size:credential_identifier_len
 * @param credential_identifier_len the length of `credential_identifier`
 * @param oprf_seed the server-side seed of Nh bytes used to generate an oprf_key, size:ecc_opaque_ristretto255_sha512_Nh
 * @param ke1_raw a KE1 message structure, size:ecc_opaque_ristretto255_sha512_KE1SIZE
 * @param client_identity the optional encoded server identity, which is set to
 * client_public_key if null, size:client_identity_len
 * @param client_identity_len the length of `client_identity`
 * @param context the application specific context, size:context_len
 * @param context_len the length of `context`
 * @param masking_nonce size:ecc_opaque_ristretto255_sha512_Nn
 * @param server_nonce size:ecc_opaque_ristretto255_sha512_Nn
 * @param seed size:ecc_opaque_ristretto255_sha512_Nn
 */
ECC_EXPORT
void ecc_opaque_ristretto255_sha512_GenerateKE2WithSeed(
    byte_t *ke2_raw,
    byte_t *state_raw,
    const byte_t *server_identity, int server_identity_len,
    const byte_t *server_private_key,
    const byte_t *server_public_key,
    const byte_t *record_raw,
    const byte_t *credential_identifier, int credential_identifier_len,
    const byte_t *oprf_seed,
    const byte_t *ke1_raw,
    const byte_t *client_identity, int client_identity_len,
    const byte_t *context, int context_len,
    const byte_t *masking_nonce,
    const byte_t *server_nonce,
    const byte_t *seed
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
 * @param record_raw the client's RegistrationUpload structure, size:ecc_opaque_ristretto255_sha512_REGISTRATIONRECORDSIZE
 * @param credential_identifier an identifier that uniquely represents the credential
 * being registered, size:credential_identifier_len
 * @param credential_identifier_len the length of `credential_identifier`
 * @param oprf_seed the server-side seed of Nh bytes used to generate an oprf_key, size:ecc_opaque_ristretto255_sha512_Nh
 * @param ke1_raw a KE1 message structure, size:ecc_opaque_ristretto255_sha512_KE1SIZE
 * @param client_identity the optional encoded server identity, which is set to
 * client_public_key if null, size:client_identity_len
 * @param client_identity_len the length of `client_identity`
 * @param context the application specific context, size:context_len
 * @param context_len the length of `context`
 */
ECC_EXPORT
void ecc_opaque_ristretto255_sha512_GenerateKE2(
    byte_t *ke2_raw,
    byte_t *state_raw,
    const byte_t *server_identity, int server_identity_len,
    const byte_t *server_private_key,
    const byte_t *server_public_key,
    const byte_t *record_raw,
    const byte_t *credential_identifier, int credential_identifier_len,
    const byte_t *oprf_seed,
    const byte_t *ke1_raw,
    const byte_t *client_identity, int client_identity_len,
    const byte_t *context, int context_len
);

/**
 *
 * @param[out] session_key the shared session secret if and only if KE3 is valid, size:64
 * @param[in,out] state a ServerState structure, size:ecc_opaque_ristretto255_sha512_SERVERSTATESIZE
 * @param ke3 a KE3 structure, size:ecc_opaque_ristretto255_sha512_KE3SIZE
 * @return 0 if the user was authenticated, else -1
 */
ECC_EXPORT
int ecc_opaque_ristretto255_sha512_ServerFinish(
    byte_t *session_key,
    byte_t *state,
    const byte_t *ke3
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
 * @param seed size:ecc_opaque_ristretto255_sha512_Nn
 */
ECC_EXPORT
void ecc_opaque_ristretto255_sha512_3DH_ResponseWithSeed(
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
    const byte_t *seed
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
