/**
 * Recover the public key related to the input "private_key".
 *
 * @param {Uint8Array} privateKey
 * @return {Uint8Array}
 */
export function opaque_RecoverPublicKey(privateKey: Uint8Array): Uint8Array;
/**
 * Returns a randomly generated private and public key pair.
 *
 * This is implemented by generating a random "seed", then
 * calling internally DeriveAuthKeyPair.
 *
 * @return object {private_key, public_key}
 */
export function opaque_GenerateAuthKeyPair(): {
    privateKey: Uint8Array;
    publicKey: Uint8Array;
};
/**
 * @param {Uint8Array} password an opaque byte string containing the client's password
 * @param {Uint8Array} blind the OPRF scalar value to use, size:ecc_opaque_ristretto255_sha512_Ns
 * @return object {request, blind}
 */
export function opaque_CreateRegistrationRequestWithBlind(password: Uint8Array, blind: Uint8Array): {
    registrationRequest: Uint8Array;
    blind: Uint8Array;
};
/**
 * @param {Uint8Array} password an opaque byte string containing the client's password
 * @return object {request, blind}
 */
export function opaque_CreateRegistrationRequest(password: Uint8Array): {
    registrationRequest: Uint8Array;
    blind: Uint8Array;
};
/**
 * In order to make this method not to use dynamic memory allocation, there is a
 * limit of credential_identifier to length <= 200.
 *
 * @param {Uint8Array} request a RegistrationRequest structure
 * @param {Uint8Array} server_public_key the server's public key
 * @param {Uint8Array} credential_identifier an identifier that uniquely represents the credential being registered
 * @param {Uint8Array} oprf_seed the server-side seed of Nh bytes used to generate an oprf_key
 * @return {Uint8Array}
 */
export function opaque_CreateRegistrationResponse(request: Uint8Array, server_public_key: Uint8Array, credential_identifier: Uint8Array, oprf_seed: Uint8Array): Uint8Array;
/**
 * To create the user record used for further authentication, the client
 * executes the following function.
 *
 * @param {Uint8Array} password an opaque byte string containing the client's password
 * @param {Uint8Array} blind the OPRF scalar value used for blinding
 * @param {Uint8Array} response_raw a RegistrationResponse structure
 * @param {Uint8Array} server_identity the optional encoded server identity
 * @param {Uint8Array} client_identity the optional encoded client identity
 * @param {number} mhf the memory hard function to use
 * @param {Uint8Array} nonce size:ecc_opaque_ristretto255_sha512_Nn
 * @return object {record, exportKey}
 */
export function opaque_FinalizeRegistrationRequestWithNonce(password: Uint8Array, blind: Uint8Array, response_raw: Uint8Array, server_identity: Uint8Array, client_identity: Uint8Array, mhf: number, nonce: Uint8Array): {
    registrationRecord: Uint8Array;
    exportKey: Uint8Array;
};
/**
 * To create the user record used for further authentication, the client
 * executes the following function.
 *
 * @param {Uint8Array} password an opaque byte string containing the client's password
 * @param {Uint8Array} blind the OPRF scalar value used for blinding
 * @param {Uint8Array} response_raw a RegistrationResponse structure
 * @param {Uint8Array} server_identity the optional encoded server identity
 * @param {Uint8Array} client_identity the optional encoded client identity
 * @param {number} mhf the memory hard function to use
 * @return object {record, exportKey}
 */
export function opaque_FinalizeRegistrationRequest(password: Uint8Array, blind: Uint8Array, response_raw: Uint8Array, server_identity: Uint8Array, client_identity: Uint8Array, mhf: number): {
    registrationRecord: Uint8Array;
    exportKey: Uint8Array;
};
/**
 *
 * @param {Uint8Array} state a ClientState structure
 * @param {Uint8Array} password an opaque byte string containing the client's password
 * @param {Uint8Array} blind
 * @param {Uint8Array} clientNonce
 * @param {Uint8Array} clientSecret
 * @param {Uint8Array} clientKeyshare
 * @return {Uint8Array} a KE1 message structure
 */
export function opaque_ClientInitWithSecrets(state: Uint8Array, password: Uint8Array, blind: Uint8Array, clientNonce: Uint8Array, clientSecret: Uint8Array, clientKeyshare: Uint8Array): Uint8Array;
/**
 *
 * @param {Uint8Array} state a ClientState structure
 * @param {Uint8Array} password an opaque byte string containing the client's password
 * @return {Uint8Array} a KE1 message structure
 */
export function opaque_ClientInit(state: Uint8Array, password: Uint8Array): Uint8Array;
/**
 *
 * @param {Uint8Array} state_raw a ClientState structure
 * @param {Uint8Array} client_identity the optional encoded client identity, which is set
 * to client_public_key if not specified
 * @param {Uint8Array} server_identity the optional encoded server identity, which is set
 * to server_public_key if not specified
 * @param {Uint8Array} ke2_raw a KE2 message structure
 * @param {number} mhf
 * @param {Uint8Array} context
 * @return object {ke3, sessionKey, exportKey, finishRet}
 */
export function opaque_ClientFinish(state_raw: Uint8Array, client_identity: Uint8Array, server_identity: Uint8Array, ke2_raw: Uint8Array, mhf: number, context: Uint8Array): {
    ke3: Uint8Array;
    sessionKey: Uint8Array;
    exportKey: Uint8Array;
    result: any;
};
/**
 *
 * @param {Uint8Array} state_raw a ServerState structure
 * @param {Uint8Array} server_identity the optional encoded server identity, which is set to
 * server_public_key if null
 * @param {Uint8Array} server_private_key the server's private key
 * @param {Uint8Array} server_public_key the server's public key
 * @param {Uint8Array} record_raw the client's RegistrationUpload structure
 * @param {Uint8Array} credential_identifier an identifier that uniquely represents the credential
 * being registered
 * @param {Uint8Array} oprf_seed the server-side seed of Nh bytes used to generate an oprf_key
 * @param {Uint8Array} ke1_raw a KE1 message structure
 * @param {Uint8Array} client_identity
 * @param {Uint8Array} context the application specific context
 * @param {Uint8Array} maskingNonce
 * @param {Uint8Array} serverNonce
 * @param {Uint8Array} serverSecret
 * @param {Uint8Array} serverKeyshare
 * @return {Uint8Array} a KE2 structure
 */
export function opaque_ServerInitWithSecrets(state_raw: Uint8Array, server_identity: Uint8Array, server_private_key: Uint8Array, server_public_key: Uint8Array, record_raw: Uint8Array, credential_identifier: Uint8Array, oprf_seed: Uint8Array, ke1_raw: Uint8Array, client_identity: Uint8Array, context: Uint8Array, maskingNonce: Uint8Array, serverNonce: Uint8Array, serverSecret: Uint8Array, serverKeyshare: Uint8Array): Uint8Array;
/**
 *
 * @param {Uint8Array} state_raw a ServerState structure
 * @param {Uint8Array} server_identity the optional encoded server identity, which is set to
 * server_public_key if null
 * @param {Uint8Array} server_private_key the server's private key
 * @param {Uint8Array} server_public_key the server's public key
 * @param {Uint8Array} record_raw the client's RegistrationUpload structure
 * @param {Uint8Array} credential_identifier an identifier that uniquely represents the credential
 * being registered
 * @param {Uint8Array} oprf_seed the server-side seed of Nh bytes used to generate an oprf_key
 * @param {Uint8Array} ke1_raw a KE1 message structure
 * @param {Uint8Array} client_identity
 * @param {Uint8Array} context the application specific context
 * @return {Uint8Array} a KE2 structure
 */
export function opaque_ServerInit(state_raw: Uint8Array, server_identity: Uint8Array, server_private_key: Uint8Array, server_public_key: Uint8Array, record_raw: Uint8Array, credential_identifier: Uint8Array, oprf_seed: Uint8Array, ke1_raw: Uint8Array, client_identity: Uint8Array, context: Uint8Array): Uint8Array;
/**
 * @param {Uint8Array} state_raw a ServerState structure
 * @param {Uint8Array} ke3_raw a KE3 structure
 * @return object {session_key, finish_ret}
 */
export function opaque_ServerFinish(state_raw: Uint8Array, ke3_raw: Uint8Array): {
    sessionKey: Uint8Array;
    result: any;
};
