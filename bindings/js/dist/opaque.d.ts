/**
 * Returns a randomly generated private and public key pair.
 *
 * This is implemented by generating a random "seed", then
 * calling internally DeriveAuthKeyPair.
 *
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-05#section-2
 *
 * @return object {private_key, public_key}
 */
export function opaque_ristretto255_sha512_GenerateAuthKeyPair(): Promise<{
    private_key: Uint8Array;
    public_key: Uint8Array;
}>;
/**
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-05#section-5.1.1.1
 *
 * @param {Uint8Array} password an opaque byte string containing the client's password
 * @return object {request, blind}
 */
export function opaque_ristretto255_sha512_CreateRegistrationRequest(password: Uint8Array): Promise<{
    request: Uint8Array;
    blind: Uint8Array;
}>;
/**
 * In order to make this method not to use dynamic memory allocation, there is a
 * limit of credential_identifier to length <= 200.
 *
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-05#section-5.1.1.2
 *
 * @param {Uint8Array} request_raw a RegistrationRequest structure
 * @param {Uint8Array} server_public_key the server's public key
 * @param {Uint8Array} credential_identifier an identifier that uniquely represents the credential being registered
 * @param {Uint8Array} oprf_seed the server-side seed of Nh bytes used to generate an oprf_key
 * @return object {response, oprf_key}
 */
export function opaque_ristretto255_sha512_CreateRegistrationResponse(request_raw: Uint8Array, server_public_key: Uint8Array, credential_identifier: Uint8Array, oprf_seed: Uint8Array): Promise<{
    response: Uint8Array;
    oprf_key: Uint8Array;
}>;
/**
 * To create the user record used for further authentication, the client
 * executes the following function. Since this works in the internal key mode, the
 * "client_private_key" is null.
 *
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-05#section-5.1.1.3
 *
 * @param {Uint8Array} client_private_key the client's private key (always null, internal mode)
 * @param {Uint8Array} password an opaque byte string containing the client's password
 * @param {Uint8Array} blind the OPRF scalar value used for blinding
 * @param {Uint8Array} response_raw a RegistrationResponse structure
 * @param {Uint8Array} server_identity the optional encoded server identity
 * @param {Uint8Array} client_identity the optional encoded client identity
 * @return object {record, export_key}
 */
export function opaque_ristretto255_sha512_FinalizeRequest(client_private_key: Uint8Array, password: Uint8Array, blind: Uint8Array, response_raw: Uint8Array, server_identity: Uint8Array, client_identity: Uint8Array): Promise<{
    record: Uint8Array;
    export_key: Uint8Array;
}>;
/**
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-05#section-6.2.3
 *
 * @param {Uint8Array} state_raw a ClientState structure
 * @param {Uint8Array} client_identity the optional encoded client identity, which is null if not specified
 * @param {Uint8Array} password an opaque byte string containing the client's password
 * @return {Promise<Uint8Array>} a KE1 message structure
 */
export function opaque_ristretto255_sha512_3DH_ClientInit(state_raw: Uint8Array, client_identity: Uint8Array, password: Uint8Array): Promise<Uint8Array>;
/**
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-05#section-6.2.3
 *
 * @param {Uint8Array} state_raw a ClientState structure
 * @param {Uint8Array} password an opaque byte string containing the client's password
 * @param {Uint8Array} client_identity the optional encoded client identity, which is set
 * to client_public_key if not specified
 * @param {Uint8Array} server_identity the optional encoded server identity, which is set
 * to server_public_key if not specified
 * @param {Uint8Array} ke2_raw a KE2 message structure
 * @return object {ke3, session_key, export_key, finish_ret}
 */
export function opaque_ristretto255_sha512_3DH_ClientFinish(state_raw: Uint8Array, password: Uint8Array, client_identity: Uint8Array, server_identity: Uint8Array, ke2_raw: Uint8Array): Promise<{
    ke3: Uint8Array;
    session_key: Uint8Array;
    export_key: Uint8Array;
    finish_ret: any;
}>;
/**
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-05#section-6.2.4
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
 * @param {Uint8Array} context the application specific context
 * @return {Promise<Uint8Array>} a KE2 structure
 */
export function opaque_ristretto255_sha512_3DH_ServerInit(state_raw: Uint8Array, server_identity: Uint8Array, server_private_key: Uint8Array, server_public_key: Uint8Array, record_raw: Uint8Array, credential_identifier: Uint8Array, oprf_seed: Uint8Array, ke1_raw: Uint8Array, context: Uint8Array): Promise<Uint8Array>;
/**
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-05#section-6.2.4
 *
 * @param {Uint8Array} state_raw a ServerState structure
 * @param {Uint8Array} ke3_raw a KE3 structure
 * @return object {session_key, finish_ret}
 */
export function opaque_ristretto255_sha512_3DH_ServerFinish(state_raw: Uint8Array, ke3_raw: Uint8Array): Promise<{
    session_key: Uint8Array;
    finish_ret: any;
}>;
