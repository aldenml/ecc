#
# Copyright (c) 2021-2022, Alden Torres
#
# Licensed under the terms of the MIT license.
# Copy of the license at https://opensource.org/licenses/MIT
#

from cffi import FFI

ffibuilder = FFI()

ffibuilder.cdef(
    """
    // util

    void ecc_randombytes(
        unsigned char *buf,
        int n
    );

    void ecc_concat2(
        unsigned char *out,
        unsigned char *a1,
        int a1_len,
        unsigned char *a2,
        int a2_len
    );

    void ecc_concat3(
        unsigned char *out,
        unsigned char *a1,
        int a1_len,
        unsigned char *a2,
        int a2_len,
        unsigned char *a3,
        int a3_len
    );

    void ecc_concat4(
        unsigned char *out,
        unsigned char *a1,
        int a1_len,
        unsigned char *a2,
        int a2_len,
        unsigned char *a3,
        int a3_len,
        unsigned char *a4,
        int a4_len
    );

    void ecc_strxor(
        unsigned char *out,
        unsigned char *a,
        unsigned char *b,
        int len
    );

    void ecc_I2OSP(
        unsigned char *out,
        int x,
        int xLen
    );

    int ecc_compare(
        unsigned char *a,
        unsigned char *b,
        int len
    );

    int ecc_is_zero(
        unsigned char *n,
        int len
    );

    // hash

    void ecc_hash_sha256(
        unsigned char *digest,
        unsigned char *input,
        int input_len
    );

    void ecc_hash_sha512(
        unsigned char *digest,
        unsigned char *input,
        int input_len
    );

    // mac

    void ecc_mac_hmac_sha256(
        unsigned char *digest,
        unsigned char *text,
        int text_len,
        unsigned char *key
    );

    void ecc_mac_hmac_sha512(
        unsigned char *digest,
        unsigned char *text,
        int text_len,
        unsigned char *key
    );

    // kdf

    void ecc_kdf_hkdf_sha256_extract(
        unsigned char *prk,
        unsigned char *salt,
        int salt_len,
        unsigned char *ikm,
        int ikm_len
    );

    void ecc_kdf_hkdf_sha256_expand(
        unsigned char *okm,
        unsigned char *prk,
        unsigned char *info,
        int info_len,
        int len
    );

    void ecc_kdf_hkdf_sha512_extract(
        unsigned char *prk,
        unsigned char *salt,
        int salt_len,
        unsigned char *ikm,
        int ikm_len
    );

    void ecc_kdf_hkdf_sha512_expand(
        unsigned char *okm,
        unsigned char *prk,
        unsigned char *info,
        int info_len,
        int len
    );

    int ecc_kdf_scrypt(
        unsigned char *out,
        unsigned char *passphrase,
        int passphrase_len,
        unsigned char *salt,
        int salt_len,
        int cost,
        int block_size,
        int parallelization,
        int len
    );

    // ed25519

    int ecc_ed25519_is_valid_point(
        unsigned char *p
    );

    int ecc_ed25519_add(
        unsigned char *r,
        unsigned char *p,
        unsigned char *q
    );

    int ecc_ed25519_sub(
        unsigned char *r,
        unsigned char *p,
        unsigned char *q
    );

    void ecc_ed25519_from_uniform(
        unsigned char *p,
        unsigned char *r
    );

    void ecc_ed25519_random(
        unsigned char *p
    );

    void ecc_ed25519_scalar_random(
        unsigned char *r
    );

    int ecc_ed25519_scalar_invert(
        unsigned char *recip,
        unsigned char *s
    );

    void ecc_ed25519_scalar_negate(
        unsigned char *neg,
        unsigned char *s
    );

    void ecc_ed25519_scalar_complement(
        unsigned char *comp,
        unsigned char *s
    );

    void ecc_ed25519_scalar_add(
        unsigned char *z,
        unsigned char *x,
        unsigned char *y
    );

    void ecc_ed25519_scalar_sub(
        unsigned char *z,
        unsigned char *x,
        unsigned char *y
    );

    void ecc_ed25519_scalar_mul(
        unsigned char *z,
        unsigned char *x,
        unsigned char *y
    );

    void ecc_ed25519_scalar_reduce(
        unsigned char *r,
        unsigned char *s
    );

    int ecc_ed25519_scalarmult(
        unsigned char *q,
        unsigned char *n,
        unsigned char *p
    );

    int ecc_ed25519_scalarmult_base(
        unsigned char *q,
        unsigned char *n
    );

    // ristretto255

    int ecc_ristretto255_is_valid_point(
        unsigned char *p
    );

    int ecc_ristretto255_add(
        unsigned char *r,
        unsigned char *p,
        unsigned char *q
    );

    int ecc_ristretto255_sub(
        unsigned char *r,
        unsigned char *p,
        unsigned char *q
    );

    void ecc_ristretto255_generator(
        unsigned char *g
    );

    void ecc_ristretto255_from_hash(
        unsigned char *p,
        unsigned char *r
    );

    void ecc_ristretto255_random(
        unsigned char *p
    );

    void ecc_ristretto255_scalar_random(
        unsigned char *r
    );

    int ecc_ristretto255_scalar_invert(
        unsigned char *recip,
        unsigned char *s
    );

    void ecc_ristretto255_scalar_negate(
        unsigned char *neg,
        unsigned char *s
    );

    void ecc_ristretto255_scalar_complement(
        unsigned char *comp,
        unsigned char *s
    );

    void ecc_ristretto255_scalar_add(
        unsigned char *z,
        unsigned char *x,
        unsigned char *y
    );

    void ecc_ristretto255_scalar_sub(
        unsigned char *z,
        unsigned char *x,
        unsigned char *y
    );

    void ecc_ristretto255_scalar_mul(
        unsigned char *z,
        unsigned char *x,
        unsigned char *y
    );

    void ecc_ristretto255_scalar_reduce(
        unsigned char *r,
        unsigned char *s
    );

    int ecc_ristretto255_scalarmult(
        unsigned char *q,
        unsigned char *n,
        unsigned char *p
    );

    int ecc_ristretto255_scalarmult_base(
        unsigned char *q,
        unsigned char *n
    );

    // bls12_381

    void ecc_bls12_381_fp_random(
        unsigned char *ret
    );

    void ecc_bls12_381_fp12_one(
        unsigned char *ret
    );

    int ecc_bls12_381_fp12_is_one(
        unsigned char *a
    );

    void ecc_bls12_381_fp12_inverse(
        unsigned char *ret,
        unsigned char *a
    );

    void ecc_bls12_381_fp12_sqr(
        unsigned char *ret,
        unsigned char *a
    );

    void ecc_bls12_381_fp12_mul(
        unsigned char *ret,
        unsigned char *a,
        unsigned char *b
    );

    void ecc_bls12_381_fp12_pow(
        unsigned char *ret,
        unsigned char *a,
        int n
    );

    void ecc_bls12_381_fp12_random(
        unsigned char *ret
    );

    void ecc_bls12_381_g1_add(
        unsigned char *r,
        unsigned char *p,
        unsigned char *q
    );

    void ecc_bls12_381_g1_negate(
        unsigned char *neg,
        unsigned char *p
    );

    void ecc_bls12_381_g1_generator(
        unsigned char *g
    );

    void ecc_bls12_381_g1_scalarmult(
        unsigned char *q,
        unsigned char *n,
        unsigned char *p
    );

    void ecc_bls12_381_g1_scalarmult_base(
        unsigned char *q,
        unsigned char *n
    );

    void ecc_bls12_381_g2_add(
        unsigned char *r,
        unsigned char *p,
        unsigned char *q
    );

    void ecc_bls12_381_g2_negate(
        unsigned char *neg,
        unsigned char *p
    );

    void ecc_bls12_381_g2_generator(
        unsigned char *g
    );

    void ecc_bls12_381_g2_scalarmult_base(
        unsigned char *q,
        unsigned char *n
    );

    void ecc_bls12_381_scalar_random(
        unsigned char *r
    );

    void ecc_bls12_381_pairing(
        unsigned char *ret,
        unsigned char *p1_g1,
        unsigned char *p2_g2
    );

    void ecc_bls12_381_pairing_miller_loop(
        unsigned char *ret,
        unsigned char *p1_g1,
        unsigned char *p2_g2
    );

    void ecc_bls12_381_pairing_final_exp(
        unsigned char *ret,
        unsigned char *a
    );

    int ecc_bls12_381_pairing_final_verify(
        unsigned char *a,
        unsigned char *b
    );

    // h2c

    void ecc_h2c_expand_message_xmd_sha256(
        unsigned char *out,
        unsigned char *msg,
        int msg_len,
        unsigned char *dst,
        int dst_len,
        int len
    );

    void ecc_h2c_expand_message_xmd_sha512(
        unsigned char *out,
        unsigned char *msg,
        int msg_len,
        unsigned char *dst,
        int dst_len,
        int len
    );

    // oprf

    int ecc_oprf_ristretto255_sha512_Evaluate(
        unsigned char *evaluatedElement,
        unsigned char *skS,
        unsigned char *blindedElement,
        unsigned char *info,
        int infoLen
    );

    int ecc_oprf_ristretto255_sha512_VerifiableEvaluateWithScalar(
        unsigned char *evaluatedElement,
        unsigned char *proof,
        unsigned char *skS,
        unsigned char *blindedElement,
        unsigned char *info,
        int infoLen,
        unsigned char *r
    );

    int ecc_oprf_ristretto255_sha512_VerifiableEvaluate(
        unsigned char *evaluatedElement,
        unsigned char *proof,
        unsigned char *skS,
        unsigned char *blindedElement,
        unsigned char *info,
        int infoLen
    );

    void ecc_oprf_ristretto255_sha512_GenerateProofWithScalar(
        unsigned char *proof,
        unsigned char *k,
        unsigned char *A,
        unsigned char *B,
        unsigned char *C,
        unsigned char *D,
        unsigned char *r
    );

    void ecc_oprf_ristretto255_sha512_GenerateProof(
        unsigned char *proof,
        unsigned char *k,
        unsigned char *A,
        unsigned char *B,
        unsigned char *C,
        unsigned char *D
    );

    void ecc_oprf_ristretto255_sha512_ComputeComposites(
        unsigned char *M,
        unsigned char *Z,
        unsigned char *B,
        unsigned char *Cs,
        unsigned char *Ds,
        int m
    );

    void ecc_oprf_ristretto255_sha512_ComputeCompositesFast(
        unsigned char *M,
        unsigned char *Z,
        unsigned char *k,
        unsigned char *B,
        unsigned char *Cs,
        unsigned char *Ds,
        int m
    );

    void ecc_oprf_ristretto255_sha512_BlindWithScalar(
        unsigned char *blindedElement,
        unsigned char *input,
        int inputLen,
        unsigned char *blind,
        int mode
    );

    void ecc_oprf_ristretto255_sha512_Blind(
        unsigned char *blindedElement,
        unsigned char *blind,
        unsigned char *input,
        int inputLen,
        int mode
    );

    void ecc_oprf_ristretto255_sha512_Unblind(
        unsigned char *unblindedElement,
        unsigned char *blind,
        unsigned char *evaluatedElement
    );

    void ecc_oprf_ristretto255_sha512_Finalize(
        unsigned char *output,
        unsigned char *input,
        int inputLen,
        unsigned char *blind,
        unsigned char *evaluatedElement,
        unsigned char *info,
        int infoLen
    );

    int ecc_oprf_ristretto255_sha512_VerifyProof(
        unsigned char *A,
        unsigned char *B,
        unsigned char *C,
        unsigned char *D,
        unsigned char *proof
    );

    int ecc_oprf_ristretto255_sha512_VerifiableUnblind(
        unsigned char *unblindedElement,
        unsigned char *blind,
        unsigned char *evaluatedElement,
        unsigned char *blindedElement,
        unsigned char *pkS,
        unsigned char *proof,
        unsigned char *info,
        int infoLen
    );

    int ecc_oprf_ristretto255_sha512_VerifiableFinalize(
        unsigned char *output,
        unsigned char *input,
        int inputLen,
        unsigned char *blind,
        unsigned char *evaluatedElement,
        unsigned char *blindedElement,
        unsigned char *pkS,
        unsigned char *proof,
        unsigned char *info,
        int infoLen
    );

    void ecc_oprf_ristretto255_sha512_HashToGroupWithDST(
        unsigned char *out,
        unsigned char *input,
        int inputLen,
        unsigned char *dst,
        int dstLen
    );

    void ecc_oprf_ristretto255_sha512_HashToGroup(
        unsigned char *out,
        unsigned char *input,
        int inputLen,
        int mode
    );

    void ecc_oprf_ristretto255_sha512_HashToScalarWithDST(
        unsigned char *out,
        unsigned char *input,
        int inputLen,
        unsigned char *dst,
        int dstLen
    );

    void ecc_oprf_ristretto255_sha512_HashToScalar(
        unsigned char *out,
        unsigned char *input,
        int inputLen,
        int mode
    );

    // opaque

    void ecc_opaque_ristretto255_sha512_DeriveKeyPair(
        unsigned char *private_key,
        unsigned char *public_key,
        unsigned char *seed,
        int seed_len
    );

    void ecc_opaque_ristretto255_sha512_CreateCleartextCredentials(
        unsigned char *cleartext_credentials,
        unsigned char *server_public_key,
        unsigned char *client_public_key,
        unsigned char *server_identity,
        int server_identity_len,
        unsigned char *client_identity,
        int client_identity_len
    );

    void ecc_opaque_ristretto255_sha512_EnvelopeStoreWithNonce(
        unsigned char *envelope,
        unsigned char *client_public_key,
        unsigned char *masking_key,
        unsigned char *export_key,
        unsigned char *randomized_pwd,
        unsigned char *server_public_key,
        unsigned char *server_identity,
        int server_identity_len,
        unsigned char *client_identity,
        int client_identity_len,
        unsigned char *nonce
    );

    void ecc_opaque_ristretto255_sha512_EnvelopeStore(
        unsigned char *envelope,
        unsigned char *client_public_key,
        unsigned char *masking_key,
        unsigned char *export_key,
        unsigned char *randomized_pwd,
        unsigned char *server_public_key,
        unsigned char *server_identity,
        int server_identity_len,
        unsigned char *client_identity,
        int client_identity_len
    );

    int ecc_opaque_ristretto255_sha512_EnvelopeRecover(
        unsigned char *client_private_key,
        unsigned char *export_key,
        unsigned char *randomized_pwd,
        unsigned char *server_public_key,
        unsigned char *envelope_raw,
        unsigned char *server_identity,
        int server_identity_len,
        unsigned char *client_identity,
        int client_identity_len
    );

    void ecc_opaque_ristretto255_sha512_RecoverPublicKey(
        unsigned char *public_key,
        unsigned char *private_key
    );

    void ecc_opaque_ristretto255_sha512_GenerateAuthKeyPair(
        unsigned char *private_key,
        unsigned char *public_key
    );

    void ecc_opaque_ristretto255_sha512_DeriveAuthKeyPair(
        unsigned char *private_key,
        unsigned char *public_key,
        unsigned char *seed,
        int seed_len
    );

    void ecc_opaque_ristretto255_sha512_CreateRegistrationRequestWithBlind(
        unsigned char *request,
        unsigned char *password,
        int password_len,
        unsigned char *blind
    );

    void ecc_opaque_ristretto255_sha512_CreateRegistrationRequest(
        unsigned char *request,
        unsigned char *blind,
        unsigned char *password,
        int password_len
    );

    void ecc_opaque_ristretto255_sha512_CreateRegistrationResponseWithOprfKey(
        unsigned char *response,
        unsigned char *request,
        unsigned char *server_public_key,
        unsigned char *credential_identifier,
        int credential_identifier_len,
        unsigned char *oprf_key
    );

    void ecc_opaque_ristretto255_sha512_CreateRegistrationResponse(
        unsigned char *response,
        unsigned char *oprf_key,
        unsigned char *request,
        unsigned char *server_public_key,
        unsigned char *credential_identifier,
        int credential_identifier_len,
        unsigned char *oprf_seed
    );

    void ecc_opaque_ristretto255_sha512_FinalizeRequestWithNonce(
        unsigned char *record,
        unsigned char *export_key,
        unsigned char *password,
        int password_len,
        unsigned char *blind,
        unsigned char *response,
        unsigned char *server_identity,
        int server_identity_len,
        unsigned char *client_identity,
        int client_identity_len,
        int mhf,
        unsigned char *nonce
    );

    void ecc_opaque_ristretto255_sha512_FinalizeRequest(
        unsigned char *record,
        unsigned char *export_key,
        unsigned char *password,
        int password_len,
        unsigned char *blind,
        unsigned char *response,
        unsigned char *server_identity,
        int server_identity_len,
        unsigned char *client_identity,
        int client_identity_len,
        int mhf
    );

    void ecc_opaque_ristretto255_sha512_CreateCredentialRequestWithBlind(
        unsigned char *request,
        unsigned char *password,
        int password_len,
        unsigned char *blind
    );

    void ecc_opaque_ristretto255_sha512_CreateCredentialRequest(
        unsigned char *request,
        unsigned char *blind,
        unsigned char *password,
        int password_len
    );

    void ecc_opaque_ristretto255_sha512_CreateCredentialResponseWithMasking(
        unsigned char *response_raw,
        unsigned char *request_raw,
        unsigned char *server_public_key,
        unsigned char *record_raw,
        unsigned char *credential_identifier,
        int credential_identifier_len,
        unsigned char *oprf_seed,
        unsigned char *masking_nonce
    );

    void ecc_opaque_ristretto255_sha512_CreateCredentialResponse(
        unsigned char *response_raw,
        unsigned char *request_raw,
        unsigned char *server_public_key,
        unsigned char *record_raw,
        unsigned char *credential_identifier,
        int credential_identifier_len,
        unsigned char *oprf_seed
    );

    int ecc_opaque_ristretto255_sha512_RecoverCredentials(
        unsigned char *client_private_key,
        unsigned char *server_public_key,
        unsigned char *export_key,
        unsigned char *password,
        int password_len,
        unsigned char *blind,
        unsigned char *response,
        unsigned char *server_identity,
        int server_identity_len,
        unsigned char *client_identity,
        int client_identity_len,
        int mhf
    );

    void ecc_opaque_ristretto255_sha512_3DH_Expand_Label(
        unsigned char *out,
        unsigned char *secret,
        unsigned char *label,
        int label_len,
        unsigned char *context,
        int context_len,
        int length
    );

    void ecc_opaque_ristretto255_sha512_3DH_Derive_Secret(
        unsigned char *out,
        unsigned char *secret,
        unsigned char *label,
        int label_len,
        unsigned char *transcript_hash,
        int transcript_hash_len
    );

    int ecc_opaque_ristretto255_sha512_3DH_Preamble(
        unsigned char *preamble,
        int preamble_len,
        unsigned char *context,
        int context_len,
        unsigned char *client_identity,
        int client_identity_len,
        unsigned char *client_public_key,
        unsigned char *ke1,
        unsigned char *server_identity,
        int server_identity_len,
        unsigned char *server_public_key,
        unsigned char *ke2
    );

    void ecc_opaque_ristretto255_sha512_3DH_TripleDHIKM(
        unsigned char *ikm,
        unsigned char *sk1,
        unsigned char *pk1,
        unsigned char *sk2,
        unsigned char *pk2,
        unsigned char *sk3,
        unsigned char *pk3
    );

    void ecc_opaque_ristretto255_sha512_3DH_DeriveKeys(
        unsigned char *km2,
        unsigned char *km3,
        unsigned char *session_key,
        unsigned char *ikm,
        int ikm_len,
        unsigned char *preamble,
        int preamble_len
    );

    void ecc_opaque_ristretto255_sha512_3DH_ClientInitWithSecrets(
        unsigned char *ke1,
        unsigned char *state,
        unsigned char *password,
        int password_len,
        unsigned char *blind,
        unsigned char *client_nonce,
        unsigned char *client_secret,
        unsigned char *client_keyshare
    );

    void ecc_opaque_ristretto255_sha512_3DH_ClientInit(
        unsigned char *ke1,
        unsigned char *state,
        unsigned char *password,
        int password_len
    );

    int ecc_opaque_ristretto255_sha512_3DH_ClientFinish(
        unsigned char *ke3_raw,
        unsigned char *session_key,
        unsigned char *export_key,
        unsigned char *state_raw,
        unsigned char *password,
        int password_len,
        unsigned char *client_identity,
        int client_identity_len,
        unsigned char *server_identity,
        int server_identity_len,
        unsigned char *ke2,
        int mhf,
        unsigned char *context,
        int context_len
    );

    void ecc_opaque_ristretto255_sha512_3DH_StartWithSecrets(
        unsigned char *ke1,
        unsigned char *state,
        unsigned char *credential_request,
        unsigned char *client_nonce,
        unsigned char *client_secret,
        unsigned char *client_keyshare
    );

    void ecc_opaque_ristretto255_sha512_3DH_Start(
        unsigned char *ke1,
        unsigned char *state,
        unsigned char *credential_request
    );

    int ecc_opaque_ristretto255_sha512_3DH_ClientFinalize(
        unsigned char *ke3_raw,
        unsigned char *session_key,
        unsigned char *state_raw,
        unsigned char *client_identity,
        int client_identity_len,
        unsigned char *client_private_key,
        unsigned char *server_identity,
        int server_identity_len,
        unsigned char *server_public_key,
        unsigned char *ke2_raw,
        unsigned char *context,
        int context_len
    );

    void ecc_opaque_ristretto255_sha512_3DH_ServerInitWithSecrets(
        unsigned char *ke2_raw,
        unsigned char *state_raw,
        unsigned char *server_identity,
        int server_identity_len,
        unsigned char *server_private_key,
        unsigned char *server_public_key,
        unsigned char *client_identity,
        int client_identity_len,
        unsigned char *record_raw,
        unsigned char *credential_identifier,
        int credential_identifier_len,
        unsigned char *oprf_seed,
        unsigned char *ke1_raw,
        unsigned char *context,
        int context_len,
        unsigned char *masking_nonce,
        unsigned char *server_nonce,
        unsigned char *server_secret,
        unsigned char *server_keyshare
    );

    void ecc_opaque_ristretto255_sha512_3DH_ServerInit(
        unsigned char *ke2_raw,
        unsigned char *state_raw,
        unsigned char *server_identity,
        int server_identity_len,
        unsigned char *server_private_key,
        unsigned char *server_public_key,
        unsigned char *client_identity,
        int client_identity_len,
        unsigned char *record_raw,
        unsigned char *credential_identifier,
        int credential_identifier_len,
        unsigned char *oprf_seed,
        unsigned char *ke1_raw,
        unsigned char *context,
        int context_len
    );

    int ecc_opaque_ristretto255_sha512_3DH_ServerFinish(
        unsigned char *session_key,
        unsigned char *state_raw,
        unsigned char *ke3_raw
    );

    void ecc_opaque_ristretto255_sha512_3DH_ResponseWithSecrets(
        unsigned char *ke2_raw,
        unsigned char *state_raw,
        unsigned char *server_identity,
        int server_identity_len,
        unsigned char *server_private_key,
        unsigned char *server_public_key,
        unsigned char *client_identity,
        int client_identity_len,
        unsigned char *client_public_key,
        unsigned char *ke1_raw,
        unsigned char *credential_response_raw,
        unsigned char *context,
        int context_len,
        unsigned char *server_nonce,
        unsigned char *server_secret,
        unsigned char *server_keyshare
    );

    void ecc_opaque_ristretto255_sha512_3DH_Response(
        unsigned char *ke2_raw,
        unsigned char *state_raw,
        unsigned char *server_identity,
        int server_identity_len,
        unsigned char *server_private_key,
        unsigned char *server_public_key,
        unsigned char *client_identity,
        int client_identity_len,
        unsigned char *client_public_key,
        unsigned char *ke1_raw,
        unsigned char *credential_response_raw,
        unsigned char *context,
        int context_len
    );

    // sign

    void ecc_sign_ed25519_Sign(
        unsigned char *signature,
        unsigned char *message,
        int message_len,
        unsigned char *sk
    );

    int ecc_sign_ed25519_Verify(
        unsigned char *signature,
        unsigned char *message,
        int message_len,
        unsigned char *pk
    );

    void ecc_sign_ed25519_KeyPair(
        unsigned char *pk,
        unsigned char *sk
    );

    void ecc_sign_ed25519_SeedKeyPair(
        unsigned char *pk,
        unsigned char *sk,
        unsigned char *seed
    );

    void ecc_sign_ed25519_SkToSeed(
        unsigned char *seed,
        unsigned char *sk
    );

    void ecc_sign_ed25519_SkToPk(
        unsigned char *pk,
        unsigned char *sk
    );

    void ecc_sign_eth_bls_KeyGen(
        unsigned char *sk,
        unsigned char *ikm,
        int ikm_len
    );

    void ecc_sign_eth_bls_SkToPk(
        unsigned char *pk,
        unsigned char *sk
    );

    int ecc_sign_eth_bls_KeyValidate(
        unsigned char *pk
    );

    void ecc_sign_eth_bls_Sign(
        unsigned char *signature,
        unsigned char *sk,
        unsigned char *message,
        int message_len
    );

    int ecc_sign_eth_bls_Verify(
        unsigned char *pk,
        unsigned char *message,
        int message_len,
        unsigned char *signature
    );

    int ecc_sign_eth_bls_Aggregate(
        unsigned char *signature,
        unsigned char *signatures,
        int n
    );

    int ecc_sign_eth_bls_FastAggregateVerify(
        unsigned char *pks,
        int n,
        unsigned char *message,
        int message_len,
        unsigned char *signature
    );

    int ecc_sign_eth_bls_AggregateVerify(
        int n,
        unsigned char *pks,
        unsigned char *messages,
        int messages_len,
        unsigned char *signature
    );

    // pre

    void ecc_pre_schema1_MessageGen(
        unsigned char *m
    );

    void ecc_pre_schema1_DeriveKey(
        unsigned char *pk,
        unsigned char *sk,
        unsigned char *seed
    );

    void ecc_pre_schema1_KeyGen(
        unsigned char *pk,
        unsigned char *sk
    );

    void ecc_pre_schema1_DeriveSigningKey(
        unsigned char *spk,
        unsigned char *ssk,
        unsigned char *seed
    );

    void ecc_pre_schema1_SigningKeyGen(
        unsigned char *spk,
        unsigned char *ssk
    );

    void ecc_pre_schema1_EncryptWithSeed(
        unsigned char *C_j_raw,
        unsigned char *m,
        unsigned char *pk_j,
        unsigned char *spk_i,
        unsigned char *ssk_i,
        unsigned char *seed
    );

    void ecc_pre_schema1_Encrypt(
        unsigned char *C_j_raw,
        unsigned char *m,
        unsigned char *pk_j,
        unsigned char *spk_i,
        unsigned char *ssk_i
    );

    void ecc_pre_schema1_ReKeyGen(
        unsigned char *tk_i_j_raw,
        unsigned char *sk_i,
        unsigned char *pk_j,
        unsigned char *spk_i,
        unsigned char *ssk_i
    );

    int ecc_pre_schema1_ReEncrypt(
        unsigned char *C_j_raw,
        unsigned char *C_i_raw,
        unsigned char *tk_i_j_raw,
        unsigned char *spk_i,
        unsigned char *pk_j,
        unsigned char *spk,
        unsigned char *ssk
    );

    int ecc_pre_schema1_DecryptLevel1(
        unsigned char *m,
        unsigned char *C_i_raw,
        unsigned char *sk_i,
        unsigned char *spk_i
    );

    int ecc_pre_schema1_DecryptLevel2(
        unsigned char *m,
        unsigned char *C_j_raw,
        unsigned char *sk_j,
        unsigned char *spk
    );

    // frost

    void ecc_frost_ristretto255_sha512_H1(
        unsigned char *h1,
        unsigned char *m,
        int m_len
    );

    void ecc_frost_ristretto255_sha512_H1_2(
        unsigned char *h1,
        unsigned char *m1,
        int m1_len,
        unsigned char *m2,
        int m2_len
    );

    void ecc_frost_ristretto255_sha512_H2(
        unsigned char *h2,
        unsigned char *m,
        int m_len
    );

    void ecc_frost_ristretto255_sha512_H2_3(
        unsigned char *h2,
        unsigned char *m1,
        int m1_len,
        unsigned char *m2,
        int m2_len,
        unsigned char *m3,
        int m3_len
    );

    void ecc_frost_ristretto255_sha512_H3(
        unsigned char *h3,
        unsigned char *m,
        int m_len
    );

    void ecc_frost_ristretto255_sha512_schnorr_signature_generate(
        unsigned char *signature,
        unsigned char *msg,
        int msg_len,
        unsigned char *SK
    );

    int ecc_frost_ristretto255_sha512_schnorr_signature_verify(
        unsigned char *msg,
        int msg_len,
        unsigned char *signature,
        unsigned char *PK
    );

    void ecc_frost_ristretto255_sha512_polynomial_evaluate(
        unsigned char *value,
        unsigned char *x,
        unsigned char *coeffs,
        int coeffs_len
    );

    void ecc_frost_ristretto255_sha512_derive_lagrange_coefficient(
        unsigned char *L_i,
        unsigned char *x_i,
        unsigned char *L,
        int L_len
    );

    void ecc_frost_ristretto255_sha512_derive_lagrange_coefficient_with_points(
        unsigned char *L_i,
        unsigned char *x_i,
        unsigned char *L,
        int L_len
    );

    void ecc_frost_ristretto255_sha512_polynomial_interpolation(
        unsigned char *constant_term,
        unsigned char *points,
        int points_len
    );

    void ecc_frost_ristretto255_sha512_compute_binding_factor(
        unsigned char *binding_factor,
        unsigned char *encoded_commitment_list,
        int encoded_commitment_list_len,
        unsigned char *msg,
        int msg_len
    );

    void ecc_frost_ristretto255_sha512_compute_challenge(
        unsigned char *challenge,
        unsigned char *group_commitment,
        unsigned char *group_public_key,
        unsigned char *msg,
        int msg_len
    );

    void ecc_frost_ristretto255_sha512_commit_with_nonce(
        unsigned char *comm,
        unsigned char *nonce
    );

    void ecc_frost_ristretto255_sha512_commit(
        unsigned char *nonce,
        unsigned char *comm
    );

    void ecc_frost_ristretto255_sha512_group_commitment(
        unsigned char *group_comm,
        unsigned char *commitment_list,
        int commitment_list_len,
        unsigned char *binding_factor
    );

    void ecc_frost_ristretto255_sha512_sign(
        unsigned char *sig_share,
        unsigned char *comm_share,
        int index,
        unsigned char *sk_i,
        unsigned char *group_public_key,
        unsigned char *nonce_i,
        unsigned char *comm_i,
        unsigned char *msg,
        int msg_len,
        unsigned char *commitment_list,
        int commitment_list_len,
        unsigned char *participant_list,
        int participant_list_len
    );

    int ecc_frost_ristretto255_sha512_verify_signature_share(
        int index,
        unsigned char *public_key_share_i,
        unsigned char *comm_i,
        unsigned char *sig_share_i,
        unsigned char *commitment_list,
        int commitment_list_len,
        unsigned char *participant_list,
        int participant_list_len,
        unsigned char *group_public_key,
        unsigned char *msg,
        int msg_len
    );

    void ecc_frost_ristretto255_sha512_trusted_dealer_keygen_with_secret_and_coefficients(
        unsigned char *public_key,
        unsigned char *secret_key_shares,
        int n,
        int t,
        unsigned char *secret_key,
        unsigned char *coefficients
    );

    void ecc_frost_ristretto255_sha512_trusted_dealer_keygen(
        unsigned char *secret_key,
        unsigned char *public_key,
        unsigned char *secret_key_shares,
        int n,
        int t
    );

    void ecc_frost_ristretto255_sha512_secret_share_shard_with_coefficients(
        unsigned char *points,
        int n,
        int t,
        unsigned char *coefficients
    );

    void ecc_frost_ristretto255_sha512_secret_share_shard(
        unsigned char *points,
        unsigned char *s,
        int n,
        int t
    );

    void ecc_frost_ristretto255_sha512_frost_aggregate(
        unsigned char *signature,
        unsigned char *group_commitment,
        unsigned char *sig_shares,
        int sig_shares_len
    );

    """
)

ffibuilder.set_source(
    module_name="_libecc_cffi",
    source=
    """
    #include "../../../../src/ecc.h"
    """,
    include_dirs=["../../../src"],
    library_dirs=["../../../../build", "../../../../build/libsodium/lib", "../../../../deps/blst"],
    libraries=["ecc_static", "sodium", "blst"]
)

if __name__ == "__main__":
    ffibuilder.compile(tmpdir="src/libecc", verbose=True)
