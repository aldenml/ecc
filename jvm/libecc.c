/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#include "jni.h"
#include <stdlib.h>
#include <ecc.h>

void throw_OutOfMemoryError(JNIEnv *env) {
    (*env)->ExceptionClear(env);
    jclass cls = (*env)->FindClass(env, "java/lang/OutOfMemoryError");
    if (cls)
        (*env)->ThrowNew(env, cls, "Unable to allocate native memory");
}

byte_t *alloc_heap(JNIEnv *env, int size) {
    byte_t *p = malloc(size);
    if (!p) {
        throw_OutOfMemoryError(env);
    }
    return p;
}

void free_heap(byte_t *p, int size) {
    ecc_memzero(p, size);
    free(p);
}

byte_t *mput(JNIEnv *env, jbyteArray src, byte_t *ptr, int length) {
    if (src != NULL)
        (*env)->GetByteArrayRegion(env, src, 0, length, (jbyte *) ptr);
    return ptr;
}

void mget(JNIEnv *env, byte_t *ptr, jbyteArray dest, int length) {
    (*env)->SetByteArrayRegion(env, dest, 0, length, (jbyte *) ptr);
}

#define ALLOC_HEAP \
    byte_t *heap = alloc_heap(env, heap_size); \
    if (!heap) { \
        return; \
    } \
    (void)(0)

#define ALLOC_HEAP_RET \
    byte_t *heap = alloc_heap(env, heap_size); \
    if (!heap) { \
        return -1; \
    } \
    (void)(0)

#define FREE_HEAP \
    free_heap(heap, heap_size)

#ifdef __cplusplus
extern "C" {
#endif

// util

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1randombytes(
    JNIEnv *env, jclass cls,
    jbyteArray buf,
    jint len
) {
    ECC_UNUSED(cls);

    const int heap_size = len;
    ALLOC_HEAP;

    byte_t *pBuf = heap;

    ecc_randombytes(pBuf, len);

    mget(env, pBuf, buf, len);

    FREE_HEAP;
}

// h2c

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1h2c_1expand_1message_1xmd_1sha512(
    JNIEnv *env, jclass cls,
    jbyteArray out,
    jbyteArray msg, jint msg_len,
    jbyteArray dst, jint dst_len,
    jint len
) {
    ECC_UNUSED(cls);

    const int heap_size = msg_len + dst_len + len;
    ALLOC_HEAP;

    byte_t *pMsg = mput(env, msg, heap, msg_len);
    byte_t *pDst = mput(env, dst, pMsg + msg_len, dst_len);
    byte_t *pOut = pDst + dst_len;

    ecc_h2c_expand_message_xmd_sha512(
        pOut,
        pMsg, msg_len,
        pDst, dst_len,
        len
    );

    mget(env, pOut, out, len);

    FREE_HEAP;
}

// opaque

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1opaque_1ristretto255_1sha512_1GenerateAuthKeyPair(
    JNIEnv *env, jclass cls,
    jbyteArray private_key, // 32
    jbyteArray public_key // 32
) {
    ECC_UNUSED(cls);

    const int heap_size = 32 + 32;
    ALLOC_HEAP;

    byte_t *pPrivate_key = heap;
    byte_t *pPublic_key = pPrivate_key + 32;

    ecc_opaque_ristretto255_sha512_GenerateAuthKeyPair(pPrivate_key, pPublic_key);

    mget(env, pPrivate_key, private_key, 32);
    mget(env, pPublic_key, public_key, 32);

    FREE_HEAP;
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1opaque_1ristretto255_1sha512_1CreateRegistrationRequestWithBlind(
    JNIEnv *env, jclass cls,
    jbyteArray request_raw, // 32
    jbyteArray password, int password_len,
    jbyteArray blind // 32
) {
    ECC_UNUSED(cls);

    const int heap_size = password_len + 32 + 32;
    ALLOC_HEAP;

    byte_t *pPassword = mput(env, password, heap, password_len);
    byte_t *pBlind = mput(env, blind, pPassword + password_len, 32);
    byte_t *pRequest = pBlind + 32;

    ecc_opaque_ristretto255_sha512_CreateRegistrationRequestWithBlind(
        pRequest,
        pPassword, password_len,
        pBlind
    );

    mget(env, pRequest, request_raw, 32);

    FREE_HEAP;
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1opaque_1ristretto255_1sha512_1CreateRegistrationRequest(
    JNIEnv *env, jclass cls,
    jbyteArray request_raw, // 32
    jbyteArray blind, // 32
    jbyteArray password, int password_len
) {
    ECC_UNUSED(cls);

    const int heap_size = password_len + 32 + 32;
    ALLOC_HEAP;

    byte_t *pPassword = mput(env, password, heap, password_len);
    byte_t *pRequest = pPassword + password_len;
    byte_t *pBlind = pRequest + 32;

    ecc_opaque_ristretto255_sha512_CreateRegistrationRequest(
        pRequest,
        pBlind,
        pPassword, password_len
    );

    mget(env, pRequest, request_raw, 32);
    mget(env, pBlind, blind, 32);

    FREE_HEAP;
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1opaque_1ristretto255_1sha512_1CreateRegistrationResponse(
    JNIEnv *env, jclass cls,
    jbyteArray response_raw, // 64
    jbyteArray oprf_key,  // 32
    jbyteArray request_raw, // 32
    jbyteArray server_public_key, // 32
    jbyteArray credential_identifier, int credential_identifier_len,
    jbyteArray oprf_seed // 64
) {
    ECC_UNUSED(cls);

    const int heap_size = 32 + 32 + credential_identifier_len + 64 + 64 + 32;
    ALLOC_HEAP;

    byte_t *pRequest = mput(env, request_raw, heap, 32);
    byte_t *pServer_public_key = mput(env, server_public_key, pRequest + 32, 32);
    byte_t *pCredential_identifier = mput(env, credential_identifier, pServer_public_key + 32, credential_identifier_len);
    byte_t *pOprf_seed = mput(env, oprf_seed, pCredential_identifier + credential_identifier_len, 64);
    byte_t *pResponse = pOprf_seed + 64;
    byte_t *pOprf_key = pResponse + 64;

    ecc_opaque_ristretto255_sha512_CreateRegistrationResponse(
        pResponse,
        pOprf_key,
        pRequest,
        pServer_public_key,
        pCredential_identifier, credential_identifier_len,
        pOprf_seed
    );

    mget(env, pResponse, response_raw, 64);
    mget(env, pOprf_key, oprf_key, 32);

    FREE_HEAP;
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1opaque_1ristretto255_1sha512_1FinalizeRequest(
    JNIEnv *env, jclass cls,
    jbyteArray record_raw, // RegistrationUpload_t // 192
    jbyteArray export_key, // 64
    jbyteArray client_private_key, // 32
    jbyteArray password, int password_len,
    jbyteArray blind, // 32
    jbyteArray response_raw, // RegistrationResponse_t // 64
    jbyteArray server_identity, int server_identity_len,
    jbyteArray client_identity, int client_identity_len
) {
    ECC_UNUSED(cls);

    const int heap_size = 32 + password_len + 32 + 64 + server_identity_len + client_identity_len + 192 + 64;
    ALLOC_HEAP;

    byte_t *pClient_private_key = mput(env, client_private_key, heap, 32);
    byte_t *pPassword = mput(env, password, pClient_private_key + 32, password_len);
    byte_t *pBlind = mput(env, blind, pPassword + password_len, 32);
    byte_t *pResponse = mput(env, response_raw, pBlind + 32, 64);
    byte_t *pServer_identity = mput(env, server_identity, pResponse + 64, server_identity_len);
    byte_t *pClient_identity = mput(env, client_identity, pServer_identity + server_identity_len, client_identity_len);
    byte_t *pRecord = pClient_identity + client_identity_len;
    byte_t *pExport_key = pRecord + 192;

    ecc_opaque_ristretto255_sha512_FinalizeRequest(
        pRecord,
        pExport_key,
        pClient_private_key,
        pPassword, password_len,
        pBlind,
        pResponse,
        pServer_identity, server_identity_len,
        pClient_identity, client_identity_len
    );

    mget(env, pRecord, record_raw, 192);
    mget(env, pExport_key, export_key, 64);

    FREE_HEAP;
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1opaque_1ristretto255_1sha512_13DH_1ClientInit(
    JNIEnv *env, jclass cls,
    jbyteArray ke1_raw, // 96
    jbyteArray state_raw, // 160
    jbyteArray client_identity, int client_identity_len,
    jbyteArray password, int password_len
) {
    ECC_UNUSED(cls);

    const int heap_size = 160 + client_identity_len + password_len + 96;
    ALLOC_HEAP;

    byte_t *pState = mput(env, state_raw, heap, 160);
    byte_t *pClient_identity = mput(env, client_identity, pState + 160, client_identity_len);
    byte_t *pPassword = mput(env, password, pClient_identity + client_identity_len, password_len);
    byte_t *pKe1 = pPassword + password_len;

    ecc_opaque_ristretto255_sha512_3DH_ClientInit(
        pKe1,
        pState,
        pClient_identity, client_identity_len,
        pPassword, password_len
    );

    mget(env, pState, state_raw, 160);
    mget(env, pKe1, ke1_raw, 96);

    FREE_HEAP;
}

JNIEXPORT int JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1opaque_1ristretto255_1sha512_13DH_1ClientFinish(
    JNIEnv *env, jclass cls,
    jbyteArray ke3_raw, // 64
    jbyteArray session_key, // 64
    jbyteArray export_key, // 64
    jbyteArray state_raw, // 160
    jbyteArray password, int password_len,
    jbyteArray client_identity, int client_identity_len,
    jbyteArray server_identity, int server_identity_len,
    jbyteArray ke2_raw // 320
) {
    ECC_UNUSED(cls);

    const int heap_size = 160 + password_len + client_identity_len + server_identity_len + 320 +
        64 + 64 + 64;
    ALLOC_HEAP_RET;

    byte_t *pState = mput(env, state_raw, heap, 160);
    byte_t *pPassword = mput(env, password, pState + 160, password_len);
    byte_t *pClient_identity = mput(env, client_identity, pPassword + password_len, client_identity_len);
    byte_t *pServer_identity = mput(env, server_identity, pClient_identity + client_identity_len, server_identity_len);
    byte_t *pKe2 = mput(env, ke2_raw, pServer_identity + server_identity_len, 320);
    byte_t *pKe3 = pKe2 + 320;
    byte_t *pSession_key = pKe3 + 64;
    byte_t *pExport_key = pSession_key + 64;

    int r = ecc_opaque_ristretto255_sha512_3DH_ClientFinish(
        pKe3,
        pSession_key,
        pExport_key,
        pState,
        pPassword, password_len,
        pClient_identity, client_identity_len,
        pServer_identity, server_identity_len,
        pKe2
    );

    mget(env, pState, state_raw, 160);
    mget(env, pKe3, ke3_raw, 64);
    mget(env, pSession_key, session_key, 64);
    mget(env, pExport_key, export_key, 64);

    FREE_HEAP;
    return r;
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1opaque_1ristretto255_1sha512_13DH_1ServerInit(
    JNIEnv *env, jclass cls,
    jbyteArray ke2_raw, // 320
    jbyteArray state_raw, // 128
    jbyteArray server_identity, int server_identity_len,
    jbyteArray server_private_key, // 32
    jbyteArray server_public_key, // 32
    jbyteArray record_raw, // 192
    jbyteArray credential_identifier, int credential_identifier_len,
    jbyteArray oprf_seed, // 64
    jbyteArray ke1_raw, // 96
    jbyteArray context, int context_len
) {
    ECC_UNUSED(cls);

    const int heap_size = 128 + server_identity_len + 32 + 32 + 192 + credential_identifier_len +
        64 + 96 + context_len + 320;
    ALLOC_HEAP;

    byte_t *pState = mput(env, state_raw, heap, 128);
    byte_t *pServer_identity = mput(env, server_identity, pState + 128, server_identity_len);
    byte_t *pServer_private_key = mput(env, server_private_key, pServer_identity + server_identity_len, 32);
    byte_t *pServer_public_key = mput(env, server_public_key, pServer_private_key + 32, 32);
    byte_t *pRecord = mput(env, record_raw, pServer_public_key + 32, 192);
    byte_t *pCredential_identifier = mput(env, credential_identifier, pRecord + 192, credential_identifier_len);
    byte_t *pOprf_seed = mput(env, oprf_seed, pCredential_identifier + credential_identifier_len, 64);
    byte_t *pKe1 = mput(env, ke1_raw, pOprf_seed + 64, 96);
    byte_t *pContext = mput(env, context, pKe1 + 96, context_len);
    byte_t *pKe2 = pContext + context_len;

    ecc_opaque_ristretto255_sha512_3DH_ServerInit(
        pKe2,
        pState,
        pServer_identity, server_identity_len,
        pServer_private_key,
        pServer_public_key,
        pRecord,
        pCredential_identifier, credential_identifier_len,
        pOprf_seed,
        pKe1,
        pContext, context_len
    );

    mget(env, pState, state_raw, 128);
    mget(env, pKe2, ke2_raw, 320);

    FREE_HEAP;
}

JNIEXPORT int JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1opaque_1ristretto255_1sha512_13DH_1ServerFinish(
    JNIEnv *env, jclass cls,
    jbyteArray session_key, // 64
    jbyteArray state_raw, // 128
    jbyteArray ke3_raw // 64
) {
    ECC_UNUSED(cls);

    const int heap_size = 128 + 64 + 64;
    ALLOC_HEAP_RET;

    byte_t *pState = mput(env, state_raw, heap, 128);
    byte_t *pKe3 = mput(env, ke3_raw, pState + 128, 64);
    byte_t *pSession_key = pKe3 + 64;

    int r = ecc_opaque_ristretto255_sha512_3DH_ServerFinish(
        pSession_key,
        pState,
        pKe3
    );

    mget(env, pState, state_raw, 128);
    mget(env, pSession_key, session_key, 64);

    FREE_HEAP;
    return r;
}

#ifdef __cplusplus
}
#endif
