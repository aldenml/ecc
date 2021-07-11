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

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1concat2(
    JNIEnv *env, jclass cls,
    jbyteArray out,
    jbyteArray a1, jint a1_len,
    jbyteArray a2, jint a2_len
) {
    ECC_UNUSED(cls);

    const int heap_size = 2 * (a1_len + a2_len);
    ALLOC_HEAP;

    byte_t *pA1 = mput(env, a1, heap, a1_len);
    byte_t *pA2 = mput(env, a2, pA1 + a1_len, a2_len);
    byte_t *pOut = pA2 + a2_len;

    ecc_concat2(
        pOut,
        pA1, a1_len,
        pA2, a2_len
    );

    mget(env, pOut, out, a1_len + a2_len);

    FREE_HEAP;
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1concat3(
    JNIEnv *env, jclass cls,
    jbyteArray out,
    jbyteArray a1, jint a1_len,
    jbyteArray a2, jint a2_len,
    jbyteArray a3, jint a3_len
) {
    ECC_UNUSED(cls);

    const int heap_size = 2 * (a1_len + a2_len + a3_len);
    ALLOC_HEAP;

    byte_t *pA1 = mput(env, a1, heap, a1_len);
    byte_t *pA2 = mput(env, a2, pA1 + a1_len, a2_len);
    byte_t *pA3 = mput(env, a3, pA2 + a2_len, a3_len);
    byte_t *pOut = pA3 + a3_len;

    ecc_concat3(
        pOut,
        pA1, a1_len,
        pA2, a2_len,
        pA3, a3_len
    );

    mget(env, pOut, out, a1_len + a2_len + a3_len);

    FREE_HEAP;
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1concat4(
    JNIEnv *env, jclass cls,
    jbyteArray out,
    jbyteArray a1, jint a1_len,
    jbyteArray a2, jint a2_len,
    jbyteArray a3, jint a3_len,
    jbyteArray a4, jint a4_len
) {
    ECC_UNUSED(cls);

    const int heap_size = 2 * (a1_len + a2_len + a3_len + a4_len);
    ALLOC_HEAP;

    byte_t *pA1 = mput(env, a1, heap, a1_len);
    byte_t *pA2 = mput(env, a2, pA1 + a1_len, a2_len);
    byte_t *pA3 = mput(env, a3, pA2 + a2_len, a3_len);
    byte_t *pA4 = mput(env, a4, pA3 + a3_len, a4_len);
    byte_t *pOut = pA4 + a4_len;

    ecc_concat4(
        pOut,
        pA1, a1_len,
        pA2, a2_len,
        pA3, a3_len,
        pA4, a4_len
    );

    mget(env, pOut, out, a1_len + a2_len + a3_len + a4_len);

    FREE_HEAP;
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1strxor(
    JNIEnv *env, jclass cls,
    jbyteArray out,
    jbyteArray a, jbyteArray b, jint len
) {
    ECC_UNUSED(cls);

    const int heap_size = len + len + len;
    ALLOC_HEAP;

    byte_t *pA = mput(env, a, heap, len);
    byte_t *pB = mput(env, b, pA + len, len);
    byte_t *pOut = pB + len;

    ecc_strxor(
        pOut,
        pA, pB, len
    );

    mget(env, pOut, out, len);

    FREE_HEAP;
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1I2OSP(
    JNIEnv *env, jclass cls,
    jbyteArray out,
    jint x, jint xLen
) {
    ECC_UNUSED(cls);

    const int heap_size = xLen;
    ALLOC_HEAP;

    byte_t *pOut = heap;

    ecc_I2OSP(pOut, x, xLen);

    mget(env, pOut, out, xLen);

    FREE_HEAP;
}

JNIEXPORT int JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1compare(
    JNIEnv *env, jclass cls,
    jbyteArray a, jbyteArray b, jint len
) {
    ECC_UNUSED(cls);

    const int heap_size = len + len;
    ALLOC_HEAP_RET;

    byte_t *pA = mput(env, a, heap, len);
    byte_t *pB = mput(env, b, pA + len, len);

    int r = ecc_compare(pA, pB, len);

    FREE_HEAP;
    return r;
}

JNIEXPORT int JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1is_1zero(
    JNIEnv *env, jclass cls,
    jbyteArray n, jint len
) {
    ECC_UNUSED(cls);

    const int heap_size = len;
    ALLOC_HEAP_RET;

    byte_t *pN = mput(env, n, heap, len);

    int r = ecc_is_zero(pN, len);

    FREE_HEAP;
    return r;
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1increment(
    JNIEnv *env, jclass cls,
    jbyteArray n, jint len
) {
    ECC_UNUSED(cls);

    const int heap_size = len;
    ALLOC_HEAP;

    byte_t *pN = mput(env, n, heap, len);

    ecc_increment(pN, len);

    mget(env, pN, n, len);

    FREE_HEAP;
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1add(
    JNIEnv *env, jclass cls,
    jbyteArray a, jbyteArray b, jint len
) {
    ECC_UNUSED(cls);

    const int heap_size = len + len;
    ALLOC_HEAP;

    byte_t *pA = mput(env, a, heap, len);
    byte_t *pB = mput(env, b, pA + len, len);

    ecc_add(pA, pB, len);

    mget(env, pA, a, len);

    FREE_HEAP;
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1sub(
    JNIEnv *env, jclass cls,
    jbyteArray a, jbyteArray b, jint len
) {
    ECC_UNUSED(cls);

    const int heap_size = len + len;
    ALLOC_HEAP;

    byte_t *pA = mput(env, a, heap, len);
    byte_t *pB = mput(env, b, pA + len, len);

    ecc_sub(pA, pB, len);

    mget(env, pA, a, len);

    FREE_HEAP;
}

// hash

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1hash_1sha256(
    JNIEnv *env, jclass cls,
    jbyteArray digest, jbyteArray input, jint input_len
) {
    ECC_UNUSED(cls);

    const int heap_size = input_len + 32;
    ALLOC_HEAP;

    byte_t *pInput = mput(env, input, heap, input_len);
    byte_t *pDigest = pInput + input_len;

    ecc_hash_sha256(pDigest, pInput, input_len);

    mget(env, pDigest, digest, input_len);

    FREE_HEAP;
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1hash_1sha512(
    JNIEnv *env, jclass cls,
    jbyteArray digest, jbyteArray input, jint input_len
) {
    ECC_UNUSED(cls);

    const int heap_size = input_len + 64;
    ALLOC_HEAP;

    byte_t *pInput = mput(env, input, heap, input_len);
    byte_t *pDigest = pInput + input_len;

    ecc_hash_sha512(pDigest, pInput, input_len);

    mget(env, pDigest, digest, input_len);

    FREE_HEAP;
}

// mac

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1mac_1hmac_1sha256(
    JNIEnv *env, jclass cls,
    jbyteArray digest,
    jbyteArray text, jint text_len,
    jbyteArray key
) {
    ECC_UNUSED(cls);

    const int heap_size = text_len + 32 + 32;
    ALLOC_HEAP;

    byte_t *pText = mput(env, text, heap, text_len);
    byte_t *pKey = mput(env, key, pText + text_len, 32);
    byte_t *pDigest = pKey + 32;

    ecc_mac_hmac_sha256(pDigest, pText, text_len, pKey);

    mget(env, pDigest, digest, 32);

    FREE_HEAP;
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1mac_1hmac_1sha512(
    JNIEnv *env, jclass cls,
    jbyteArray digest,
    jbyteArray text, jint text_len,
    jbyteArray key
) {
    ECC_UNUSED(cls);

    const int heap_size = text_len + 32 + 64;
    ALLOC_HEAP;

    byte_t *pText = mput(env, text, heap, text_len);
    byte_t *pKey = mput(env, key, pText + text_len, 32);
    byte_t *pDigest = pKey + 32;

    ecc_mac_hmac_sha256(pDigest, pText, text_len, pKey);

    mget(env, pDigest, digest, 64);

    FREE_HEAP;
}

// kdf

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1kdf_1hkdf_1sha256_1extract(
    JNIEnv *env, jclass cls,
    jbyteArray prk,
    jbyteArray salt, jint salt_len,
    jbyteArray ikm, jint ikm_len
) {
    ECC_UNUSED(cls);

    const int heap_size = salt_len + ikm_len + 32;
    ALLOC_HEAP;

    byte_t *pSalt = mput(env, salt, heap, salt_len);
    byte_t *pIkm = mput(env, ikm, pSalt + salt_len, ikm_len);
    byte_t *pPrk = pIkm + ikm_len;

    ecc_kdf_hkdf_sha256_extract(
        pPrk,
        pSalt, salt_len,
        pIkm, ikm_len
    );

    mget(env, pPrk, prk, 32);

    FREE_HEAP;
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1kdf_1hkdf_1sha256_1expand(
    JNIEnv *env, jclass cls,
    jbyteArray okm,
    jbyteArray prk,
    jbyteArray info, int info_len,
    int len
) {
    ECC_UNUSED(cls);

    const int heap_size = 32 + info_len + len;
    ALLOC_HEAP;

    byte_t *pPrk = mput(env, prk, heap, 32);
    byte_t *pInfo = mput(env, info, pPrk + 32, info_len);
    byte_t *pOkm = pInfo + info_len;

    ecc_kdf_hkdf_sha256_expand(
        pOkm,
        pPrk,
        pInfo, info_len,
        len
    );

    mget(env, pOkm, okm, len);

    FREE_HEAP;
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1kdf_1hkdf_1sha512_1extract(
    JNIEnv *env, jclass cls,
    jbyteArray prk,
    jbyteArray salt, jint salt_len,
    jbyteArray ikm, jint ikm_len
) {
    ECC_UNUSED(cls);

    const int heap_size = salt_len + ikm_len + 64;
    ALLOC_HEAP;

    byte_t *pSalt = mput(env, salt, heap, salt_len);
    byte_t *pIkm = mput(env, ikm, pSalt + salt_len, ikm_len);
    byte_t *pPrk = pIkm + ikm_len;

    ecc_kdf_hkdf_sha512_extract(
        pPrk,
        pSalt, salt_len,
        pIkm, ikm_len
    );

    mget(env, pPrk, prk, 64);

    FREE_HEAP;
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1kdf_1hkdf_1sha512_1expand(
    JNIEnv *env, jclass cls,
    jbyteArray okm,
    jbyteArray prk,
    jbyteArray info, int info_len,
    int len
) {
    ECC_UNUSED(cls);

    const int heap_size = 64 + info_len + len;
    ALLOC_HEAP;

    byte_t *pPrk = mput(env, prk, heap, 64);
    byte_t *pInfo = mput(env, info, pPrk + 64, info_len);
    byte_t *pOkm = pInfo + info_len;

    ecc_kdf_hkdf_sha512_expand(
        pOkm,
        pPrk,
        pInfo, info_len,
        len
    );

    mget(env, pOkm, okm, len);

    FREE_HEAP;
}

// ed25519

JNIEXPORT int JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1ed25519_1is_1valid_1point(
    JNIEnv *env, jclass cls,
    jbyteArray p
) {
    ECC_UNUSED(cls);

    const int heap_size = 32;
    ALLOC_HEAP_RET;

    byte_t *pP = mput(env, p, heap, 32);

    int r = ecc_ed25519_is_valid_point(pP);

    FREE_HEAP;
    return r;
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1ed25519_1random(
    JNIEnv *env, jclass cls,
    jbyteArray p
) {
    ECC_UNUSED(cls);

    const int heap_size = 32;
    ALLOC_HEAP;

    byte_t *pP = heap;

    ecc_ed25519_random(pP);

    mget(env, pP, p, 32);

    FREE_HEAP;
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1ed25519_1sign_1keypair(
    JNIEnv *env, jclass cls,
    jbyteArray pk, jbyteArray sk
) {
    ECC_UNUSED(cls);

    const int heap_size = 32 + 64;
    ALLOC_HEAP;

    byte_t *pPk = heap;
    byte_t *pSk = pPk + 32;

    ecc_ed25519_sign_keypair(pPk, pSk);

    mget(env, pPk, pk, 32);
    mget(env, pSk, sk, 64);

    FREE_HEAP;
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1ed25519_1sign_1seed_1keypair(
    JNIEnv *env, jclass cls,
    jbyteArray pk, jbyteArray sk,
    jbyteArray seed
) {
    ECC_UNUSED(cls);

    const int heap_size = 32 + 32 + 64;
    ALLOC_HEAP;

    byte_t *pSeed = mput(env, seed, heap, 32);
    byte_t *pPk = pSeed + 32;
    byte_t *pSk = pPk + 32;

    ecc_ed25519_sign_seed_keypair(pPk, pSk, pSeed);

    mget(env, pPk, pk, 32);
    mget(env, pSk, sk, 64);

    FREE_HEAP;
}

// ristretto255

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1ristretto255_1from_1hash(
    JNIEnv *env, jclass cls,
    jbyteArray p,
    jbyteArray r
) {
    ECC_UNUSED(cls);

    const int heap_size = 64 + 32;
    ALLOC_HEAP;

    byte_t *pR = mput(env, r, heap, 64);
    byte_t *pP = pR + 64;

    ecc_ristretto255_from_hash(pP, pR);

    mget(env, pP, p, 32);

    FREE_HEAP;
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1ristretto255_1scalar_1random(
    JNIEnv *env, jclass cls,
    jbyteArray r
) {
    ECC_UNUSED(cls);

    const int heap_size = 32;
    ALLOC_HEAP;

    byte_t *pR = heap;

    ecc_ristretto255_scalar_random(pR);

    mget(env, pR, r, 32);

    FREE_HEAP;
}

JNIEXPORT int JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1ristretto255_1scalar_1invert(
    JNIEnv *env, jclass cls,
    jbyteArray recip,
    jbyteArray s
) {
    ECC_UNUSED(cls);

    const int heap_size = 32 + 32;
    ALLOC_HEAP_RET;

    byte_t *pS = mput(env, s, heap, 32);
    byte_t *pRecip = pS + 32;

    int r = ecc_ristretto255_scalar_invert(pRecip, pS);

    mget(env, pRecip, recip, 32);

    FREE_HEAP;
    return r;
}

JNIEXPORT int JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1ristretto255_1scalarmult(
    JNIEnv *env, jclass cls,
    jbyteArray q,
    jbyteArray n,
    jbyteArray p
) {
    ECC_UNUSED(cls);

    const int heap_size = 32 + 32 + 32;
    ALLOC_HEAP_RET;

    byte_t *pN = mput(env, n, heap, 32);
    byte_t *pP = mput(env, p, pN + 32, 32);
    byte_t *pQ = pP + 32;

    int r = ecc_ristretto255_scalarmult(pQ, pN, pP);

    mget(env, pQ, q, 32);

    FREE_HEAP;
    return r;
}

// bls12_381

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1bls12_1381_1keygen(
    JNIEnv *env, jclass cls,
    jbyteArray out_SK,
    jbyteArray IKM,
    jint IKM_len
) {
    ECC_UNUSED(cls);

    const int heap_size = IKM_len + 32;
    ALLOC_HEAP;

    byte_t *pIKM = mput(env, IKM, heap, IKM_len);
    byte_t *pOut_SK = pIKM + IKM_len;

    ecc_bls12_381_keygen(pOut_SK, pIKM, IKM_len);

    mget(env, pOut_SK, out_SK, 32);

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

// oprf

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1oprf_1ristretto255_1sha512_1Evaluate(
    JNIEnv *env, jclass cls,
    jbyteArray evaluatedElement, // 32
    jbyteArray skS, // 32
    jbyteArray blindedElement // 32
) {
    ECC_UNUSED(cls);

    const int heap_size = 32 + 32 + 32;
    ALLOC_HEAP;

    byte_t *pSkS = mput(env, skS, heap, 32);
    byte_t *pBlindedElement = mput(env, blindedElement, pSkS + 32, 32);
    byte_t *pEvaluatedElement = pBlindedElement + 32;

    ecc_oprf_ristretto255_sha512_Evaluate(
        pEvaluatedElement,
        pSkS,
        pEvaluatedElement
    );

    mget(env, pEvaluatedElement, evaluatedElement, 32);

    FREE_HEAP;
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1oprf_1ristretto255_1sha512_1Finalize(
    JNIEnv *env, jclass cls,
    jbyteArray output,
    jbyteArray input, jint input_len,
    jbyteArray blind,
    jbyteArray evaluatedElement,
    jint mode
) {
    ECC_UNUSED(cls);

    const int heap_size = input_len + 32 + 32 + 64;
    ALLOC_HEAP;

    byte_t *pInput = mput(env, input, heap, input_len);
    byte_t *pBlind = mput(env, blind, pInput + input_len, 32);
    byte_t *pEvaluatedElement = mput(env, evaluatedElement, pBlind + 32, 32);
    byte_t *pOutput = pEvaluatedElement + 32;

    ecc_oprf_ristretto255_sha512_Finalize(
        pOutput,
        pInput, input_len,
        pBlind,
        pEvaluatedElement,
        mode
    );

    mget(env, pOutput, output, 64);

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
