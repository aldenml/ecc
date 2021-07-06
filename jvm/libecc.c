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

#ifdef __cplusplus
}
#endif
