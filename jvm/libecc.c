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

#ifdef __cplusplus
extern "C" {
#endif

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1randombytes(
    JNIEnv *env, jclass cls,
    jbyteArray buf,
    jint len
) {
    byte_t *pBuf = malloc(len);
    if (!pBuf) {
        throw_OutOfMemoryError(env);
        return;
    }

    ecc_randombytes(pBuf, len);

    (*env)->SetByteArrayRegion(env, buf, 0, len, (jbyte *) pBuf);

    ecc_memzero(pBuf, len);
    free(pBuf);
}

#ifdef __cplusplus
}
#endif
