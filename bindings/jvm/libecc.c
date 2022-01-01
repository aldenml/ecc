/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#include "jni.h"
#include <ecc.h>

byte_t *mput(JNIEnv *env, jbyteArray src, int size) {
    if (src != NULL) {
        byte_t *ptr = ecc_malloc(size);
        (*env)->GetByteArrayRegion(env, src, 0, size, (jbyte *) ptr);
        return ptr;
    }
    return NULL;
}

void mget(JNIEnv *env, jbyteArray dest, byte_t *ptr, int size) {
    (*env)->SetByteArrayRegion(env, dest, 0, size, (jbyte *) ptr);
}

void mfree(byte_t *ptr, int size) {
    ecc_free(ptr, size);
}

#ifdef __cplusplus
extern "C" {
#endif

// util

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1randombytes(
    JNIEnv *env, jclass cls,
    jbyteArray buf,
    jint n
) {
    byte_t *ptr_buf = mput(env, buf, n);
    ecc_randombytes(
        ptr_buf,
        n
    );
    mget(env, buf, ptr_buf, n);
    mfree(ptr_buf, n);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1concat2(
    JNIEnv *env, jclass cls,
    jbyteArray out,
    jbyteArray a1,
    jint a1_len,
    jbyteArray a2,
    jint a2_len
) {
    byte_t *ptr_out = mput(env, out, a1_len+a2_len);
    byte_t *ptr_a1 = mput(env, a1, a1_len);
    byte_t *ptr_a2 = mput(env, a2, a2_len);
    ecc_concat2(
        ptr_out,
        ptr_a1,
        a1_len,
        ptr_a2,
        a2_len
    );
    mget(env, out, ptr_out, a1_len+a2_len);
    mfree(ptr_out, a1_len+a2_len);
    mfree(ptr_a1, a1_len);
    mfree(ptr_a2, a2_len);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1concat3(
    JNIEnv *env, jclass cls,
    jbyteArray out,
    jbyteArray a1,
    jint a1_len,
    jbyteArray a2,
    jint a2_len,
    jbyteArray a3,
    jint a3_len
) {
    byte_t *ptr_out = mput(env, out, a1_len+a2_len+a3_len);
    byte_t *ptr_a1 = mput(env, a1, a1_len);
    byte_t *ptr_a2 = mput(env, a2, a2_len);
    byte_t *ptr_a3 = mput(env, a3, a3_len);
    ecc_concat3(
        ptr_out,
        ptr_a1,
        a1_len,
        ptr_a2,
        a2_len,
        ptr_a3,
        a3_len
    );
    mget(env, out, ptr_out, a1_len+a2_len+a3_len);
    mfree(ptr_out, a1_len+a2_len+a3_len);
    mfree(ptr_a1, a1_len);
    mfree(ptr_a2, a2_len);
    mfree(ptr_a3, a3_len);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1concat4(
    JNIEnv *env, jclass cls,
    jbyteArray out,
    jbyteArray a1,
    jint a1_len,
    jbyteArray a2,
    jint a2_len,
    jbyteArray a3,
    jint a3_len,
    jbyteArray a4,
    jint a4_len
) {
    byte_t *ptr_out = mput(env, out, a1_len+a2_len+a3_len+a4_len);
    byte_t *ptr_a1 = mput(env, a1, a1_len);
    byte_t *ptr_a2 = mput(env, a2, a2_len);
    byte_t *ptr_a3 = mput(env, a3, a3_len);
    byte_t *ptr_a4 = mput(env, a4, a4_len);
    ecc_concat4(
        ptr_out,
        ptr_a1,
        a1_len,
        ptr_a2,
        a2_len,
        ptr_a3,
        a3_len,
        ptr_a4,
        a4_len
    );
    mget(env, out, ptr_out, a1_len+a2_len+a3_len+a4_len);
    mfree(ptr_out, a1_len+a2_len+a3_len+a4_len);
    mfree(ptr_a1, a1_len);
    mfree(ptr_a2, a2_len);
    mfree(ptr_a3, a3_len);
    mfree(ptr_a4, a4_len);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1strxor(
    JNIEnv *env, jclass cls,
    jbyteArray out,
    jbyteArray a,
    jbyteArray b,
    jint len
) {
    byte_t *ptr_out = mput(env, out, len);
    byte_t *ptr_a = mput(env, a, len);
    byte_t *ptr_b = mput(env, b, len);
    ecc_strxor(
        ptr_out,
        ptr_a,
        ptr_b,
        len
    );
    mget(env, out, ptr_out, len);
    mfree(ptr_out, len);
    mfree(ptr_a, len);
    mfree(ptr_b, len);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1I2OSP(
    JNIEnv *env, jclass cls,
    jbyteArray out,
    jint x,
    jint xLen
) {
    byte_t *ptr_out = mput(env, out, xLen);
    ecc_I2OSP(
        ptr_out,
        x,
        xLen
    );
    mget(env, out, ptr_out, xLen);
    mfree(ptr_out, xLen);
}

JNIEXPORT int JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1compare(
    JNIEnv *env, jclass cls,
    jbyteArray a,
    jbyteArray b,
    jint len
) {
    byte_t *ptr_a = mput(env, a, len);
    byte_t *ptr_b = mput(env, b, len);
    const int fun_ret = ecc_compare(
        ptr_a,
        ptr_b,
        len
    );
    mfree(ptr_a, len);
    mfree(ptr_b, len);
    return fun_ret;
}

JNIEXPORT int JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1is_1zero(
    JNIEnv *env, jclass cls,
    jbyteArray n,
    jint len
) {
    byte_t *ptr_n = mput(env, n, len);
    const int fun_ret = ecc_is_zero(
        ptr_n,
        len
    );
    mfree(ptr_n, len);
    return fun_ret;
}

// hash

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1hash_1sha256(
    JNIEnv *env, jclass cls,
    jbyteArray digest,
    jbyteArray input,
    jint input_len
) {
    byte_t *ptr_digest = mput(env, digest, ecc_hash_sha256_SIZE);
    byte_t *ptr_input = mput(env, input, input_len);
    ecc_hash_sha256(
        ptr_digest,
        ptr_input,
        input_len
    );
    mget(env, digest, ptr_digest, ecc_hash_sha256_SIZE);
    mfree(ptr_digest, ecc_hash_sha256_SIZE);
    mfree(ptr_input, input_len);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1hash_1sha512(
    JNIEnv *env, jclass cls,
    jbyteArray digest,
    jbyteArray input,
    jint input_len
) {
    byte_t *ptr_digest = mput(env, digest, ecc_hash_sha512_SIZE);
    byte_t *ptr_input = mput(env, input, input_len);
    ecc_hash_sha512(
        ptr_digest,
        ptr_input,
        input_len
    );
    mget(env, digest, ptr_digest, ecc_hash_sha512_SIZE);
    mfree(ptr_digest, ecc_hash_sha512_SIZE);
    mfree(ptr_input, input_len);
}

// mac

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1mac_1hmac_1sha256(
    JNIEnv *env, jclass cls,
    jbyteArray digest,
    jbyteArray text,
    jint text_len,
    jbyteArray key
) {
    byte_t *ptr_digest = mput(env, digest, ecc_mac_hmac_sha256_SIZE);
    byte_t *ptr_text = mput(env, text, text_len);
    byte_t *ptr_key = mput(env, key, ecc_mac_hmac_sha256_KEYSIZE);
    ecc_mac_hmac_sha256(
        ptr_digest,
        ptr_text,
        text_len,
        ptr_key
    );
    mget(env, digest, ptr_digest, ecc_mac_hmac_sha256_SIZE);
    mfree(ptr_digest, ecc_mac_hmac_sha256_SIZE);
    mfree(ptr_text, text_len);
    mfree(ptr_key, ecc_mac_hmac_sha256_KEYSIZE);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1mac_1hmac_1sha512(
    JNIEnv *env, jclass cls,
    jbyteArray digest,
    jbyteArray text,
    jint text_len,
    jbyteArray key
) {
    byte_t *ptr_digest = mput(env, digest, ecc_mac_hmac_sha512_SIZE);
    byte_t *ptr_text = mput(env, text, text_len);
    byte_t *ptr_key = mput(env, key, ecc_mac_hmac_sha512_KEYSIZE);
    ecc_mac_hmac_sha512(
        ptr_digest,
        ptr_text,
        text_len,
        ptr_key
    );
    mget(env, digest, ptr_digest, ecc_mac_hmac_sha512_SIZE);
    mfree(ptr_digest, ecc_mac_hmac_sha512_SIZE);
    mfree(ptr_text, text_len);
    mfree(ptr_key, ecc_mac_hmac_sha512_KEYSIZE);
}

// kdf

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1kdf_1hkdf_1sha256_1extract(
    JNIEnv *env, jclass cls,
    jbyteArray prk,
    jbyteArray salt,
    jint salt_len,
    jbyteArray ikm,
    jint ikm_len
) {
    byte_t *ptr_prk = mput(env, prk, ecc_kdf_hkdf_sha256_KEYSIZE);
    byte_t *ptr_salt = mput(env, salt, salt_len);
    byte_t *ptr_ikm = mput(env, ikm, ikm_len);
    ecc_kdf_hkdf_sha256_extract(
        ptr_prk,
        ptr_salt,
        salt_len,
        ptr_ikm,
        ikm_len
    );
    mget(env, prk, ptr_prk, ecc_kdf_hkdf_sha256_KEYSIZE);
    mfree(ptr_prk, ecc_kdf_hkdf_sha256_KEYSIZE);
    mfree(ptr_salt, salt_len);
    mfree(ptr_ikm, ikm_len);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1kdf_1hkdf_1sha256_1expand(
    JNIEnv *env, jclass cls,
    jbyteArray okm,
    jbyteArray prk,
    jbyteArray info,
    jint info_len,
    jint len
) {
    byte_t *ptr_okm = mput(env, okm, len);
    byte_t *ptr_prk = mput(env, prk, ecc_kdf_hkdf_sha256_KEYSIZE);
    byte_t *ptr_info = mput(env, info, info_len);
    ecc_kdf_hkdf_sha256_expand(
        ptr_okm,
        ptr_prk,
        ptr_info,
        info_len,
        len
    );
    mget(env, okm, ptr_okm, len);
    mfree(ptr_okm, len);
    mfree(ptr_prk, ecc_kdf_hkdf_sha256_KEYSIZE);
    mfree(ptr_info, info_len);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1kdf_1hkdf_1sha512_1extract(
    JNIEnv *env, jclass cls,
    jbyteArray prk,
    jbyteArray salt,
    jint salt_len,
    jbyteArray ikm,
    jint ikm_len
) {
    byte_t *ptr_prk = mput(env, prk, ecc_kdf_hkdf_sha512_KEYSIZE);
    byte_t *ptr_salt = mput(env, salt, salt_len);
    byte_t *ptr_ikm = mput(env, ikm, ikm_len);
    ecc_kdf_hkdf_sha512_extract(
        ptr_prk,
        ptr_salt,
        salt_len,
        ptr_ikm,
        ikm_len
    );
    mget(env, prk, ptr_prk, ecc_kdf_hkdf_sha512_KEYSIZE);
    mfree(ptr_prk, ecc_kdf_hkdf_sha512_KEYSIZE);
    mfree(ptr_salt, salt_len);
    mfree(ptr_ikm, ikm_len);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1kdf_1hkdf_1sha512_1expand(
    JNIEnv *env, jclass cls,
    jbyteArray okm,
    jbyteArray prk,
    jbyteArray info,
    jint info_len,
    jint len
) {
    byte_t *ptr_okm = mput(env, okm, len);
    byte_t *ptr_prk = mput(env, prk, ecc_kdf_hkdf_sha512_KEYSIZE);
    byte_t *ptr_info = mput(env, info, info_len);
    ecc_kdf_hkdf_sha512_expand(
        ptr_okm,
        ptr_prk,
        ptr_info,
        info_len,
        len
    );
    mget(env, okm, ptr_okm, len);
    mfree(ptr_okm, len);
    mfree(ptr_prk, ecc_kdf_hkdf_sha512_KEYSIZE);
    mfree(ptr_info, info_len);
}

// ed25519

JNIEXPORT int JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1ed25519_1is_1valid_1point(
    JNIEnv *env, jclass cls,
    jbyteArray p
) {
    byte_t *ptr_p = mput(env, p, ecc_ed25519_SIZE);
    const int fun_ret = ecc_ed25519_is_valid_point(
        ptr_p
    );
    mfree(ptr_p, ecc_ed25519_SIZE);
    return fun_ret;
}

JNIEXPORT int JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1ed25519_1add(
    JNIEnv *env, jclass cls,
    jbyteArray r,
    jbyteArray p,
    jbyteArray q
) {
    byte_t *ptr_r = mput(env, r, ecc_ed25519_SIZE);
    byte_t *ptr_p = mput(env, p, ecc_ed25519_SIZE);
    byte_t *ptr_q = mput(env, q, ecc_ed25519_SIZE);
    const int fun_ret = ecc_ed25519_add(
        ptr_r,
        ptr_p,
        ptr_q
    );
    mget(env, r, ptr_r, ecc_ed25519_SIZE);
    mfree(ptr_r, ecc_ed25519_SIZE);
    mfree(ptr_p, ecc_ed25519_SIZE);
    mfree(ptr_q, ecc_ed25519_SIZE);
    return fun_ret;
}

JNIEXPORT int JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1ed25519_1sub(
    JNIEnv *env, jclass cls,
    jbyteArray r,
    jbyteArray p,
    jbyteArray q
) {
    byte_t *ptr_r = mput(env, r, ecc_ed25519_SIZE);
    byte_t *ptr_p = mput(env, p, ecc_ed25519_SIZE);
    byte_t *ptr_q = mput(env, q, ecc_ed25519_SIZE);
    const int fun_ret = ecc_ed25519_sub(
        ptr_r,
        ptr_p,
        ptr_q
    );
    mget(env, r, ptr_r, ecc_ed25519_SIZE);
    mfree(ptr_r, ecc_ed25519_SIZE);
    mfree(ptr_p, ecc_ed25519_SIZE);
    mfree(ptr_q, ecc_ed25519_SIZE);
    return fun_ret;
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1ed25519_1from_1uniform(
    JNIEnv *env, jclass cls,
    jbyteArray p,
    jbyteArray r
) {
    byte_t *ptr_p = mput(env, p, ecc_ed25519_SIZE);
    byte_t *ptr_r = mput(env, r, ecc_ed25519_UNIFORMSIZE);
    ecc_ed25519_from_uniform(
        ptr_p,
        ptr_r
    );
    mget(env, p, ptr_p, ecc_ed25519_SIZE);
    mfree(ptr_p, ecc_ed25519_SIZE);
    mfree(ptr_r, ecc_ed25519_UNIFORMSIZE);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1ed25519_1random(
    JNIEnv *env, jclass cls,
    jbyteArray p
) {
    byte_t *ptr_p = mput(env, p, ecc_ed25519_SIZE);
    ecc_ed25519_random(
        ptr_p
    );
    mget(env, p, ptr_p, ecc_ed25519_SIZE);
    mfree(ptr_p, ecc_ed25519_SIZE);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1ed25519_1scalar_1random(
    JNIEnv *env, jclass cls,
    jbyteArray r
) {
    byte_t *ptr_r = mput(env, r, ecc_ed25519_SCALARSIZE);
    ecc_ed25519_scalar_random(
        ptr_r
    );
    mget(env, r, ptr_r, ecc_ed25519_SCALARSIZE);
    mfree(ptr_r, ecc_ed25519_SCALARSIZE);
}

JNIEXPORT int JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1ed25519_1scalar_1invert(
    JNIEnv *env, jclass cls,
    jbyteArray recip,
    jbyteArray s
) {
    byte_t *ptr_recip = mput(env, recip, ecc_ed25519_SCALARSIZE);
    byte_t *ptr_s = mput(env, s, ecc_ed25519_SCALARSIZE);
    const int fun_ret = ecc_ed25519_scalar_invert(
        ptr_recip,
        ptr_s
    );
    mget(env, recip, ptr_recip, ecc_ed25519_SCALARSIZE);
    mfree(ptr_recip, ecc_ed25519_SCALARSIZE);
    mfree(ptr_s, ecc_ed25519_SCALARSIZE);
    return fun_ret;
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1ed25519_1scalar_1negate(
    JNIEnv *env, jclass cls,
    jbyteArray neg,
    jbyteArray s
) {
    byte_t *ptr_neg = mput(env, neg, ecc_ed25519_SCALARSIZE);
    byte_t *ptr_s = mput(env, s, ecc_ed25519_SCALARSIZE);
    ecc_ed25519_scalar_negate(
        ptr_neg,
        ptr_s
    );
    mget(env, neg, ptr_neg, ecc_ed25519_SCALARSIZE);
    mfree(ptr_neg, ecc_ed25519_SCALARSIZE);
    mfree(ptr_s, ecc_ed25519_SCALARSIZE);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1ed25519_1scalar_1complement(
    JNIEnv *env, jclass cls,
    jbyteArray comp,
    jbyteArray s
) {
    byte_t *ptr_comp = mput(env, comp, ecc_ed25519_SCALARSIZE);
    byte_t *ptr_s = mput(env, s, ecc_ed25519_SCALARSIZE);
    ecc_ed25519_scalar_complement(
        ptr_comp,
        ptr_s
    );
    mget(env, comp, ptr_comp, ecc_ed25519_SCALARSIZE);
    mfree(ptr_comp, ecc_ed25519_SCALARSIZE);
    mfree(ptr_s, ecc_ed25519_SCALARSIZE);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1ed25519_1scalar_1add(
    JNIEnv *env, jclass cls,
    jbyteArray z,
    jbyteArray x,
    jbyteArray y
) {
    byte_t *ptr_z = mput(env, z, ecc_ed25519_SCALARSIZE);
    byte_t *ptr_x = mput(env, x, ecc_ed25519_SCALARSIZE);
    byte_t *ptr_y = mput(env, y, ecc_ed25519_SCALARSIZE);
    ecc_ed25519_scalar_add(
        ptr_z,
        ptr_x,
        ptr_y
    );
    mget(env, z, ptr_z, ecc_ed25519_SCALARSIZE);
    mfree(ptr_z, ecc_ed25519_SCALARSIZE);
    mfree(ptr_x, ecc_ed25519_SCALARSIZE);
    mfree(ptr_y, ecc_ed25519_SCALARSIZE);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1ed25519_1scalar_1sub(
    JNIEnv *env, jclass cls,
    jbyteArray z,
    jbyteArray x,
    jbyteArray y
) {
    byte_t *ptr_z = mput(env, z, ecc_ed25519_SCALARSIZE);
    byte_t *ptr_x = mput(env, x, ecc_ed25519_SCALARSIZE);
    byte_t *ptr_y = mput(env, y, ecc_ed25519_SCALARSIZE);
    ecc_ed25519_scalar_sub(
        ptr_z,
        ptr_x,
        ptr_y
    );
    mget(env, z, ptr_z, ecc_ed25519_SCALARSIZE);
    mfree(ptr_z, ecc_ed25519_SCALARSIZE);
    mfree(ptr_x, ecc_ed25519_SCALARSIZE);
    mfree(ptr_y, ecc_ed25519_SCALARSIZE);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1ed25519_1scalar_1mul(
    JNIEnv *env, jclass cls,
    jbyteArray z,
    jbyteArray x,
    jbyteArray y
) {
    byte_t *ptr_z = mput(env, z, ecc_ed25519_SCALARSIZE);
    byte_t *ptr_x = mput(env, x, ecc_ed25519_SCALARSIZE);
    byte_t *ptr_y = mput(env, y, ecc_ed25519_SCALARSIZE);
    ecc_ed25519_scalar_mul(
        ptr_z,
        ptr_x,
        ptr_y
    );
    mget(env, z, ptr_z, ecc_ed25519_SCALARSIZE);
    mfree(ptr_z, ecc_ed25519_SCALARSIZE);
    mfree(ptr_x, ecc_ed25519_SCALARSIZE);
    mfree(ptr_y, ecc_ed25519_SCALARSIZE);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1ed25519_1scalar_1reduce(
    JNIEnv *env, jclass cls,
    jbyteArray r,
    jbyteArray s
) {
    byte_t *ptr_r = mput(env, r, ecc_ed25519_SCALARSIZE);
    byte_t *ptr_s = mput(env, s, ecc_ed25519_NONREDUCEDSCALARSIZE);
    ecc_ed25519_scalar_reduce(
        ptr_r,
        ptr_s
    );
    mget(env, r, ptr_r, ecc_ed25519_SCALARSIZE);
    mfree(ptr_r, ecc_ed25519_SCALARSIZE);
    mfree(ptr_s, ecc_ed25519_NONREDUCEDSCALARSIZE);
}

JNIEXPORT int JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1ed25519_1scalarmult(
    JNIEnv *env, jclass cls,
    jbyteArray q,
    jbyteArray n,
    jbyteArray p
) {
    byte_t *ptr_q = mput(env, q, ecc_ed25519_SIZE);
    byte_t *ptr_n = mput(env, n, ecc_ed25519_SCALARSIZE);
    byte_t *ptr_p = mput(env, p, ecc_ed25519_SIZE);
    const int fun_ret = ecc_ed25519_scalarmult(
        ptr_q,
        ptr_n,
        ptr_p
    );
    mget(env, q, ptr_q, ecc_ed25519_SIZE);
    mfree(ptr_q, ecc_ed25519_SIZE);
    mfree(ptr_n, ecc_ed25519_SCALARSIZE);
    mfree(ptr_p, ecc_ed25519_SIZE);
    return fun_ret;
}

JNIEXPORT int JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1ed25519_1scalarmult_1base(
    JNIEnv *env, jclass cls,
    jbyteArray q,
    jbyteArray n
) {
    byte_t *ptr_q = mput(env, q, ecc_ed25519_SIZE);
    byte_t *ptr_n = mput(env, n, ecc_ed25519_SCALARSIZE);
    const int fun_ret = ecc_ed25519_scalarmult_base(
        ptr_q,
        ptr_n
    );
    mget(env, q, ptr_q, ecc_ed25519_SIZE);
    mfree(ptr_q, ecc_ed25519_SIZE);
    mfree(ptr_n, ecc_ed25519_SCALARSIZE);
    return fun_ret;
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1ed25519_1sign(
    JNIEnv *env, jclass cls,
    jbyteArray sig,
    jbyteArray msg,
    jint msg_len,
    jbyteArray sk
) {
    byte_t *ptr_sig = mput(env, sig, ecc_ed25519_sign_SIZE);
    byte_t *ptr_msg = mput(env, msg, msg_len);
    byte_t *ptr_sk = mput(env, sk, ecc_ed25519_sign_SECRETKEYSIZE);
    ecc_ed25519_sign(
        ptr_sig,
        ptr_msg,
        msg_len,
        ptr_sk
    );
    mget(env, sig, ptr_sig, ecc_ed25519_sign_SIZE);
    mfree(ptr_sig, ecc_ed25519_sign_SIZE);
    mfree(ptr_msg, msg_len);
    mfree(ptr_sk, ecc_ed25519_sign_SECRETKEYSIZE);
}

JNIEXPORT int JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1ed25519_1sign_1verify(
    JNIEnv *env, jclass cls,
    jbyteArray sig,
    jbyteArray msg,
    jint msg_len,
    jbyteArray pk
) {
    byte_t *ptr_sig = mput(env, sig, ecc_ed25519_sign_SIZE);
    byte_t *ptr_msg = mput(env, msg, msg_len);
    byte_t *ptr_pk = mput(env, pk, ecc_ed25519_sign_PUBLICKEYSIZE);
    const int fun_ret = ecc_ed25519_sign_verify(
        ptr_sig,
        ptr_msg,
        msg_len,
        ptr_pk
    );
    mfree(ptr_sig, ecc_ed25519_sign_SIZE);
    mfree(ptr_msg, msg_len);
    mfree(ptr_pk, ecc_ed25519_sign_PUBLICKEYSIZE);
    return fun_ret;
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1ed25519_1sign_1keypair(
    JNIEnv *env, jclass cls,
    jbyteArray pk,
    jbyteArray sk
) {
    byte_t *ptr_pk = mput(env, pk, ecc_ed25519_sign_PUBLICKEYSIZE);
    byte_t *ptr_sk = mput(env, sk, ecc_ed25519_sign_SECRETKEYSIZE);
    ecc_ed25519_sign_keypair(
        ptr_pk,
        ptr_sk
    );
    mget(env, pk, ptr_pk, ecc_ed25519_sign_PUBLICKEYSIZE);
    mget(env, sk, ptr_sk, ecc_ed25519_sign_SECRETKEYSIZE);
    mfree(ptr_pk, ecc_ed25519_sign_PUBLICKEYSIZE);
    mfree(ptr_sk, ecc_ed25519_sign_SECRETKEYSIZE);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1ed25519_1sign_1seed_1keypair(
    JNIEnv *env, jclass cls,
    jbyteArray pk,
    jbyteArray sk,
    jbyteArray seed
) {
    byte_t *ptr_pk = mput(env, pk, ecc_ed25519_sign_PUBLICKEYSIZE);
    byte_t *ptr_sk = mput(env, sk, ecc_ed25519_sign_SECRETKEYSIZE);
    byte_t *ptr_seed = mput(env, seed, ecc_ed25519_sign_SEEDSIZE);
    ecc_ed25519_sign_seed_keypair(
        ptr_pk,
        ptr_sk,
        ptr_seed
    );
    mget(env, pk, ptr_pk, ecc_ed25519_sign_PUBLICKEYSIZE);
    mget(env, sk, ptr_sk, ecc_ed25519_sign_SECRETKEYSIZE);
    mfree(ptr_pk, ecc_ed25519_sign_PUBLICKEYSIZE);
    mfree(ptr_sk, ecc_ed25519_sign_SECRETKEYSIZE);
    mfree(ptr_seed, ecc_ed25519_sign_SEEDSIZE);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1ed25519_1sign_1sk_1to_1seed(
    JNIEnv *env, jclass cls,
    jbyteArray seed,
    jbyteArray sk
) {
    byte_t *ptr_seed = mput(env, seed, ecc_ed25519_sign_SEEDSIZE);
    byte_t *ptr_sk = mput(env, sk, ecc_ed25519_sign_SECRETKEYSIZE);
    ecc_ed25519_sign_sk_to_seed(
        ptr_seed,
        ptr_sk
    );
    mget(env, seed, ptr_seed, ecc_ed25519_sign_SEEDSIZE);
    mfree(ptr_seed, ecc_ed25519_sign_SEEDSIZE);
    mfree(ptr_sk, ecc_ed25519_sign_SECRETKEYSIZE);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1ed25519_1sign_1sk_1to_1pk(
    JNIEnv *env, jclass cls,
    jbyteArray pk,
    jbyteArray sk
) {
    byte_t *ptr_pk = mput(env, pk, ecc_ed25519_sign_PUBLICKEYSIZE);
    byte_t *ptr_sk = mput(env, sk, ecc_ed25519_sign_SECRETKEYSIZE);
    ecc_ed25519_sign_sk_to_pk(
        ptr_pk,
        ptr_sk
    );
    mget(env, pk, ptr_pk, ecc_ed25519_sign_PUBLICKEYSIZE);
    mfree(ptr_pk, ecc_ed25519_sign_PUBLICKEYSIZE);
    mfree(ptr_sk, ecc_ed25519_sign_SECRETKEYSIZE);
}

// ristretto255

JNIEXPORT int JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1ristretto255_1is_1valid_1point(
    JNIEnv *env, jclass cls,
    jbyteArray p
) {
    byte_t *ptr_p = mput(env, p, ecc_ristretto255_SIZE);
    const int fun_ret = ecc_ristretto255_is_valid_point(
        ptr_p
    );
    mfree(ptr_p, ecc_ristretto255_SIZE);
    return fun_ret;
}

JNIEXPORT int JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1ristretto255_1add(
    JNIEnv *env, jclass cls,
    jbyteArray r,
    jbyteArray p,
    jbyteArray q
) {
    byte_t *ptr_r = mput(env, r, ecc_ristretto255_SIZE);
    byte_t *ptr_p = mput(env, p, ecc_ristretto255_SIZE);
    byte_t *ptr_q = mput(env, q, ecc_ristretto255_SIZE);
    const int fun_ret = ecc_ristretto255_add(
        ptr_r,
        ptr_p,
        ptr_q
    );
    mget(env, r, ptr_r, ecc_ristretto255_SIZE);
    mfree(ptr_r, ecc_ristretto255_SIZE);
    mfree(ptr_p, ecc_ristretto255_SIZE);
    mfree(ptr_q, ecc_ristretto255_SIZE);
    return fun_ret;
}

JNIEXPORT int JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1ristretto255_1sub(
    JNIEnv *env, jclass cls,
    jbyteArray r,
    jbyteArray p,
    jbyteArray q
) {
    byte_t *ptr_r = mput(env, r, ecc_ristretto255_SIZE);
    byte_t *ptr_p = mput(env, p, ecc_ristretto255_SIZE);
    byte_t *ptr_q = mput(env, q, ecc_ristretto255_SIZE);
    const int fun_ret = ecc_ristretto255_sub(
        ptr_r,
        ptr_p,
        ptr_q
    );
    mget(env, r, ptr_r, ecc_ristretto255_SIZE);
    mfree(ptr_r, ecc_ristretto255_SIZE);
    mfree(ptr_p, ecc_ristretto255_SIZE);
    mfree(ptr_q, ecc_ristretto255_SIZE);
    return fun_ret;
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1ristretto255_1generator(
    JNIEnv *env, jclass cls,
    jbyteArray g
) {
    byte_t *ptr_g = mput(env, g, ecc_ristretto255_SIZE);
    ecc_ristretto255_generator(
        ptr_g
    );
    mget(env, g, ptr_g, ecc_ristretto255_SIZE);
    mfree(ptr_g, ecc_ristretto255_SIZE);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1ristretto255_1from_1hash(
    JNIEnv *env, jclass cls,
    jbyteArray p,
    jbyteArray r
) {
    byte_t *ptr_p = mput(env, p, ecc_ristretto255_SIZE);
    byte_t *ptr_r = mput(env, r, ecc_ristretto255_HASHSIZE);
    ecc_ristretto255_from_hash(
        ptr_p,
        ptr_r
    );
    mget(env, p, ptr_p, ecc_ristretto255_SIZE);
    mfree(ptr_p, ecc_ristretto255_SIZE);
    mfree(ptr_r, ecc_ristretto255_HASHSIZE);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1ristretto255_1random(
    JNIEnv *env, jclass cls,
    jbyteArray p
) {
    byte_t *ptr_p = mput(env, p, ecc_ristretto255_SIZE);
    ecc_ristretto255_random(
        ptr_p
    );
    mget(env, p, ptr_p, ecc_ristretto255_SIZE);
    mfree(ptr_p, ecc_ristretto255_SIZE);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1ristretto255_1scalar_1random(
    JNIEnv *env, jclass cls,
    jbyteArray r
) {
    byte_t *ptr_r = mput(env, r, ecc_ristretto255_SCALARSIZE);
    ecc_ristretto255_scalar_random(
        ptr_r
    );
    mget(env, r, ptr_r, ecc_ristretto255_SCALARSIZE);
    mfree(ptr_r, ecc_ristretto255_SCALARSIZE);
}

JNIEXPORT int JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1ristretto255_1scalar_1invert(
    JNIEnv *env, jclass cls,
    jbyteArray recip,
    jbyteArray s
) {
    byte_t *ptr_recip = mput(env, recip, ecc_ristretto255_SCALARSIZE);
    byte_t *ptr_s = mput(env, s, ecc_ristretto255_SCALARSIZE);
    const int fun_ret = ecc_ristretto255_scalar_invert(
        ptr_recip,
        ptr_s
    );
    mget(env, recip, ptr_recip, ecc_ristretto255_SCALARSIZE);
    mfree(ptr_recip, ecc_ristretto255_SCALARSIZE);
    mfree(ptr_s, ecc_ristretto255_SCALARSIZE);
    return fun_ret;
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1ristretto255_1scalar_1negate(
    JNIEnv *env, jclass cls,
    jbyteArray neg,
    jbyteArray s
) {
    byte_t *ptr_neg = mput(env, neg, ecc_ristretto255_SCALARSIZE);
    byte_t *ptr_s = mput(env, s, ecc_ristretto255_SCALARSIZE);
    ecc_ristretto255_scalar_negate(
        ptr_neg,
        ptr_s
    );
    mget(env, neg, ptr_neg, ecc_ristretto255_SCALARSIZE);
    mfree(ptr_neg, ecc_ristretto255_SCALARSIZE);
    mfree(ptr_s, ecc_ristretto255_SCALARSIZE);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1ristretto255_1scalar_1complement(
    JNIEnv *env, jclass cls,
    jbyteArray comp,
    jbyteArray s
) {
    byte_t *ptr_comp = mput(env, comp, ecc_ristretto255_SCALARSIZE);
    byte_t *ptr_s = mput(env, s, ecc_ristretto255_SCALARSIZE);
    ecc_ristretto255_scalar_complement(
        ptr_comp,
        ptr_s
    );
    mget(env, comp, ptr_comp, ecc_ristretto255_SCALARSIZE);
    mfree(ptr_comp, ecc_ristretto255_SCALARSIZE);
    mfree(ptr_s, ecc_ristretto255_SCALARSIZE);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1ristretto255_1scalar_1add(
    JNIEnv *env, jclass cls,
    jbyteArray z,
    jbyteArray x,
    jbyteArray y
) {
    byte_t *ptr_z = mput(env, z, ecc_ristretto255_SCALARSIZE);
    byte_t *ptr_x = mput(env, x, ecc_ristretto255_SCALARSIZE);
    byte_t *ptr_y = mput(env, y, ecc_ristretto255_SCALARSIZE);
    ecc_ristretto255_scalar_add(
        ptr_z,
        ptr_x,
        ptr_y
    );
    mget(env, z, ptr_z, ecc_ristretto255_SCALARSIZE);
    mfree(ptr_z, ecc_ristretto255_SCALARSIZE);
    mfree(ptr_x, ecc_ristretto255_SCALARSIZE);
    mfree(ptr_y, ecc_ristretto255_SCALARSIZE);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1ristretto255_1scalar_1sub(
    JNIEnv *env, jclass cls,
    jbyteArray z,
    jbyteArray x,
    jbyteArray y
) {
    byte_t *ptr_z = mput(env, z, ecc_ristretto255_SCALARSIZE);
    byte_t *ptr_x = mput(env, x, ecc_ristretto255_SCALARSIZE);
    byte_t *ptr_y = mput(env, y, ecc_ristretto255_SCALARSIZE);
    ecc_ristretto255_scalar_sub(
        ptr_z,
        ptr_x,
        ptr_y
    );
    mget(env, z, ptr_z, ecc_ristretto255_SCALARSIZE);
    mfree(ptr_z, ecc_ristretto255_SCALARSIZE);
    mfree(ptr_x, ecc_ristretto255_SCALARSIZE);
    mfree(ptr_y, ecc_ristretto255_SCALARSIZE);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1ristretto255_1scalar_1mul(
    JNIEnv *env, jclass cls,
    jbyteArray z,
    jbyteArray x,
    jbyteArray y
) {
    byte_t *ptr_z = mput(env, z, ecc_ristretto255_SCALARSIZE);
    byte_t *ptr_x = mput(env, x, ecc_ristretto255_SCALARSIZE);
    byte_t *ptr_y = mput(env, y, ecc_ristretto255_SCALARSIZE);
    ecc_ristretto255_scalar_mul(
        ptr_z,
        ptr_x,
        ptr_y
    );
    mget(env, z, ptr_z, ecc_ristretto255_SCALARSIZE);
    mfree(ptr_z, ecc_ristretto255_SCALARSIZE);
    mfree(ptr_x, ecc_ristretto255_SCALARSIZE);
    mfree(ptr_y, ecc_ristretto255_SCALARSIZE);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1ristretto255_1scalar_1reduce(
    JNIEnv *env, jclass cls,
    jbyteArray r,
    jbyteArray s
) {
    byte_t *ptr_r = mput(env, r, ecc_ristretto255_SCALARSIZE);
    byte_t *ptr_s = mput(env, s, ecc_ristretto255_NONREDUCEDSCALARSIZE);
    ecc_ristretto255_scalar_reduce(
        ptr_r,
        ptr_s
    );
    mget(env, r, ptr_r, ecc_ristretto255_SCALARSIZE);
    mfree(ptr_r, ecc_ristretto255_SCALARSIZE);
    mfree(ptr_s, ecc_ristretto255_NONREDUCEDSCALARSIZE);
}

JNIEXPORT int JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1ristretto255_1scalarmult(
    JNIEnv *env, jclass cls,
    jbyteArray q,
    jbyteArray n,
    jbyteArray p
) {
    byte_t *ptr_q = mput(env, q, ecc_ristretto255_SIZE);
    byte_t *ptr_n = mput(env, n, ecc_ristretto255_SCALARSIZE);
    byte_t *ptr_p = mput(env, p, ecc_ristretto255_SIZE);
    const int fun_ret = ecc_ristretto255_scalarmult(
        ptr_q,
        ptr_n,
        ptr_p
    );
    mget(env, q, ptr_q, ecc_ristretto255_SIZE);
    mfree(ptr_q, ecc_ristretto255_SIZE);
    mfree(ptr_n, ecc_ristretto255_SCALARSIZE);
    mfree(ptr_p, ecc_ristretto255_SIZE);
    return fun_ret;
}

JNIEXPORT int JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1ristretto255_1scalarmult_1base(
    JNIEnv *env, jclass cls,
    jbyteArray q,
    jbyteArray n
) {
    byte_t *ptr_q = mput(env, q, ecc_ristretto255_SIZE);
    byte_t *ptr_n = mput(env, n, ecc_ristretto255_SCALARSIZE);
    const int fun_ret = ecc_ristretto255_scalarmult_base(
        ptr_q,
        ptr_n
    );
    mget(env, q, ptr_q, ecc_ristretto255_SIZE);
    mfree(ptr_q, ecc_ristretto255_SIZE);
    mfree(ptr_n, ecc_ristretto255_SCALARSIZE);
    return fun_ret;
}

// bls12_381

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1bls12_1381_1fp_1random(
    JNIEnv *env, jclass cls,
    jbyteArray ret
) {
    byte_t *ptr_ret = mput(env, ret, ecc_bls12_381_FPSIZE);
    ecc_bls12_381_fp_random(
        ptr_ret
    );
    mget(env, ret, ptr_ret, ecc_bls12_381_FPSIZE);
    mfree(ptr_ret, ecc_bls12_381_FPSIZE);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1bls12_1381_1fp12_1one(
    JNIEnv *env, jclass cls,
    jbyteArray ret
) {
    byte_t *ptr_ret = mput(env, ret, ecc_bls12_381_FP12SIZE);
    ecc_bls12_381_fp12_one(
        ptr_ret
    );
    mget(env, ret, ptr_ret, ecc_bls12_381_FP12SIZE);
    mfree(ptr_ret, ecc_bls12_381_FP12SIZE);
}

JNIEXPORT int JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1bls12_1381_1fp12_1is_1one(
    JNIEnv *env, jclass cls,
    jbyteArray a
) {
    byte_t *ptr_a = mput(env, a, ecc_bls12_381_FP12SIZE);
    const int fun_ret = ecc_bls12_381_fp12_is_one(
        ptr_a
    );
    mfree(ptr_a, ecc_bls12_381_FP12SIZE);
    return fun_ret;
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1bls12_1381_1fp12_1inverse(
    JNIEnv *env, jclass cls,
    jbyteArray ret,
    jbyteArray a
) {
    byte_t *ptr_ret = mput(env, ret, ecc_bls12_381_FP12SIZE);
    byte_t *ptr_a = mput(env, a, ecc_bls12_381_FP12SIZE);
    ecc_bls12_381_fp12_inverse(
        ptr_ret,
        ptr_a
    );
    mget(env, ret, ptr_ret, ecc_bls12_381_FP12SIZE);
    mfree(ptr_ret, ecc_bls12_381_FP12SIZE);
    mfree(ptr_a, ecc_bls12_381_FP12SIZE);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1bls12_1381_1fp12_1sqr(
    JNIEnv *env, jclass cls,
    jbyteArray ret,
    jbyteArray a
) {
    byte_t *ptr_ret = mput(env, ret, ecc_bls12_381_FP12SIZE);
    byte_t *ptr_a = mput(env, a, ecc_bls12_381_FP12SIZE);
    ecc_bls12_381_fp12_sqr(
        ptr_ret,
        ptr_a
    );
    mget(env, ret, ptr_ret, ecc_bls12_381_FP12SIZE);
    mfree(ptr_ret, ecc_bls12_381_FP12SIZE);
    mfree(ptr_a, ecc_bls12_381_FP12SIZE);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1bls12_1381_1fp12_1mul(
    JNIEnv *env, jclass cls,
    jbyteArray ret,
    jbyteArray a,
    jbyteArray b
) {
    byte_t *ptr_ret = mput(env, ret, ecc_bls12_381_FP12SIZE);
    byte_t *ptr_a = mput(env, a, ecc_bls12_381_FP12SIZE);
    byte_t *ptr_b = mput(env, b, ecc_bls12_381_FP12SIZE);
    ecc_bls12_381_fp12_mul(
        ptr_ret,
        ptr_a,
        ptr_b
    );
    mget(env, ret, ptr_ret, ecc_bls12_381_FP12SIZE);
    mfree(ptr_ret, ecc_bls12_381_FP12SIZE);
    mfree(ptr_a, ecc_bls12_381_FP12SIZE);
    mfree(ptr_b, ecc_bls12_381_FP12SIZE);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1bls12_1381_1fp12_1pow(
    JNIEnv *env, jclass cls,
    jbyteArray ret,
    jbyteArray a,
    jint n
) {
    byte_t *ptr_ret = mput(env, ret, ecc_bls12_381_FP12SIZE);
    byte_t *ptr_a = mput(env, a, ecc_bls12_381_FP12SIZE);
    ecc_bls12_381_fp12_pow(
        ptr_ret,
        ptr_a,
        n
    );
    mget(env, ret, ptr_ret, ecc_bls12_381_FP12SIZE);
    mfree(ptr_ret, ecc_bls12_381_FP12SIZE);
    mfree(ptr_a, ecc_bls12_381_FP12SIZE);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1bls12_1381_1fp12_1random(
    JNIEnv *env, jclass cls,
    jbyteArray ret
) {
    byte_t *ptr_ret = mput(env, ret, ecc_bls12_381_FP12SIZE);
    ecc_bls12_381_fp12_random(
        ptr_ret
    );
    mget(env, ret, ptr_ret, ecc_bls12_381_FP12SIZE);
    mfree(ptr_ret, ecc_bls12_381_FP12SIZE);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1bls12_1381_1g1_1add(
    JNIEnv *env, jclass cls,
    jbyteArray r,
    jbyteArray p,
    jbyteArray q
) {
    byte_t *ptr_r = mput(env, r, ecc_bls12_381_G1SIZE);
    byte_t *ptr_p = mput(env, p, ecc_bls12_381_G1SIZE);
    byte_t *ptr_q = mput(env, q, ecc_bls12_381_G1SIZE);
    ecc_bls12_381_g1_add(
        ptr_r,
        ptr_p,
        ptr_q
    );
    mget(env, r, ptr_r, ecc_bls12_381_G1SIZE);
    mfree(ptr_r, ecc_bls12_381_G1SIZE);
    mfree(ptr_p, ecc_bls12_381_G1SIZE);
    mfree(ptr_q, ecc_bls12_381_G1SIZE);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1bls12_1381_1g1_1negate(
    JNIEnv *env, jclass cls,
    jbyteArray neg,
    jbyteArray p
) {
    byte_t *ptr_neg = mput(env, neg, ecc_bls12_381_G1SIZE);
    byte_t *ptr_p = mput(env, p, ecc_bls12_381_G1SIZE);
    ecc_bls12_381_g1_negate(
        ptr_neg,
        ptr_p
    );
    mget(env, neg, ptr_neg, ecc_bls12_381_G1SIZE);
    mfree(ptr_neg, ecc_bls12_381_G1SIZE);
    mfree(ptr_p, ecc_bls12_381_G1SIZE);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1bls12_1381_1g1_1generator(
    JNIEnv *env, jclass cls,
    jbyteArray g
) {
    byte_t *ptr_g = mput(env, g, ecc_bls12_381_G1SIZE);
    ecc_bls12_381_g1_generator(
        ptr_g
    );
    mget(env, g, ptr_g, ecc_bls12_381_G1SIZE);
    mfree(ptr_g, ecc_bls12_381_G1SIZE);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1bls12_1381_1g1_1scalarmult(
    JNIEnv *env, jclass cls,
    jbyteArray q,
    jbyteArray n,
    jbyteArray p
) {
    byte_t *ptr_q = mput(env, q, ecc_bls12_381_G1SIZE);
    byte_t *ptr_n = mput(env, n, ecc_bls12_381_SCALARSIZE);
    byte_t *ptr_p = mput(env, p, ecc_bls12_381_G1SIZE);
    ecc_bls12_381_g1_scalarmult(
        ptr_q,
        ptr_n,
        ptr_p
    );
    mget(env, q, ptr_q, ecc_bls12_381_G1SIZE);
    mfree(ptr_q, ecc_bls12_381_G1SIZE);
    mfree(ptr_n, ecc_bls12_381_SCALARSIZE);
    mfree(ptr_p, ecc_bls12_381_G1SIZE);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1bls12_1381_1g1_1scalarmult_1base(
    JNIEnv *env, jclass cls,
    jbyteArray q,
    jbyteArray n
) {
    byte_t *ptr_q = mput(env, q, ecc_bls12_381_G1SIZE);
    byte_t *ptr_n = mput(env, n, ecc_bls12_381_SCALARSIZE);
    ecc_bls12_381_g1_scalarmult_base(
        ptr_q,
        ptr_n
    );
    mget(env, q, ptr_q, ecc_bls12_381_G1SIZE);
    mfree(ptr_q, ecc_bls12_381_G1SIZE);
    mfree(ptr_n, ecc_bls12_381_SCALARSIZE);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1bls12_1381_1g2_1add(
    JNIEnv *env, jclass cls,
    jbyteArray r,
    jbyteArray p,
    jbyteArray q
) {
    byte_t *ptr_r = mput(env, r, ecc_bls12_381_G2SIZE);
    byte_t *ptr_p = mput(env, p, ecc_bls12_381_G2SIZE);
    byte_t *ptr_q = mput(env, q, ecc_bls12_381_G2SIZE);
    ecc_bls12_381_g2_add(
        ptr_r,
        ptr_p,
        ptr_q
    );
    mget(env, r, ptr_r, ecc_bls12_381_G2SIZE);
    mfree(ptr_r, ecc_bls12_381_G2SIZE);
    mfree(ptr_p, ecc_bls12_381_G2SIZE);
    mfree(ptr_q, ecc_bls12_381_G2SIZE);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1bls12_1381_1g2_1negate(
    JNIEnv *env, jclass cls,
    jbyteArray neg,
    jbyteArray p
) {
    byte_t *ptr_neg = mput(env, neg, ecc_bls12_381_G2SIZE);
    byte_t *ptr_p = mput(env, p, ecc_bls12_381_G2SIZE);
    ecc_bls12_381_g2_negate(
        ptr_neg,
        ptr_p
    );
    mget(env, neg, ptr_neg, ecc_bls12_381_G2SIZE);
    mfree(ptr_neg, ecc_bls12_381_G2SIZE);
    mfree(ptr_p, ecc_bls12_381_G2SIZE);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1bls12_1381_1g2_1generator(
    JNIEnv *env, jclass cls,
    jbyteArray g
) {
    byte_t *ptr_g = mput(env, g, ecc_bls12_381_G2SIZE);
    ecc_bls12_381_g2_generator(
        ptr_g
    );
    mget(env, g, ptr_g, ecc_bls12_381_G2SIZE);
    mfree(ptr_g, ecc_bls12_381_G2SIZE);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1bls12_1381_1g2_1scalarmult_1base(
    JNIEnv *env, jclass cls,
    jbyteArray q,
    jbyteArray n
) {
    byte_t *ptr_q = mput(env, q, ecc_bls12_381_G2SIZE);
    byte_t *ptr_n = mput(env, n, ecc_bls12_381_SCALARSIZE);
    ecc_bls12_381_g2_scalarmult_base(
        ptr_q,
        ptr_n
    );
    mget(env, q, ptr_q, ecc_bls12_381_G2SIZE);
    mfree(ptr_q, ecc_bls12_381_G2SIZE);
    mfree(ptr_n, ecc_bls12_381_SCALARSIZE);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1bls12_1381_1scalar_1random(
    JNIEnv *env, jclass cls,
    jbyteArray r
) {
    byte_t *ptr_r = mput(env, r, ecc_bls12_381_SCALARSIZE);
    ecc_bls12_381_scalar_random(
        ptr_r
    );
    mget(env, r, ptr_r, ecc_bls12_381_SCALARSIZE);
    mfree(ptr_r, ecc_bls12_381_SCALARSIZE);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1bls12_1381_1pairing(
    JNIEnv *env, jclass cls,
    jbyteArray ret,
    jbyteArray p1_g1,
    jbyteArray p2_g2
) {
    byte_t *ptr_ret = mput(env, ret, ecc_bls12_381_FP12SIZE);
    byte_t *ptr_p1_g1 = mput(env, p1_g1, ecc_bls12_381_G1SIZE);
    byte_t *ptr_p2_g2 = mput(env, p2_g2, ecc_bls12_381_G2SIZE);
    ecc_bls12_381_pairing(
        ptr_ret,
        ptr_p1_g1,
        ptr_p2_g2
    );
    mget(env, ret, ptr_ret, ecc_bls12_381_FP12SIZE);
    mfree(ptr_ret, ecc_bls12_381_FP12SIZE);
    mfree(ptr_p1_g1, ecc_bls12_381_G1SIZE);
    mfree(ptr_p2_g2, ecc_bls12_381_G2SIZE);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1bls12_1381_1pairing_1miller_1loop(
    JNIEnv *env, jclass cls,
    jbyteArray ret,
    jbyteArray p1_g1,
    jbyteArray p2_g2
) {
    byte_t *ptr_ret = mput(env, ret, ecc_bls12_381_FP12SIZE);
    byte_t *ptr_p1_g1 = mput(env, p1_g1, ecc_bls12_381_G1SIZE);
    byte_t *ptr_p2_g2 = mput(env, p2_g2, ecc_bls12_381_G2SIZE);
    ecc_bls12_381_pairing_miller_loop(
        ptr_ret,
        ptr_p1_g1,
        ptr_p2_g2
    );
    mget(env, ret, ptr_ret, ecc_bls12_381_FP12SIZE);
    mfree(ptr_ret, ecc_bls12_381_FP12SIZE);
    mfree(ptr_p1_g1, ecc_bls12_381_G1SIZE);
    mfree(ptr_p2_g2, ecc_bls12_381_G2SIZE);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1bls12_1381_1pairing_1final_1exp(
    JNIEnv *env, jclass cls,
    jbyteArray ret,
    jbyteArray a
) {
    byte_t *ptr_ret = mput(env, ret, ecc_bls12_381_FP12SIZE);
    byte_t *ptr_a = mput(env, a, ecc_bls12_381_FP12SIZE);
    ecc_bls12_381_pairing_final_exp(
        ptr_ret,
        ptr_a
    );
    mget(env, ret, ptr_ret, ecc_bls12_381_FP12SIZE);
    mfree(ptr_ret, ecc_bls12_381_FP12SIZE);
    mfree(ptr_a, ecc_bls12_381_FP12SIZE);
}

JNIEXPORT int JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1bls12_1381_1pairing_1final_1verify(
    JNIEnv *env, jclass cls,
    jbyteArray a,
    jbyteArray b
) {
    byte_t *ptr_a = mput(env, a, ecc_bls12_381_FP12SIZE);
    byte_t *ptr_b = mput(env, b, ecc_bls12_381_FP12SIZE);
    const int fun_ret = ecc_bls12_381_pairing_final_verify(
        ptr_a,
        ptr_b
    );
    mfree(ptr_a, ecc_bls12_381_FP12SIZE);
    mfree(ptr_b, ecc_bls12_381_FP12SIZE);
    return fun_ret;
}

// h2c

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1h2c_1expand_1message_1xmd_1sha256(
    JNIEnv *env, jclass cls,
    jbyteArray out,
    jbyteArray msg,
    jint msg_len,
    jbyteArray dst,
    jint dst_len,
    jint len
) {
    byte_t *ptr_out = mput(env, out, len);
    byte_t *ptr_msg = mput(env, msg, msg_len);
    byte_t *ptr_dst = mput(env, dst, dst_len);
    ecc_h2c_expand_message_xmd_sha256(
        ptr_out,
        ptr_msg,
        msg_len,
        ptr_dst,
        dst_len,
        len
    );
    mget(env, out, ptr_out, len);
    mfree(ptr_out, len);
    mfree(ptr_msg, msg_len);
    mfree(ptr_dst, dst_len);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1h2c_1expand_1message_1xmd_1sha512(
    JNIEnv *env, jclass cls,
    jbyteArray out,
    jbyteArray msg,
    jint msg_len,
    jbyteArray dst,
    jint dst_len,
    jint len
) {
    byte_t *ptr_out = mput(env, out, len);
    byte_t *ptr_msg = mput(env, msg, msg_len);
    byte_t *ptr_dst = mput(env, dst, dst_len);
    ecc_h2c_expand_message_xmd_sha512(
        ptr_out,
        ptr_msg,
        msg_len,
        ptr_dst,
        dst_len,
        len
    );
    mget(env, out, ptr_out, len);
    mfree(ptr_out, len);
    mfree(ptr_msg, msg_len);
    mfree(ptr_dst, dst_len);
}

// oprf

JNIEXPORT int JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1oprf_1ristretto255_1sha512_1Evaluate(
    JNIEnv *env, jclass cls,
    jbyteArray evaluatedElement,
    jbyteArray skS,
    jbyteArray blindedElement,
    jbyteArray info,
    jint infoLen
) {
    byte_t *ptr_evaluatedElement = mput(env, evaluatedElement, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_skS = mput(env, skS, ecc_oprf_ristretto255_sha512_SCALARSIZE);
    byte_t *ptr_blindedElement = mput(env, blindedElement, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_info = mput(env, info, infoLen);
    const int fun_ret = ecc_oprf_ristretto255_sha512_Evaluate(
        ptr_evaluatedElement,
        ptr_skS,
        ptr_blindedElement,
        ptr_info,
        infoLen
    );
    mget(env, evaluatedElement, ptr_evaluatedElement, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_evaluatedElement, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_skS, ecc_oprf_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_blindedElement, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_info, infoLen);
    return fun_ret;
}

JNIEXPORT int JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1oprf_1ristretto255_1sha512_1VerifiableEvaluateWithScalar(
    JNIEnv *env, jclass cls,
    jbyteArray evaluatedElement,
    jbyteArray proof,
    jbyteArray skS,
    jbyteArray blindedElement,
    jbyteArray info,
    jint infoLen,
    jbyteArray r
) {
    byte_t *ptr_evaluatedElement = mput(env, evaluatedElement, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_proof = mput(env, proof, ecc_oprf_ristretto255_sha512_PROOFSIZE);
    byte_t *ptr_skS = mput(env, skS, ecc_oprf_ristretto255_sha512_SCALARSIZE);
    byte_t *ptr_blindedElement = mput(env, blindedElement, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_info = mput(env, info, infoLen);
    byte_t *ptr_r = mput(env, r, ecc_oprf_ristretto255_sha512_SCALARSIZE);
    const int fun_ret = ecc_oprf_ristretto255_sha512_VerifiableEvaluateWithScalar(
        ptr_evaluatedElement,
        ptr_proof,
        ptr_skS,
        ptr_blindedElement,
        ptr_info,
        infoLen,
        ptr_r
    );
    mget(env, evaluatedElement, ptr_evaluatedElement, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    mget(env, proof, ptr_proof, ecc_oprf_ristretto255_sha512_PROOFSIZE);
    mfree(ptr_evaluatedElement, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_proof, ecc_oprf_ristretto255_sha512_PROOFSIZE);
    mfree(ptr_skS, ecc_oprf_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_blindedElement, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_info, infoLen);
    mfree(ptr_r, ecc_oprf_ristretto255_sha512_SCALARSIZE);
    return fun_ret;
}

JNIEXPORT int JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1oprf_1ristretto255_1sha512_1VerifiableEvaluate(
    JNIEnv *env, jclass cls,
    jbyteArray evaluatedElement,
    jbyteArray proof,
    jbyteArray skS,
    jbyteArray blindedElement,
    jbyteArray info,
    jint infoLen
) {
    byte_t *ptr_evaluatedElement = mput(env, evaluatedElement, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_proof = mput(env, proof, ecc_oprf_ristretto255_sha512_PROOFSIZE);
    byte_t *ptr_skS = mput(env, skS, ecc_oprf_ristretto255_sha512_SCALARSIZE);
    byte_t *ptr_blindedElement = mput(env, blindedElement, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_info = mput(env, info, infoLen);
    const int fun_ret = ecc_oprf_ristretto255_sha512_VerifiableEvaluate(
        ptr_evaluatedElement,
        ptr_proof,
        ptr_skS,
        ptr_blindedElement,
        ptr_info,
        infoLen
    );
    mget(env, evaluatedElement, ptr_evaluatedElement, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    mget(env, proof, ptr_proof, ecc_oprf_ristretto255_sha512_PROOFSIZE);
    mfree(ptr_evaluatedElement, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_proof, ecc_oprf_ristretto255_sha512_PROOFSIZE);
    mfree(ptr_skS, ecc_oprf_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_blindedElement, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_info, infoLen);
    return fun_ret;
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1oprf_1ristretto255_1sha512_1GenerateProofWithScalar(
    JNIEnv *env, jclass cls,
    jbyteArray proof,
    jbyteArray k,
    jbyteArray A,
    jbyteArray B,
    jbyteArray C,
    jbyteArray D,
    jbyteArray r
) {
    byte_t *ptr_proof = mput(env, proof, ecc_oprf_ristretto255_sha512_PROOFSIZE);
    byte_t *ptr_k = mput(env, k, ecc_oprf_ristretto255_sha512_SCALARSIZE);
    byte_t *ptr_A = mput(env, A, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_B = mput(env, B, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_C = mput(env, C, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_D = mput(env, D, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_r = mput(env, r, ecc_oprf_ristretto255_sha512_SCALARSIZE);
    ecc_oprf_ristretto255_sha512_GenerateProofWithScalar(
        ptr_proof,
        ptr_k,
        ptr_A,
        ptr_B,
        ptr_C,
        ptr_D,
        ptr_r
    );
    mget(env, proof, ptr_proof, ecc_oprf_ristretto255_sha512_PROOFSIZE);
    mfree(ptr_proof, ecc_oprf_ristretto255_sha512_PROOFSIZE);
    mfree(ptr_k, ecc_oprf_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_A, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_B, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_C, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_D, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_r, ecc_oprf_ristretto255_sha512_SCALARSIZE);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1oprf_1ristretto255_1sha512_1GenerateProof(
    JNIEnv *env, jclass cls,
    jbyteArray proof,
    jbyteArray k,
    jbyteArray A,
    jbyteArray B,
    jbyteArray C,
    jbyteArray D
) {
    byte_t *ptr_proof = mput(env, proof, ecc_oprf_ristretto255_sha512_PROOFSIZE);
    byte_t *ptr_k = mput(env, k, ecc_oprf_ristretto255_sha512_SCALARSIZE);
    byte_t *ptr_A = mput(env, A, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_B = mput(env, B, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_C = mput(env, C, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_D = mput(env, D, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    ecc_oprf_ristretto255_sha512_GenerateProof(
        ptr_proof,
        ptr_k,
        ptr_A,
        ptr_B,
        ptr_C,
        ptr_D
    );
    mget(env, proof, ptr_proof, ecc_oprf_ristretto255_sha512_PROOFSIZE);
    mfree(ptr_proof, ecc_oprf_ristretto255_sha512_PROOFSIZE);
    mfree(ptr_k, ecc_oprf_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_A, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_B, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_C, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_D, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1oprf_1ristretto255_1sha512_1ComputeComposites(
    JNIEnv *env, jclass cls,
    jbyteArray M,
    jbyteArray Z,
    jbyteArray B,
    jbyteArray Cs,
    jbyteArray Ds,
    jint m
) {
    byte_t *ptr_M = mput(env, M, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_Z = mput(env, Z, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_B = mput(env, B, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_Cs = mput(env, Cs, m*ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_Ds = mput(env, Ds, m*ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    ecc_oprf_ristretto255_sha512_ComputeComposites(
        ptr_M,
        ptr_Z,
        ptr_B,
        ptr_Cs,
        ptr_Ds,
        m
    );
    mget(env, M, ptr_M, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    mget(env, Z, ptr_Z, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_M, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_Z, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_B, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_Cs, m*ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_Ds, m*ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1oprf_1ristretto255_1sha512_1ComputeCompositesFast(
    JNIEnv *env, jclass cls,
    jbyteArray M,
    jbyteArray Z,
    jbyteArray k,
    jbyteArray B,
    jbyteArray Cs,
    jbyteArray Ds,
    jint m
) {
    byte_t *ptr_M = mput(env, M, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_Z = mput(env, Z, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_k = mput(env, k, ecc_oprf_ristretto255_sha512_SCALARSIZE);
    byte_t *ptr_B = mput(env, B, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_Cs = mput(env, Cs, m*ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_Ds = mput(env, Ds, m*ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    ecc_oprf_ristretto255_sha512_ComputeCompositesFast(
        ptr_M,
        ptr_Z,
        ptr_k,
        ptr_B,
        ptr_Cs,
        ptr_Ds,
        m
    );
    mget(env, M, ptr_M, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    mget(env, Z, ptr_Z, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_M, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_Z, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_k, ecc_oprf_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_B, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_Cs, m*ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_Ds, m*ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1oprf_1ristretto255_1sha512_1BlindWithScalar(
    JNIEnv *env, jclass cls,
    jbyteArray blindedElement,
    jbyteArray input,
    jint inputLen,
    jbyteArray blind,
    jint mode
) {
    byte_t *ptr_blindedElement = mput(env, blindedElement, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_input = mput(env, input, inputLen);
    byte_t *ptr_blind = mput(env, blind, ecc_oprf_ristretto255_sha512_SCALARSIZE);
    ecc_oprf_ristretto255_sha512_BlindWithScalar(
        ptr_blindedElement,
        ptr_input,
        inputLen,
        ptr_blind,
        mode
    );
    mget(env, blindedElement, ptr_blindedElement, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_blindedElement, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_input, inputLen);
    mfree(ptr_blind, ecc_oprf_ristretto255_sha512_SCALARSIZE);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1oprf_1ristretto255_1sha512_1Blind(
    JNIEnv *env, jclass cls,
    jbyteArray blindedElement,
    jbyteArray blind,
    jbyteArray input,
    jint inputLen,
    jint mode
) {
    byte_t *ptr_blindedElement = mput(env, blindedElement, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_blind = mput(env, blind, ecc_oprf_ristretto255_sha512_SCALARSIZE);
    byte_t *ptr_input = mput(env, input, inputLen);
    ecc_oprf_ristretto255_sha512_Blind(
        ptr_blindedElement,
        ptr_blind,
        ptr_input,
        inputLen,
        mode
    );
    mget(env, blindedElement, ptr_blindedElement, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    mget(env, blind, ptr_blind, ecc_oprf_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_blindedElement, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_blind, ecc_oprf_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_input, inputLen);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1oprf_1ristretto255_1sha512_1Unblind(
    JNIEnv *env, jclass cls,
    jbyteArray unblindedElement,
    jbyteArray blind,
    jbyteArray evaluatedElement
) {
    byte_t *ptr_unblindedElement = mput(env, unblindedElement, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_blind = mput(env, blind, ecc_oprf_ristretto255_sha512_SCALARSIZE);
    byte_t *ptr_evaluatedElement = mput(env, evaluatedElement, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    ecc_oprf_ristretto255_sha512_Unblind(
        ptr_unblindedElement,
        ptr_blind,
        ptr_evaluatedElement
    );
    mget(env, unblindedElement, ptr_unblindedElement, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_unblindedElement, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_blind, ecc_oprf_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_evaluatedElement, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1oprf_1ristretto255_1sha512_1Finalize(
    JNIEnv *env, jclass cls,
    jbyteArray output,
    jbyteArray input,
    jint inputLen,
    jbyteArray blind,
    jbyteArray evaluatedElement,
    jbyteArray info,
    jint infoLen
) {
    byte_t *ptr_output = mput(env, output, ecc_oprf_ristretto255_sha512_Nh);
    byte_t *ptr_input = mput(env, input, inputLen);
    byte_t *ptr_blind = mput(env, blind, ecc_oprf_ristretto255_sha512_SCALARSIZE);
    byte_t *ptr_evaluatedElement = mput(env, evaluatedElement, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_info = mput(env, info, infoLen);
    ecc_oprf_ristretto255_sha512_Finalize(
        ptr_output,
        ptr_input,
        inputLen,
        ptr_blind,
        ptr_evaluatedElement,
        ptr_info,
        infoLen
    );
    mget(env, output, ptr_output, ecc_oprf_ristretto255_sha512_Nh);
    mfree(ptr_output, ecc_oprf_ristretto255_sha512_Nh);
    mfree(ptr_input, inputLen);
    mfree(ptr_blind, ecc_oprf_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_evaluatedElement, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_info, infoLen);
}

JNIEXPORT int JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1oprf_1ristretto255_1sha512_1VerifyProof(
    JNIEnv *env, jclass cls,
    jbyteArray A,
    jbyteArray B,
    jbyteArray C,
    jbyteArray D,
    jbyteArray proof
) {
    byte_t *ptr_A = mput(env, A, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_B = mput(env, B, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_C = mput(env, C, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_D = mput(env, D, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_proof = mput(env, proof, ecc_oprf_ristretto255_sha512_PROOFSIZE);
    const int fun_ret = ecc_oprf_ristretto255_sha512_VerifyProof(
        ptr_A,
        ptr_B,
        ptr_C,
        ptr_D,
        ptr_proof
    );
    mfree(ptr_A, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_B, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_C, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_D, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_proof, ecc_oprf_ristretto255_sha512_PROOFSIZE);
    return fun_ret;
}

JNIEXPORT int JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1oprf_1ristretto255_1sha512_1VerifiableUnblind(
    JNIEnv *env, jclass cls,
    jbyteArray unblindedElement,
    jbyteArray blind,
    jbyteArray evaluatedElement,
    jbyteArray blindedElement,
    jbyteArray pkS,
    jbyteArray proof,
    jbyteArray info,
    jint infoLen
) {
    byte_t *ptr_unblindedElement = mput(env, unblindedElement, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_blind = mput(env, blind, ecc_oprf_ristretto255_sha512_SCALARSIZE);
    byte_t *ptr_evaluatedElement = mput(env, evaluatedElement, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_blindedElement = mput(env, blindedElement, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_pkS = mput(env, pkS, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_proof = mput(env, proof, ecc_oprf_ristretto255_sha512_PROOFSIZE);
    byte_t *ptr_info = mput(env, info, infoLen);
    const int fun_ret = ecc_oprf_ristretto255_sha512_VerifiableUnblind(
        ptr_unblindedElement,
        ptr_blind,
        ptr_evaluatedElement,
        ptr_blindedElement,
        ptr_pkS,
        ptr_proof,
        ptr_info,
        infoLen
    );
    mget(env, unblindedElement, ptr_unblindedElement, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_unblindedElement, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_blind, ecc_oprf_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_evaluatedElement, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_blindedElement, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_pkS, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_proof, ecc_oprf_ristretto255_sha512_PROOFSIZE);
    mfree(ptr_info, infoLen);
    return fun_ret;
}

JNIEXPORT int JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1oprf_1ristretto255_1sha512_1VerifiableFinalize(
    JNIEnv *env, jclass cls,
    jbyteArray output,
    jbyteArray input,
    jint inputLen,
    jbyteArray blind,
    jbyteArray evaluatedElement,
    jbyteArray blindedElement,
    jbyteArray pkS,
    jbyteArray proof,
    jbyteArray info,
    jint infoLen
) {
    byte_t *ptr_output = mput(env, output, ecc_oprf_ristretto255_sha512_Nh);
    byte_t *ptr_input = mput(env, input, inputLen);
    byte_t *ptr_blind = mput(env, blind, ecc_oprf_ristretto255_sha512_SCALARSIZE);
    byte_t *ptr_evaluatedElement = mput(env, evaluatedElement, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_blindedElement = mput(env, blindedElement, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_pkS = mput(env, pkS, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_proof = mput(env, proof, ecc_oprf_ristretto255_sha512_PROOFSIZE);
    byte_t *ptr_info = mput(env, info, infoLen);
    const int fun_ret = ecc_oprf_ristretto255_sha512_VerifiableFinalize(
        ptr_output,
        ptr_input,
        inputLen,
        ptr_blind,
        ptr_evaluatedElement,
        ptr_blindedElement,
        ptr_pkS,
        ptr_proof,
        ptr_info,
        infoLen
    );
    mget(env, output, ptr_output, ecc_oprf_ristretto255_sha512_Nh);
    mfree(ptr_output, ecc_oprf_ristretto255_sha512_Nh);
    mfree(ptr_input, inputLen);
    mfree(ptr_blind, ecc_oprf_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_evaluatedElement, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_blindedElement, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_pkS, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_proof, ecc_oprf_ristretto255_sha512_PROOFSIZE);
    mfree(ptr_info, infoLen);
    return fun_ret;
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1oprf_1ristretto255_1sha512_1HashToGroupWithDST(
    JNIEnv *env, jclass cls,
    jbyteArray out,
    jbyteArray input,
    jint inputLen,
    jbyteArray dst,
    jint dstLen
) {
    byte_t *ptr_out = mput(env, out, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_input = mput(env, input, inputLen);
    byte_t *ptr_dst = mput(env, dst, dstLen);
    ecc_oprf_ristretto255_sha512_HashToGroupWithDST(
        ptr_out,
        ptr_input,
        inputLen,
        ptr_dst,
        dstLen
    );
    mget(env, out, ptr_out, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_out, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_input, inputLen);
    mfree(ptr_dst, dstLen);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1oprf_1ristretto255_1sha512_1HashToGroup(
    JNIEnv *env, jclass cls,
    jbyteArray out,
    jbyteArray input,
    jint inputLen,
    jint mode
) {
    byte_t *ptr_out = mput(env, out, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_input = mput(env, input, inputLen);
    ecc_oprf_ristretto255_sha512_HashToGroup(
        ptr_out,
        ptr_input,
        inputLen,
        mode
    );
    mget(env, out, ptr_out, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_out, ecc_oprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_input, inputLen);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1oprf_1ristretto255_1sha512_1HashToScalarWithDST(
    JNIEnv *env, jclass cls,
    jbyteArray out,
    jbyteArray input,
    jint inputLen,
    jbyteArray dst,
    jint dstLen
) {
    byte_t *ptr_out = mput(env, out, ecc_oprf_ristretto255_sha512_SCALARSIZE);
    byte_t *ptr_input = mput(env, input, inputLen);
    byte_t *ptr_dst = mput(env, dst, dstLen);
    ecc_oprf_ristretto255_sha512_HashToScalarWithDST(
        ptr_out,
        ptr_input,
        inputLen,
        ptr_dst,
        dstLen
    );
    mget(env, out, ptr_out, ecc_oprf_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_out, ecc_oprf_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_input, inputLen);
    mfree(ptr_dst, dstLen);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1oprf_1ristretto255_1sha512_1HashToScalar(
    JNIEnv *env, jclass cls,
    jbyteArray out,
    jbyteArray input,
    jint inputLen,
    jint mode
) {
    byte_t *ptr_out = mput(env, out, ecc_oprf_ristretto255_sha512_SCALARSIZE);
    byte_t *ptr_input = mput(env, input, inputLen);
    ecc_oprf_ristretto255_sha512_HashToScalar(
        ptr_out,
        ptr_input,
        inputLen,
        mode
    );
    mget(env, out, ptr_out, ecc_oprf_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_out, ecc_oprf_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_input, inputLen);
}

// opaque

JNIEXPORT int JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1opaque_1ristretto255_1sha512_1CreateCleartextCredentials(
    JNIEnv *env, jclass cls,
    jbyteArray cleartext_credentials,
    jint cleartext_credentials_len,
    jbyteArray server_public_key,
    jbyteArray client_public_key,
    jbyteArray server_identity,
    jint server_identity_len,
    jbyteArray client_identity,
    jint client_identity_len
) {
    byte_t *ptr_cleartext_credentials = mput(env, cleartext_credentials, cleartext_credentials_len);
    byte_t *ptr_server_public_key = mput(env, server_public_key, ecc_opaque_ristretto255_sha512_Npk);
    byte_t *ptr_client_public_key = mput(env, client_public_key, ecc_opaque_ristretto255_sha512_Npk);
    byte_t *ptr_server_identity = mput(env, server_identity, server_identity_len);
    byte_t *ptr_client_identity = mput(env, client_identity, client_identity_len);
    const int fun_ret = ecc_opaque_ristretto255_sha512_CreateCleartextCredentials(
        ptr_cleartext_credentials,
        cleartext_credentials_len,
        ptr_server_public_key,
        ptr_client_public_key,
        ptr_server_identity,
        server_identity_len,
        ptr_client_identity,
        client_identity_len
    );
    mget(env, cleartext_credentials, ptr_cleartext_credentials, cleartext_credentials_len);
    mfree(ptr_cleartext_credentials, cleartext_credentials_len);
    mfree(ptr_server_public_key, ecc_opaque_ristretto255_sha512_Npk);
    mfree(ptr_client_public_key, ecc_opaque_ristretto255_sha512_Npk);
    mfree(ptr_server_identity, server_identity_len);
    mfree(ptr_client_identity, client_identity_len);
    return fun_ret;
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1opaque_1ristretto255_1sha512_1CreateEnvelopeWithNonce(
    JNIEnv *env, jclass cls,
    jbyteArray envelope_raw,
    jbyteArray client_public_key,
    jbyteArray masking_key,
    jbyteArray export_key,
    jbyteArray randomized_pwd,
    jbyteArray server_public_key,
    jbyteArray client_private_key,
    jbyteArray server_identity,
    jint server_identity_len,
    jbyteArray client_identity,
    jint client_identity_len,
    jbyteArray nonce
) {
    byte_t *ptr_envelope_raw = mput(env, envelope_raw, ecc_opaque_ristretto255_sha512_Ne);
    byte_t *ptr_client_public_key = mput(env, client_public_key, ecc_opaque_ristretto255_sha512_Npk);
    byte_t *ptr_masking_key = mput(env, masking_key, ecc_opaque_ristretto255_sha512_Nh);
    byte_t *ptr_export_key = mput(env, export_key, ecc_opaque_ristretto255_sha512_Nh);
    byte_t *ptr_randomized_pwd = mput(env, randomized_pwd, 64);
    byte_t *ptr_server_public_key = mput(env, server_public_key, ecc_opaque_ristretto255_sha512_Npk);
    byte_t *ptr_client_private_key = mput(env, client_private_key, ecc_opaque_ristretto255_sha512_Nsk);
    byte_t *ptr_server_identity = mput(env, server_identity, server_identity_len);
    byte_t *ptr_client_identity = mput(env, client_identity, client_identity_len);
    byte_t *ptr_nonce = mput(env, nonce, ecc_opaque_ristretto255_sha512_Nn);
    ecc_opaque_ristretto255_sha512_CreateEnvelopeWithNonce(
        ptr_envelope_raw,
        ptr_client_public_key,
        ptr_masking_key,
        ptr_export_key,
        ptr_randomized_pwd,
        ptr_server_public_key,
        ptr_client_private_key,
        ptr_server_identity,
        server_identity_len,
        ptr_client_identity,
        client_identity_len,
        ptr_nonce
    );
    mget(env, envelope_raw, ptr_envelope_raw, ecc_opaque_ristretto255_sha512_Ne);
    mget(env, client_public_key, ptr_client_public_key, ecc_opaque_ristretto255_sha512_Npk);
    mget(env, masking_key, ptr_masking_key, ecc_opaque_ristretto255_sha512_Nh);
    mget(env, export_key, ptr_export_key, ecc_opaque_ristretto255_sha512_Nh);
    mfree(ptr_envelope_raw, ecc_opaque_ristretto255_sha512_Ne);
    mfree(ptr_client_public_key, ecc_opaque_ristretto255_sha512_Npk);
    mfree(ptr_masking_key, ecc_opaque_ristretto255_sha512_Nh);
    mfree(ptr_export_key, ecc_opaque_ristretto255_sha512_Nh);
    mfree(ptr_randomized_pwd, 64);
    mfree(ptr_server_public_key, ecc_opaque_ristretto255_sha512_Npk);
    mfree(ptr_client_private_key, ecc_opaque_ristretto255_sha512_Nsk);
    mfree(ptr_server_identity, server_identity_len);
    mfree(ptr_client_identity, client_identity_len);
    mfree(ptr_nonce, ecc_opaque_ristretto255_sha512_Nn);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1opaque_1ristretto255_1sha512_1CreateEnvelope(
    JNIEnv *env, jclass cls,
    jbyteArray envelope,
    jbyteArray client_public_key,
    jbyteArray masking_key,
    jbyteArray export_key,
    jbyteArray randomized_pwd,
    jbyteArray server_public_key,
    jbyteArray client_private_key,
    jbyteArray server_identity,
    jint server_identity_len,
    jbyteArray client_identity,
    jint client_identity_len
) {
    byte_t *ptr_envelope = mput(env, envelope, ecc_opaque_ristretto255_sha512_Ne);
    byte_t *ptr_client_public_key = mput(env, client_public_key, ecc_opaque_ristretto255_sha512_Npk);
    byte_t *ptr_masking_key = mput(env, masking_key, ecc_opaque_ristretto255_sha512_Nh);
    byte_t *ptr_export_key = mput(env, export_key, ecc_opaque_ristretto255_sha512_Nh);
    byte_t *ptr_randomized_pwd = mput(env, randomized_pwd, 64);
    byte_t *ptr_server_public_key = mput(env, server_public_key, ecc_opaque_ristretto255_sha512_Npk);
    byte_t *ptr_client_private_key = mput(env, client_private_key, ecc_opaque_ristretto255_sha512_Nsk);
    byte_t *ptr_server_identity = mput(env, server_identity, server_identity_len);
    byte_t *ptr_client_identity = mput(env, client_identity, client_identity_len);
    ecc_opaque_ristretto255_sha512_CreateEnvelope(
        ptr_envelope,
        ptr_client_public_key,
        ptr_masking_key,
        ptr_export_key,
        ptr_randomized_pwd,
        ptr_server_public_key,
        ptr_client_private_key,
        ptr_server_identity,
        server_identity_len,
        ptr_client_identity,
        client_identity_len
    );
    mget(env, envelope, ptr_envelope, ecc_opaque_ristretto255_sha512_Ne);
    mget(env, client_public_key, ptr_client_public_key, ecc_opaque_ristretto255_sha512_Npk);
    mget(env, masking_key, ptr_masking_key, ecc_opaque_ristretto255_sha512_Nh);
    mget(env, export_key, ptr_export_key, ecc_opaque_ristretto255_sha512_Nh);
    mfree(ptr_envelope, ecc_opaque_ristretto255_sha512_Ne);
    mfree(ptr_client_public_key, ecc_opaque_ristretto255_sha512_Npk);
    mfree(ptr_masking_key, ecc_opaque_ristretto255_sha512_Nh);
    mfree(ptr_export_key, ecc_opaque_ristretto255_sha512_Nh);
    mfree(ptr_randomized_pwd, 64);
    mfree(ptr_server_public_key, ecc_opaque_ristretto255_sha512_Npk);
    mfree(ptr_client_private_key, ecc_opaque_ristretto255_sha512_Nsk);
    mfree(ptr_server_identity, server_identity_len);
    mfree(ptr_client_identity, client_identity_len);
}

JNIEXPORT int JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1opaque_1ristretto255_1sha512_1RecoverEnvelope(
    JNIEnv *env, jclass cls,
    jbyteArray client_private_key,
    jbyteArray export_key,
    jbyteArray randomized_pwd,
    jbyteArray server_public_key,
    jbyteArray envelope_raw,
    jbyteArray server_identity,
    jint server_identity_len,
    jbyteArray client_identity,
    jint client_identity_len
) {
    byte_t *ptr_client_private_key = mput(env, client_private_key, ecc_opaque_ristretto255_sha512_Nsk);
    byte_t *ptr_export_key = mput(env, export_key, ecc_opaque_ristretto255_sha512_Nh);
    byte_t *ptr_randomized_pwd = mput(env, randomized_pwd, 64);
    byte_t *ptr_server_public_key = mput(env, server_public_key, ecc_opaque_ristretto255_sha512_Npk);
    byte_t *ptr_envelope_raw = mput(env, envelope_raw, ecc_opaque_ristretto255_sha512_Ne);
    byte_t *ptr_server_identity = mput(env, server_identity, server_identity_len);
    byte_t *ptr_client_identity = mput(env, client_identity, client_identity_len);
    const int fun_ret = ecc_opaque_ristretto255_sha512_RecoverEnvelope(
        ptr_client_private_key,
        ptr_export_key,
        ptr_randomized_pwd,
        ptr_server_public_key,
        ptr_envelope_raw,
        ptr_server_identity,
        server_identity_len,
        ptr_client_identity,
        client_identity_len
    );
    mget(env, client_private_key, ptr_client_private_key, ecc_opaque_ristretto255_sha512_Nsk);
    mget(env, export_key, ptr_export_key, ecc_opaque_ristretto255_sha512_Nh);
    mfree(ptr_client_private_key, ecc_opaque_ristretto255_sha512_Nsk);
    mfree(ptr_export_key, ecc_opaque_ristretto255_sha512_Nh);
    mfree(ptr_randomized_pwd, 64);
    mfree(ptr_server_public_key, ecc_opaque_ristretto255_sha512_Npk);
    mfree(ptr_envelope_raw, ecc_opaque_ristretto255_sha512_Ne);
    mfree(ptr_server_identity, server_identity_len);
    mfree(ptr_client_identity, client_identity_len);
    return fun_ret;
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1opaque_1ristretto255_1sha512_1RecoverPublicKey(
    JNIEnv *env, jclass cls,
    jbyteArray public_key,
    jbyteArray private_key
) {
    byte_t *ptr_public_key = mput(env, public_key, ecc_opaque_ristretto255_sha512_Npk);
    byte_t *ptr_private_key = mput(env, private_key, ecc_opaque_ristretto255_sha512_Nsk);
    ecc_opaque_ristretto255_sha512_RecoverPublicKey(
        ptr_public_key,
        ptr_private_key
    );
    mget(env, public_key, ptr_public_key, ecc_opaque_ristretto255_sha512_Npk);
    mfree(ptr_public_key, ecc_opaque_ristretto255_sha512_Npk);
    mfree(ptr_private_key, ecc_opaque_ristretto255_sha512_Nsk);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1opaque_1ristretto255_1sha512_1GenerateAuthKeyPair(
    JNIEnv *env, jclass cls,
    jbyteArray private_key,
    jbyteArray public_key
) {
    byte_t *ptr_private_key = mput(env, private_key, ecc_opaque_ristretto255_sha512_Nsk);
    byte_t *ptr_public_key = mput(env, public_key, ecc_opaque_ristretto255_sha512_Npk);
    ecc_opaque_ristretto255_sha512_GenerateAuthKeyPair(
        ptr_private_key,
        ptr_public_key
    );
    mget(env, private_key, ptr_private_key, ecc_opaque_ristretto255_sha512_Nsk);
    mget(env, public_key, ptr_public_key, ecc_opaque_ristretto255_sha512_Npk);
    mfree(ptr_private_key, ecc_opaque_ristretto255_sha512_Nsk);
    mfree(ptr_public_key, ecc_opaque_ristretto255_sha512_Npk);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1opaque_1ristretto255_1sha512_1DeriveAuthKeyPair(
    JNIEnv *env, jclass cls,
    jbyteArray private_key,
    jbyteArray public_key,
    jbyteArray seed,
    jint seed_len
) {
    byte_t *ptr_private_key = mput(env, private_key, ecc_opaque_ristretto255_sha512_Nsk);
    byte_t *ptr_public_key = mput(env, public_key, ecc_opaque_ristretto255_sha512_Npk);
    byte_t *ptr_seed = mput(env, seed, seed_len);
    ecc_opaque_ristretto255_sha512_DeriveAuthKeyPair(
        ptr_private_key,
        ptr_public_key,
        ptr_seed,
        seed_len
    );
    mget(env, private_key, ptr_private_key, ecc_opaque_ristretto255_sha512_Nsk);
    mget(env, public_key, ptr_public_key, ecc_opaque_ristretto255_sha512_Npk);
    mfree(ptr_private_key, ecc_opaque_ristretto255_sha512_Nsk);
    mfree(ptr_public_key, ecc_opaque_ristretto255_sha512_Npk);
    mfree(ptr_seed, seed_len);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1opaque_1ristretto255_1sha512_1BuildInnerEnvelope(
    JNIEnv *env, jclass cls,
    jbyteArray inner_env,
    jbyteArray client_public_key,
    jbyteArray randomized_pwd,
    jbyteArray nonce,
    jbyteArray client_private_key
) {
    byte_t *ptr_inner_env = mput(env, inner_env, 0);
    byte_t *ptr_client_public_key = mput(env, client_public_key, ecc_opaque_ristretto255_sha512_Npk);
    byte_t *ptr_randomized_pwd = mput(env, randomized_pwd, 64);
    byte_t *ptr_nonce = mput(env, nonce, ecc_opaque_ristretto255_sha512_Nn);
    byte_t *ptr_client_private_key = mput(env, client_private_key, ecc_opaque_ristretto255_sha512_Nsk);
    ecc_opaque_ristretto255_sha512_BuildInnerEnvelope(
        ptr_inner_env,
        ptr_client_public_key,
        ptr_randomized_pwd,
        ptr_nonce,
        ptr_client_private_key
    );
    mget(env, inner_env, ptr_inner_env, 0);
    mget(env, client_public_key, ptr_client_public_key, ecc_opaque_ristretto255_sha512_Npk);
    mfree(ptr_inner_env, 0);
    mfree(ptr_client_public_key, ecc_opaque_ristretto255_sha512_Npk);
    mfree(ptr_randomized_pwd, 64);
    mfree(ptr_nonce, ecc_opaque_ristretto255_sha512_Nn);
    mfree(ptr_client_private_key, ecc_opaque_ristretto255_sha512_Nsk);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1opaque_1ristretto255_1sha512_1RecoverKeys(
    JNIEnv *env, jclass cls,
    jbyteArray client_private_key,
    jbyteArray client_public_key,
    jbyteArray randomized_pwd,
    jbyteArray nonce,
    jbyteArray inner_env
) {
    byte_t *ptr_client_private_key = mput(env, client_private_key, ecc_opaque_ristretto255_sha512_Nsk);
    byte_t *ptr_client_public_key = mput(env, client_public_key, ecc_opaque_ristretto255_sha512_Npk);
    byte_t *ptr_randomized_pwd = mput(env, randomized_pwd, 64);
    byte_t *ptr_nonce = mput(env, nonce, ecc_opaque_ristretto255_sha512_Nn);
    byte_t *ptr_inner_env = mput(env, inner_env, 0);
    ecc_opaque_ristretto255_sha512_RecoverKeys(
        ptr_client_private_key,
        ptr_client_public_key,
        ptr_randomized_pwd,
        ptr_nonce,
        ptr_inner_env
    );
    mget(env, client_private_key, ptr_client_private_key, ecc_opaque_ristretto255_sha512_Nsk);
    mget(env, client_public_key, ptr_client_public_key, ecc_opaque_ristretto255_sha512_Npk);
    mfree(ptr_client_private_key, ecc_opaque_ristretto255_sha512_Nsk);
    mfree(ptr_client_public_key, ecc_opaque_ristretto255_sha512_Npk);
    mfree(ptr_randomized_pwd, 64);
    mfree(ptr_nonce, ecc_opaque_ristretto255_sha512_Nn);
    mfree(ptr_inner_env, 0);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1opaque_1ristretto255_1sha512_1CreateRegistrationRequestWithBlind(
    JNIEnv *env, jclass cls,
    jbyteArray request_raw,
    jbyteArray password,
    jint password_len,
    jbyteArray blind
) {
    byte_t *ptr_request_raw = mput(env, request_raw, ecc_opaque_ristretto255_sha512_REGISTRATIONREQUESTSIZE);
    byte_t *ptr_password = mput(env, password, password_len);
    byte_t *ptr_blind = mput(env, blind, ecc_opaque_ristretto255_sha512_Noe);
    ecc_opaque_ristretto255_sha512_CreateRegistrationRequestWithBlind(
        ptr_request_raw,
        ptr_password,
        password_len,
        ptr_blind
    );
    mget(env, request_raw, ptr_request_raw, ecc_opaque_ristretto255_sha512_REGISTRATIONREQUESTSIZE);
    mfree(ptr_request_raw, ecc_opaque_ristretto255_sha512_REGISTRATIONREQUESTSIZE);
    mfree(ptr_password, password_len);
    mfree(ptr_blind, ecc_opaque_ristretto255_sha512_Noe);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1opaque_1ristretto255_1sha512_1CreateRegistrationRequest(
    JNIEnv *env, jclass cls,
    jbyteArray request_raw,
    jbyteArray blind,
    jbyteArray password,
    jint password_len
) {
    byte_t *ptr_request_raw = mput(env, request_raw, ecc_opaque_ristretto255_sha512_REGISTRATIONREQUESTSIZE);
    byte_t *ptr_blind = mput(env, blind, ecc_opaque_ristretto255_sha512_Noe);
    byte_t *ptr_password = mput(env, password, password_len);
    ecc_opaque_ristretto255_sha512_CreateRegistrationRequest(
        ptr_request_raw,
        ptr_blind,
        ptr_password,
        password_len
    );
    mget(env, request_raw, ptr_request_raw, ecc_opaque_ristretto255_sha512_REGISTRATIONREQUESTSIZE);
    mget(env, blind, ptr_blind, ecc_opaque_ristretto255_sha512_Noe);
    mfree(ptr_request_raw, ecc_opaque_ristretto255_sha512_REGISTRATIONREQUESTSIZE);
    mfree(ptr_blind, ecc_opaque_ristretto255_sha512_Noe);
    mfree(ptr_password, password_len);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1opaque_1ristretto255_1sha512_1CreateRegistrationResponseWithOprfKey(
    JNIEnv *env, jclass cls,
    jbyteArray response_raw,
    jbyteArray request_raw,
    jbyteArray server_public_key,
    jbyteArray credential_identifier,
    jint credential_identifier_len,
    jbyteArray oprf_key
) {
    byte_t *ptr_response_raw = mput(env, response_raw, ecc_opaque_ristretto255_sha512_REGISTRATIONRESPONSESIZE);
    byte_t *ptr_request_raw = mput(env, request_raw, ecc_opaque_ristretto255_sha512_REGISTRATIONREQUESTSIZE);
    byte_t *ptr_server_public_key = mput(env, server_public_key, ecc_opaque_ristretto255_sha512_Npk);
    byte_t *ptr_credential_identifier = mput(env, credential_identifier, credential_identifier_len);
    byte_t *ptr_oprf_key = mput(env, oprf_key, 32);
    ecc_opaque_ristretto255_sha512_CreateRegistrationResponseWithOprfKey(
        ptr_response_raw,
        ptr_request_raw,
        ptr_server_public_key,
        ptr_credential_identifier,
        credential_identifier_len,
        ptr_oprf_key
    );
    mget(env, response_raw, ptr_response_raw, ecc_opaque_ristretto255_sha512_REGISTRATIONRESPONSESIZE);
    mfree(ptr_response_raw, ecc_opaque_ristretto255_sha512_REGISTRATIONRESPONSESIZE);
    mfree(ptr_request_raw, ecc_opaque_ristretto255_sha512_REGISTRATIONREQUESTSIZE);
    mfree(ptr_server_public_key, ecc_opaque_ristretto255_sha512_Npk);
    mfree(ptr_credential_identifier, credential_identifier_len);
    mfree(ptr_oprf_key, 32);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1opaque_1ristretto255_1sha512_1CreateRegistrationResponse(
    JNIEnv *env, jclass cls,
    jbyteArray response_raw,
    jbyteArray oprf_key,
    jbyteArray request_raw,
    jbyteArray server_public_key,
    jbyteArray credential_identifier,
    jint credential_identifier_len,
    jbyteArray oprf_seed
) {
    byte_t *ptr_response_raw = mput(env, response_raw, ecc_opaque_ristretto255_sha512_REGISTRATIONRESPONSESIZE);
    byte_t *ptr_oprf_key = mput(env, oprf_key, 32);
    byte_t *ptr_request_raw = mput(env, request_raw, ecc_opaque_ristretto255_sha512_REGISTRATIONREQUESTSIZE);
    byte_t *ptr_server_public_key = mput(env, server_public_key, ecc_opaque_ristretto255_sha512_Npk);
    byte_t *ptr_credential_identifier = mput(env, credential_identifier, credential_identifier_len);
    byte_t *ptr_oprf_seed = mput(env, oprf_seed, ecc_opaque_ristretto255_sha512_Nh);
    ecc_opaque_ristretto255_sha512_CreateRegistrationResponse(
        ptr_response_raw,
        ptr_oprf_key,
        ptr_request_raw,
        ptr_server_public_key,
        ptr_credential_identifier,
        credential_identifier_len,
        ptr_oprf_seed
    );
    mget(env, response_raw, ptr_response_raw, ecc_opaque_ristretto255_sha512_REGISTRATIONRESPONSESIZE);
    mget(env, oprf_key, ptr_oprf_key, 32);
    mfree(ptr_response_raw, ecc_opaque_ristretto255_sha512_REGISTRATIONRESPONSESIZE);
    mfree(ptr_oprf_key, 32);
    mfree(ptr_request_raw, ecc_opaque_ristretto255_sha512_REGISTRATIONREQUESTSIZE);
    mfree(ptr_server_public_key, ecc_opaque_ristretto255_sha512_Npk);
    mfree(ptr_credential_identifier, credential_identifier_len);
    mfree(ptr_oprf_seed, ecc_opaque_ristretto255_sha512_Nh);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1opaque_1ristretto255_1sha512_1FinalizeRequestWithNonce(
    JNIEnv *env, jclass cls,
    jbyteArray record_raw,
    jbyteArray export_key,
    jbyteArray client_private_key,
    jbyteArray password,
    jint password_len,
    jbyteArray blind,
    jbyteArray response_raw,
    jbyteArray server_identity,
    jint server_identity_len,
    jbyteArray client_identity,
    jint client_identity_len,
    jbyteArray nonce
) {
    byte_t *ptr_record_raw = mput(env, record_raw, ecc_opaque_ristretto255_sha512_REGISTRATIONUPLOADSIZE);
    byte_t *ptr_export_key = mput(env, export_key, ecc_opaque_ristretto255_sha512_Nh);
    byte_t *ptr_client_private_key = mput(env, client_private_key, 0);
    byte_t *ptr_password = mput(env, password, password_len);
    byte_t *ptr_blind = mput(env, blind, ecc_opaque_ristretto255_sha512_Noe);
    byte_t *ptr_response_raw = mput(env, response_raw, ecc_opaque_ristretto255_sha512_REGISTRATIONRESPONSESIZE);
    byte_t *ptr_server_identity = mput(env, server_identity, server_identity_len);
    byte_t *ptr_client_identity = mput(env, client_identity, client_identity_len);
    byte_t *ptr_nonce = mput(env, nonce, ecc_opaque_ristretto255_sha512_Nn);
    ecc_opaque_ristretto255_sha512_FinalizeRequestWithNonce(
        ptr_record_raw,
        ptr_export_key,
        ptr_client_private_key,
        ptr_password,
        password_len,
        ptr_blind,
        ptr_response_raw,
        ptr_server_identity,
        server_identity_len,
        ptr_client_identity,
        client_identity_len,
        ptr_nonce
    );
    mget(env, record_raw, ptr_record_raw, ecc_opaque_ristretto255_sha512_REGISTRATIONUPLOADSIZE);
    mget(env, export_key, ptr_export_key, ecc_opaque_ristretto255_sha512_Nh);
    mfree(ptr_record_raw, ecc_opaque_ristretto255_sha512_REGISTRATIONUPLOADSIZE);
    mfree(ptr_export_key, ecc_opaque_ristretto255_sha512_Nh);
    mfree(ptr_client_private_key, 0);
    mfree(ptr_password, password_len);
    mfree(ptr_blind, ecc_opaque_ristretto255_sha512_Noe);
    mfree(ptr_response_raw, ecc_opaque_ristretto255_sha512_REGISTRATIONRESPONSESIZE);
    mfree(ptr_server_identity, server_identity_len);
    mfree(ptr_client_identity, client_identity_len);
    mfree(ptr_nonce, ecc_opaque_ristretto255_sha512_Nn);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1opaque_1ristretto255_1sha512_1FinalizeRequest(
    JNIEnv *env, jclass cls,
    jbyteArray record_raw,
    jbyteArray export_key,
    jbyteArray client_private_key,
    jbyteArray password,
    jint password_len,
    jbyteArray blind,
    jbyteArray response_raw,
    jbyteArray server_identity,
    jint server_identity_len,
    jbyteArray client_identity,
    jint client_identity_len
) {
    byte_t *ptr_record_raw = mput(env, record_raw, ecc_opaque_ristretto255_sha512_REGISTRATIONUPLOADSIZE);
    byte_t *ptr_export_key = mput(env, export_key, ecc_opaque_ristretto255_sha512_Nh);
    byte_t *ptr_client_private_key = mput(env, client_private_key, 0);
    byte_t *ptr_password = mput(env, password, password_len);
    byte_t *ptr_blind = mput(env, blind, ecc_opaque_ristretto255_sha512_Noe);
    byte_t *ptr_response_raw = mput(env, response_raw, ecc_opaque_ristretto255_sha512_REGISTRATIONRESPONSESIZE);
    byte_t *ptr_server_identity = mput(env, server_identity, server_identity_len);
    byte_t *ptr_client_identity = mput(env, client_identity, client_identity_len);
    ecc_opaque_ristretto255_sha512_FinalizeRequest(
        ptr_record_raw,
        ptr_export_key,
        ptr_client_private_key,
        ptr_password,
        password_len,
        ptr_blind,
        ptr_response_raw,
        ptr_server_identity,
        server_identity_len,
        ptr_client_identity,
        client_identity_len
    );
    mget(env, record_raw, ptr_record_raw, ecc_opaque_ristretto255_sha512_REGISTRATIONUPLOADSIZE);
    mget(env, export_key, ptr_export_key, ecc_opaque_ristretto255_sha512_Nh);
    mfree(ptr_record_raw, ecc_opaque_ristretto255_sha512_REGISTRATIONUPLOADSIZE);
    mfree(ptr_export_key, ecc_opaque_ristretto255_sha512_Nh);
    mfree(ptr_client_private_key, 0);
    mfree(ptr_password, password_len);
    mfree(ptr_blind, ecc_opaque_ristretto255_sha512_Noe);
    mfree(ptr_response_raw, ecc_opaque_ristretto255_sha512_REGISTRATIONRESPONSESIZE);
    mfree(ptr_server_identity, server_identity_len);
    mfree(ptr_client_identity, client_identity_len);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1opaque_1ristretto255_1sha512_1CreateCredentialRequest(
    JNIEnv *env, jclass cls,
    jbyteArray request_raw,
    jbyteArray blind,
    jbyteArray password,
    jint password_len
) {
    byte_t *ptr_request_raw = mput(env, request_raw, ecc_opaque_ristretto255_sha512_CREDENTIALREQUESTSIZE);
    byte_t *ptr_blind = mput(env, blind, ecc_opaque_ristretto255_sha512_Noe);
    byte_t *ptr_password = mput(env, password, password_len);
    ecc_opaque_ristretto255_sha512_CreateCredentialRequest(
        ptr_request_raw,
        ptr_blind,
        ptr_password,
        password_len
    );
    mget(env, request_raw, ptr_request_raw, ecc_opaque_ristretto255_sha512_CREDENTIALREQUESTSIZE);
    mget(env, blind, ptr_blind, ecc_opaque_ristretto255_sha512_Noe);
    mfree(ptr_request_raw, ecc_opaque_ristretto255_sha512_CREDENTIALREQUESTSIZE);
    mfree(ptr_blind, ecc_opaque_ristretto255_sha512_Noe);
    mfree(ptr_password, password_len);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1opaque_1ristretto255_1sha512_1CreateCredentialResponse(
    JNIEnv *env, jclass cls,
    jbyteArray response_raw,
    jbyteArray request_raw,
    jbyteArray server_public_key,
    jbyteArray record_raw,
    jbyteArray credential_identifier,
    jint credential_identifier_len,
    jbyteArray oprf_seed
) {
    byte_t *ptr_response_raw = mput(env, response_raw, ecc_opaque_ristretto255_sha512_CREDENTIALRESPONSESIZE);
    byte_t *ptr_request_raw = mput(env, request_raw, ecc_opaque_ristretto255_sha512_CREDENTIALREQUESTSIZE);
    byte_t *ptr_server_public_key = mput(env, server_public_key, ecc_opaque_ristretto255_sha512_Npk);
    byte_t *ptr_record_raw = mput(env, record_raw, ecc_opaque_ristretto255_sha512_REGISTRATIONUPLOADSIZE);
    byte_t *ptr_credential_identifier = mput(env, credential_identifier, credential_identifier_len);
    byte_t *ptr_oprf_seed = mput(env, oprf_seed, ecc_opaque_ristretto255_sha512_Nh);
    ecc_opaque_ristretto255_sha512_CreateCredentialResponse(
        ptr_response_raw,
        ptr_request_raw,
        ptr_server_public_key,
        ptr_record_raw,
        ptr_credential_identifier,
        credential_identifier_len,
        ptr_oprf_seed
    );
    mget(env, response_raw, ptr_response_raw, ecc_opaque_ristretto255_sha512_CREDENTIALRESPONSESIZE);
    mfree(ptr_response_raw, ecc_opaque_ristretto255_sha512_CREDENTIALRESPONSESIZE);
    mfree(ptr_request_raw, ecc_opaque_ristretto255_sha512_CREDENTIALREQUESTSIZE);
    mfree(ptr_server_public_key, ecc_opaque_ristretto255_sha512_Npk);
    mfree(ptr_record_raw, ecc_opaque_ristretto255_sha512_REGISTRATIONUPLOADSIZE);
    mfree(ptr_credential_identifier, credential_identifier_len);
    mfree(ptr_oprf_seed, ecc_opaque_ristretto255_sha512_Nh);
}

JNIEXPORT int JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1opaque_1ristretto255_1sha512_1RecoverCredentials(
    JNIEnv *env, jclass cls,
    jbyteArray client_private_key,
    jbyteArray server_public_key,
    jbyteArray export_key,
    jbyteArray password,
    jint password_len,
    jbyteArray blind,
    jbyteArray response,
    jbyteArray server_identity,
    jint server_identity_len,
    jbyteArray client_identity,
    jint client_identity_len
) {
    byte_t *ptr_client_private_key = mput(env, client_private_key, ecc_opaque_ristretto255_sha512_Nsk);
    byte_t *ptr_server_public_key = mput(env, server_public_key, ecc_opaque_ristretto255_sha512_Npk);
    byte_t *ptr_export_key = mput(env, export_key, ecc_opaque_ristretto255_sha512_Nh);
    byte_t *ptr_password = mput(env, password, password_len);
    byte_t *ptr_blind = mput(env, blind, ecc_opaque_ristretto255_sha512_Noe);
    byte_t *ptr_response = mput(env, response, ecc_opaque_ristretto255_sha512_CREDENTIALRESPONSESIZE);
    byte_t *ptr_server_identity = mput(env, server_identity, server_identity_len);
    byte_t *ptr_client_identity = mput(env, client_identity, client_identity_len);
    const int fun_ret = ecc_opaque_ristretto255_sha512_RecoverCredentials(
        ptr_client_private_key,
        ptr_server_public_key,
        ptr_export_key,
        ptr_password,
        password_len,
        ptr_blind,
        ptr_response,
        ptr_server_identity,
        server_identity_len,
        ptr_client_identity,
        client_identity_len
    );
    mget(env, client_private_key, ptr_client_private_key, ecc_opaque_ristretto255_sha512_Nsk);
    mget(env, server_public_key, ptr_server_public_key, ecc_opaque_ristretto255_sha512_Npk);
    mget(env, export_key, ptr_export_key, ecc_opaque_ristretto255_sha512_Nh);
    mfree(ptr_client_private_key, ecc_opaque_ristretto255_sha512_Nsk);
    mfree(ptr_server_public_key, ecc_opaque_ristretto255_sha512_Npk);
    mfree(ptr_export_key, ecc_opaque_ristretto255_sha512_Nh);
    mfree(ptr_password, password_len);
    mfree(ptr_blind, ecc_opaque_ristretto255_sha512_Noe);
    mfree(ptr_response, ecc_opaque_ristretto255_sha512_CREDENTIALRESPONSESIZE);
    mfree(ptr_server_identity, server_identity_len);
    mfree(ptr_client_identity, client_identity_len);
    return fun_ret;
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1opaque_1ristretto255_1sha512_13DH_1Expand_1Label(
    JNIEnv *env, jclass cls,
    jbyteArray out,
    jbyteArray secret,
    jbyteArray label,
    jint label_len,
    jbyteArray context,
    jint context_len,
    jint length
) {
    byte_t *ptr_out = mput(env, out, length);
    byte_t *ptr_secret = mput(env, secret, 64);
    byte_t *ptr_label = mput(env, label, label_len);
    byte_t *ptr_context = mput(env, context, context_len);
    ecc_opaque_ristretto255_sha512_3DH_Expand_Label(
        ptr_out,
        ptr_secret,
        ptr_label,
        label_len,
        ptr_context,
        context_len,
        length
    );
    mget(env, out, ptr_out, length);
    mfree(ptr_out, length);
    mfree(ptr_secret, 64);
    mfree(ptr_label, label_len);
    mfree(ptr_context, context_len);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1opaque_1ristretto255_1sha512_13DH_1Derive_1Secret(
    JNIEnv *env, jclass cls,
    jbyteArray out,
    jbyteArray secret,
    jbyteArray label,
    jint label_len,
    jbyteArray transcript_hash,
    jint transcript_hash_len
) {
    byte_t *ptr_out = mput(env, out, ecc_opaque_ristretto255_sha512_Nx);
    byte_t *ptr_secret = mput(env, secret, 64);
    byte_t *ptr_label = mput(env, label, label_len);
    byte_t *ptr_transcript_hash = mput(env, transcript_hash, transcript_hash_len);
    ecc_opaque_ristretto255_sha512_3DH_Derive_Secret(
        ptr_out,
        ptr_secret,
        ptr_label,
        label_len,
        ptr_transcript_hash,
        transcript_hash_len
    );
    mget(env, out, ptr_out, ecc_opaque_ristretto255_sha512_Nx);
    mfree(ptr_out, ecc_opaque_ristretto255_sha512_Nx);
    mfree(ptr_secret, 64);
    mfree(ptr_label, label_len);
    mfree(ptr_transcript_hash, transcript_hash_len);
}

JNIEXPORT int JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1opaque_1ristretto255_1sha512_13DH_1Preamble(
    JNIEnv *env, jclass cls,
    jbyteArray preamble,
    jint preamble_len,
    jbyteArray context,
    jint context_len,
    jbyteArray client_identity,
    jint client_identity_len,
    jbyteArray ke1,
    jint ke1_len,
    jbyteArray server_identity,
    jint server_identity_len,
    jbyteArray inner_ke2,
    jint inner_ke2_len
) {
    byte_t *ptr_preamble = mput(env, preamble, preamble_len);
    byte_t *ptr_context = mput(env, context, context_len);
    byte_t *ptr_client_identity = mput(env, client_identity, client_identity_len);
    byte_t *ptr_ke1 = mput(env, ke1, ke1_len);
    byte_t *ptr_server_identity = mput(env, server_identity, server_identity_len);
    byte_t *ptr_inner_ke2 = mput(env, inner_ke2, inner_ke2_len);
    const int fun_ret = ecc_opaque_ristretto255_sha512_3DH_Preamble(
        ptr_preamble,
        preamble_len,
        ptr_context,
        context_len,
        ptr_client_identity,
        client_identity_len,
        ptr_ke1,
        ke1_len,
        ptr_server_identity,
        server_identity_len,
        ptr_inner_ke2,
        inner_ke2_len
    );
    mget(env, preamble, ptr_preamble, preamble_len);
    mfree(ptr_preamble, preamble_len);
    mfree(ptr_context, context_len);
    mfree(ptr_client_identity, client_identity_len);
    mfree(ptr_ke1, ke1_len);
    mfree(ptr_server_identity, server_identity_len);
    mfree(ptr_inner_ke2, inner_ke2_len);
    return fun_ret;
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1opaque_1ristretto255_1sha512_13DH_1TripleDHIKM(
    JNIEnv *env, jclass cls,
    jbyteArray ikm,
    jbyteArray sk1,
    jbyteArray pk1,
    jbyteArray sk2,
    jbyteArray pk2,
    jbyteArray sk3,
    jbyteArray pk3
) {
    byte_t *ptr_ikm = mput(env, ikm, 96);
    byte_t *ptr_sk1 = mput(env, sk1, 32);
    byte_t *ptr_pk1 = mput(env, pk1, 32);
    byte_t *ptr_sk2 = mput(env, sk2, 32);
    byte_t *ptr_pk2 = mput(env, pk2, 32);
    byte_t *ptr_sk3 = mput(env, sk3, 32);
    byte_t *ptr_pk3 = mput(env, pk3, 32);
    ecc_opaque_ristretto255_sha512_3DH_TripleDHIKM(
        ptr_ikm,
        ptr_sk1,
        ptr_pk1,
        ptr_sk2,
        ptr_pk2,
        ptr_sk3,
        ptr_pk3
    );
    mget(env, ikm, ptr_ikm, 96);
    mfree(ptr_ikm, 96);
    mfree(ptr_sk1, 32);
    mfree(ptr_pk1, 32);
    mfree(ptr_sk2, 32);
    mfree(ptr_pk2, 32);
    mfree(ptr_sk3, 32);
    mfree(ptr_pk3, 32);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1opaque_1ristretto255_1sha512_13DH_1DeriveKeys(
    JNIEnv *env, jclass cls,
    jbyteArray km2,
    jbyteArray km3,
    jbyteArray session_key,
    jbyteArray ikm,
    jint ikm_len,
    jbyteArray preamble,
    jint preamble_len
) {
    byte_t *ptr_km2 = mput(env, km2, 64);
    byte_t *ptr_km3 = mput(env, km3, 64);
    byte_t *ptr_session_key = mput(env, session_key, 64);
    byte_t *ptr_ikm = mput(env, ikm, ikm_len);
    byte_t *ptr_preamble = mput(env, preamble, preamble_len);
    ecc_opaque_ristretto255_sha512_3DH_DeriveKeys(
        ptr_km2,
        ptr_km3,
        ptr_session_key,
        ptr_ikm,
        ikm_len,
        ptr_preamble,
        preamble_len
    );
    mget(env, km2, ptr_km2, 64);
    mget(env, km3, ptr_km3, 64);
    mget(env, session_key, ptr_session_key, 64);
    mfree(ptr_km2, 64);
    mfree(ptr_km3, 64);
    mfree(ptr_session_key, 64);
    mfree(ptr_ikm, ikm_len);
    mfree(ptr_preamble, preamble_len);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1opaque_1ristretto255_1sha512_13DH_1ClientInit(
    JNIEnv *env, jclass cls,
    jbyteArray ke1_raw,
    jbyteArray state_raw,
    jbyteArray client_identity,
    jint client_identity_len,
    jbyteArray password,
    jint password_len
) {
    byte_t *ptr_ke1_raw = mput(env, ke1_raw, ecc_opaque_ristretto255_sha512_KE1SIZE);
    byte_t *ptr_state_raw = mput(env, state_raw, ecc_opaque_ristretto255_sha512_CLIENTSTATESIZE);
    byte_t *ptr_client_identity = mput(env, client_identity, client_identity_len);
    byte_t *ptr_password = mput(env, password, password_len);
    ecc_opaque_ristretto255_sha512_3DH_ClientInit(
        ptr_ke1_raw,
        ptr_state_raw,
        ptr_client_identity,
        client_identity_len,
        ptr_password,
        password_len
    );
    mget(env, ke1_raw, ptr_ke1_raw, ecc_opaque_ristretto255_sha512_KE1SIZE);
    mget(env, state_raw, ptr_state_raw, ecc_opaque_ristretto255_sha512_CLIENTSTATESIZE);
    mfree(ptr_ke1_raw, ecc_opaque_ristretto255_sha512_KE1SIZE);
    mfree(ptr_state_raw, ecc_opaque_ristretto255_sha512_CLIENTSTATESIZE);
    mfree(ptr_client_identity, client_identity_len);
    mfree(ptr_password, password_len);
}

JNIEXPORT int JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1opaque_1ristretto255_1sha512_13DH_1ClientFinish(
    JNIEnv *env, jclass cls,
    jbyteArray ke3_raw,
    jbyteArray session_key,
    jbyteArray export_key,
    jbyteArray state_raw,
    jbyteArray password,
    jint password_len,
    jbyteArray client_identity,
    jint client_identity_len,
    jbyteArray server_identity,
    jint server_identity_len,
    jbyteArray ke2_raw
) {
    byte_t *ptr_ke3_raw = mput(env, ke3_raw, ecc_opaque_ristretto255_sha512_KE3SIZE);
    byte_t *ptr_session_key = mput(env, session_key, 64);
    byte_t *ptr_export_key = mput(env, export_key, 64);
    byte_t *ptr_state_raw = mput(env, state_raw, ecc_opaque_ristretto255_sha512_CLIENTSTATESIZE);
    byte_t *ptr_password = mput(env, password, password_len);
    byte_t *ptr_client_identity = mput(env, client_identity, client_identity_len);
    byte_t *ptr_server_identity = mput(env, server_identity, server_identity_len);
    byte_t *ptr_ke2_raw = mput(env, ke2_raw, ecc_opaque_ristretto255_sha512_KE2SIZE);
    const int fun_ret = ecc_opaque_ristretto255_sha512_3DH_ClientFinish(
        ptr_ke3_raw,
        ptr_session_key,
        ptr_export_key,
        ptr_state_raw,
        ptr_password,
        password_len,
        ptr_client_identity,
        client_identity_len,
        ptr_server_identity,
        server_identity_len,
        ptr_ke2_raw
    );
    mget(env, ke3_raw, ptr_ke3_raw, ecc_opaque_ristretto255_sha512_KE3SIZE);
    mget(env, session_key, ptr_session_key, 64);
    mget(env, export_key, ptr_export_key, 64);
    mget(env, state_raw, ptr_state_raw, ecc_opaque_ristretto255_sha512_CLIENTSTATESIZE);
    mfree(ptr_ke3_raw, ecc_opaque_ristretto255_sha512_KE3SIZE);
    mfree(ptr_session_key, 64);
    mfree(ptr_export_key, 64);
    mfree(ptr_state_raw, ecc_opaque_ristretto255_sha512_CLIENTSTATESIZE);
    mfree(ptr_password, password_len);
    mfree(ptr_client_identity, client_identity_len);
    mfree(ptr_server_identity, server_identity_len);
    mfree(ptr_ke2_raw, ecc_opaque_ristretto255_sha512_KE2SIZE);
    return fun_ret;
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1opaque_1ristretto255_1sha512_13DH_1Start(
    JNIEnv *env, jclass cls,
    jbyteArray ke1_raw,
    jbyteArray state_raw,
    jbyteArray credential_request
) {
    byte_t *ptr_ke1_raw = mput(env, ke1_raw, ecc_opaque_ristretto255_sha512_KE1SIZE);
    byte_t *ptr_state_raw = mput(env, state_raw, ecc_opaque_ristretto255_sha512_CLIENTSTATESIZE);
    byte_t *ptr_credential_request = mput(env, credential_request, ecc_opaque_ristretto255_sha512_CREDENTIALREQUESTSIZE);
    ecc_opaque_ristretto255_sha512_3DH_Start(
        ptr_ke1_raw,
        ptr_state_raw,
        ptr_credential_request
    );
    mget(env, ke1_raw, ptr_ke1_raw, ecc_opaque_ristretto255_sha512_KE1SIZE);
    mget(env, state_raw, ptr_state_raw, ecc_opaque_ristretto255_sha512_CLIENTSTATESIZE);
    mfree(ptr_ke1_raw, ecc_opaque_ristretto255_sha512_KE1SIZE);
    mfree(ptr_state_raw, ecc_opaque_ristretto255_sha512_CLIENTSTATESIZE);
    mfree(ptr_credential_request, ecc_opaque_ristretto255_sha512_CREDENTIALREQUESTSIZE);
}

JNIEXPORT int JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1opaque_1ristretto255_1sha512_13DH_1ClientFinalize(
    JNIEnv *env, jclass cls,
    jbyteArray ke3_raw,
    jbyteArray session_key,
    jbyteArray state_raw,
    jbyteArray client_identity,
    jint client_identity_len,
    jbyteArray client_private_key,
    jbyteArray server_identity,
    jint server_identity_len,
    jbyteArray server_public_key,
    jbyteArray ke2_raw,
    jbyteArray context,
    jint context_len
) {
    byte_t *ptr_ke3_raw = mput(env, ke3_raw, ecc_opaque_ristretto255_sha512_KE3SIZE);
    byte_t *ptr_session_key = mput(env, session_key, 64);
    byte_t *ptr_state_raw = mput(env, state_raw, ecc_opaque_ristretto255_sha512_CLIENTSTATESIZE);
    byte_t *ptr_client_identity = mput(env, client_identity, client_identity_len);
    byte_t *ptr_client_private_key = mput(env, client_private_key, ecc_opaque_ristretto255_sha512_Nsk);
    byte_t *ptr_server_identity = mput(env, server_identity, server_identity_len);
    byte_t *ptr_server_public_key = mput(env, server_public_key, ecc_opaque_ristretto255_sha512_Npk);
    byte_t *ptr_ke2_raw = mput(env, ke2_raw, ecc_opaque_ristretto255_sha512_KE2SIZE);
    byte_t *ptr_context = mput(env, context, context_len);
    const int fun_ret = ecc_opaque_ristretto255_sha512_3DH_ClientFinalize(
        ptr_ke3_raw,
        ptr_session_key,
        ptr_state_raw,
        ptr_client_identity,
        client_identity_len,
        ptr_client_private_key,
        ptr_server_identity,
        server_identity_len,
        ptr_server_public_key,
        ptr_ke2_raw,
        ptr_context,
        context_len
    );
    mget(env, ke3_raw, ptr_ke3_raw, ecc_opaque_ristretto255_sha512_KE3SIZE);
    mget(env, session_key, ptr_session_key, 64);
    mget(env, state_raw, ptr_state_raw, ecc_opaque_ristretto255_sha512_CLIENTSTATESIZE);
    mfree(ptr_ke3_raw, ecc_opaque_ristretto255_sha512_KE3SIZE);
    mfree(ptr_session_key, 64);
    mfree(ptr_state_raw, ecc_opaque_ristretto255_sha512_CLIENTSTATESIZE);
    mfree(ptr_client_identity, client_identity_len);
    mfree(ptr_client_private_key, ecc_opaque_ristretto255_sha512_Nsk);
    mfree(ptr_server_identity, server_identity_len);
    mfree(ptr_server_public_key, ecc_opaque_ristretto255_sha512_Npk);
    mfree(ptr_ke2_raw, ecc_opaque_ristretto255_sha512_KE2SIZE);
    mfree(ptr_context, context_len);
    return fun_ret;
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1opaque_1ristretto255_1sha512_13DH_1ServerInit(
    JNIEnv *env, jclass cls,
    jbyteArray ke2_raw,
    jbyteArray state_raw,
    jbyteArray server_identity,
    jint server_identity_len,
    jbyteArray server_private_key,
    jbyteArray server_public_key,
    jbyteArray record_raw,
    jbyteArray credential_identifier,
    jint credential_identifier_len,
    jbyteArray oprf_seed,
    jbyteArray ke1_raw,
    jbyteArray context,
    jint context_len
) {
    byte_t *ptr_ke2_raw = mput(env, ke2_raw, ecc_opaque_ristretto255_sha512_KE2SIZE);
    byte_t *ptr_state_raw = mput(env, state_raw, ecc_opaque_ristretto255_sha512_SERVERSTATESIZE);
    byte_t *ptr_server_identity = mput(env, server_identity, server_identity_len);
    byte_t *ptr_server_private_key = mput(env, server_private_key, ecc_opaque_ristretto255_sha512_Nsk);
    byte_t *ptr_server_public_key = mput(env, server_public_key, ecc_opaque_ristretto255_sha512_Npk);
    byte_t *ptr_record_raw = mput(env, record_raw, ecc_opaque_ristretto255_sha512_REGISTRATIONUPLOADSIZE);
    byte_t *ptr_credential_identifier = mput(env, credential_identifier, credential_identifier_len);
    byte_t *ptr_oprf_seed = mput(env, oprf_seed, ecc_opaque_ristretto255_sha512_Nh);
    byte_t *ptr_ke1_raw = mput(env, ke1_raw, ecc_opaque_ristretto255_sha512_KE1SIZE);
    byte_t *ptr_context = mput(env, context, context_len);
    ecc_opaque_ristretto255_sha512_3DH_ServerInit(
        ptr_ke2_raw,
        ptr_state_raw,
        ptr_server_identity,
        server_identity_len,
        ptr_server_private_key,
        ptr_server_public_key,
        ptr_record_raw,
        ptr_credential_identifier,
        credential_identifier_len,
        ptr_oprf_seed,
        ptr_ke1_raw,
        ptr_context,
        context_len
    );
    mget(env, ke2_raw, ptr_ke2_raw, ecc_opaque_ristretto255_sha512_KE2SIZE);
    mget(env, state_raw, ptr_state_raw, ecc_opaque_ristretto255_sha512_SERVERSTATESIZE);
    mfree(ptr_ke2_raw, ecc_opaque_ristretto255_sha512_KE2SIZE);
    mfree(ptr_state_raw, ecc_opaque_ristretto255_sha512_SERVERSTATESIZE);
    mfree(ptr_server_identity, server_identity_len);
    mfree(ptr_server_private_key, ecc_opaque_ristretto255_sha512_Nsk);
    mfree(ptr_server_public_key, ecc_opaque_ristretto255_sha512_Npk);
    mfree(ptr_record_raw, ecc_opaque_ristretto255_sha512_REGISTRATIONUPLOADSIZE);
    mfree(ptr_credential_identifier, credential_identifier_len);
    mfree(ptr_oprf_seed, ecc_opaque_ristretto255_sha512_Nh);
    mfree(ptr_ke1_raw, ecc_opaque_ristretto255_sha512_KE1SIZE);
    mfree(ptr_context, context_len);
}

JNIEXPORT int JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1opaque_1ristretto255_1sha512_13DH_1ServerFinish(
    JNIEnv *env, jclass cls,
    jbyteArray session_key,
    jbyteArray state_raw,
    jbyteArray ke3_raw
) {
    byte_t *ptr_session_key = mput(env, session_key, 64);
    byte_t *ptr_state_raw = mput(env, state_raw, ecc_opaque_ristretto255_sha512_SERVERSTATESIZE);
    byte_t *ptr_ke3_raw = mput(env, ke3_raw, ecc_opaque_ristretto255_sha512_KE3SIZE);
    const int fun_ret = ecc_opaque_ristretto255_sha512_3DH_ServerFinish(
        ptr_session_key,
        ptr_state_raw,
        ptr_ke3_raw
    );
    mget(env, session_key, ptr_session_key, 64);
    mget(env, state_raw, ptr_state_raw, ecc_opaque_ristretto255_sha512_SERVERSTATESIZE);
    mfree(ptr_session_key, 64);
    mfree(ptr_state_raw, ecc_opaque_ristretto255_sha512_SERVERSTATESIZE);
    mfree(ptr_ke3_raw, ecc_opaque_ristretto255_sha512_KE3SIZE);
    return fun_ret;
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1opaque_1ristretto255_1sha512_13DH_1Response(
    JNIEnv *env, jclass cls,
    jbyteArray ke2_raw,
    jbyteArray state_raw,
    jbyteArray server_identity,
    jint server_identity_len,
    jbyteArray server_private_key,
    jbyteArray client_identity,
    jint client_identity_len,
    jbyteArray client_public_key,
    jbyteArray ke1_raw,
    jbyteArray credential_response_raw,
    jbyteArray context,
    jint context_len
) {
    byte_t *ptr_ke2_raw = mput(env, ke2_raw, ecc_opaque_ristretto255_sha512_KE2SIZE);
    byte_t *ptr_state_raw = mput(env, state_raw, ecc_opaque_ristretto255_sha512_SERVERSTATESIZE);
    byte_t *ptr_server_identity = mput(env, server_identity, server_identity_len);
    byte_t *ptr_server_private_key = mput(env, server_private_key, ecc_opaque_ristretto255_sha512_Nsk);
    byte_t *ptr_client_identity = mput(env, client_identity, client_identity_len);
    byte_t *ptr_client_public_key = mput(env, client_public_key, ecc_opaque_ristretto255_sha512_Npk);
    byte_t *ptr_ke1_raw = mput(env, ke1_raw, ecc_opaque_ristretto255_sha512_KE1SIZE);
    byte_t *ptr_credential_response_raw = mput(env, credential_response_raw, ecc_opaque_ristretto255_sha512_CREDENTIALRESPONSESIZE);
    byte_t *ptr_context = mput(env, context, context_len);
    ecc_opaque_ristretto255_sha512_3DH_Response(
        ptr_ke2_raw,
        ptr_state_raw,
        ptr_server_identity,
        server_identity_len,
        ptr_server_private_key,
        ptr_client_identity,
        client_identity_len,
        ptr_client_public_key,
        ptr_ke1_raw,
        ptr_credential_response_raw,
        ptr_context,
        context_len
    );
    mget(env, ke2_raw, ptr_ke2_raw, ecc_opaque_ristretto255_sha512_KE2SIZE);
    mget(env, state_raw, ptr_state_raw, ecc_opaque_ristretto255_sha512_SERVERSTATESIZE);
    mfree(ptr_ke2_raw, ecc_opaque_ristretto255_sha512_KE2SIZE);
    mfree(ptr_state_raw, ecc_opaque_ristretto255_sha512_SERVERSTATESIZE);
    mfree(ptr_server_identity, server_identity_len);
    mfree(ptr_server_private_key, ecc_opaque_ristretto255_sha512_Nsk);
    mfree(ptr_client_identity, client_identity_len);
    mfree(ptr_client_public_key, ecc_opaque_ristretto255_sha512_Npk);
    mfree(ptr_ke1_raw, ecc_opaque_ristretto255_sha512_KE1SIZE);
    mfree(ptr_credential_response_raw, ecc_opaque_ristretto255_sha512_CREDENTIALRESPONSESIZE);
    mfree(ptr_context, context_len);
}

// sign

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1sign_1bls12_1381_1KeyGen(
    JNIEnv *env, jclass cls,
    jbyteArray sk,
    jbyteArray ikm,
    jint ikm_len
) {
    byte_t *ptr_sk = mput(env, sk, ecc_sign_bls12_381_PRIVATEKEYSIZE);
    byte_t *ptr_ikm = mput(env, ikm, ikm_len);
    ecc_sign_bls12_381_KeyGen(
        ptr_sk,
        ptr_ikm,
        ikm_len
    );
    mget(env, sk, ptr_sk, ecc_sign_bls12_381_PRIVATEKEYSIZE);
    mfree(ptr_sk, ecc_sign_bls12_381_PRIVATEKEYSIZE);
    mfree(ptr_ikm, ikm_len);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1sign_1bls12_1381_1SkToPk(
    JNIEnv *env, jclass cls,
    jbyteArray pk,
    jbyteArray sk
) {
    byte_t *ptr_pk = mput(env, pk, ecc_sign_bls12_381_PUBLICKEYSIZE);
    byte_t *ptr_sk = mput(env, sk, ecc_sign_bls12_381_PRIVATEKEYSIZE);
    ecc_sign_bls12_381_SkToPk(
        ptr_pk,
        ptr_sk
    );
    mget(env, pk, ptr_pk, ecc_sign_bls12_381_PUBLICKEYSIZE);
    mfree(ptr_pk, ecc_sign_bls12_381_PUBLICKEYSIZE);
    mfree(ptr_sk, ecc_sign_bls12_381_PRIVATEKEYSIZE);
}

JNIEXPORT int JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1sign_1bls12_1381_1KeyValidate(
    JNIEnv *env, jclass cls,
    jbyteArray pk
) {
    byte_t *ptr_pk = mput(env, pk, ecc_sign_bls12_381_PUBLICKEYSIZE);
    const int fun_ret = ecc_sign_bls12_381_KeyValidate(
        ptr_pk
    );
    mfree(ptr_pk, ecc_sign_bls12_381_PUBLICKEYSIZE);
    return fun_ret;
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1sign_1bls12_1381_1CoreSign(
    JNIEnv *env, jclass cls,
    jbyteArray sig,
    jbyteArray msg,
    jint msg_len,
    jbyteArray sk
) {
    byte_t *ptr_sig = mput(env, sig, ecc_sign_bls12_381_SIGNATURESIZE);
    byte_t *ptr_msg = mput(env, msg, msg_len);
    byte_t *ptr_sk = mput(env, sk, ecc_sign_bls12_381_PRIVATEKEYSIZE);
    ecc_sign_bls12_381_CoreSign(
        ptr_sig,
        ptr_msg,
        msg_len,
        ptr_sk
    );
    mget(env, sig, ptr_sig, ecc_sign_bls12_381_SIGNATURESIZE);
    mfree(ptr_sig, ecc_sign_bls12_381_SIGNATURESIZE);
    mfree(ptr_msg, msg_len);
    mfree(ptr_sk, ecc_sign_bls12_381_PRIVATEKEYSIZE);
}

JNIEXPORT int JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1sign_1bls12_1381_1CoreVerify(
    JNIEnv *env, jclass cls,
    jbyteArray pk,
    jbyteArray msg,
    jint msg_len,
    jbyteArray sig
) {
    byte_t *ptr_pk = mput(env, pk, ecc_sign_bls12_381_PUBLICKEYSIZE);
    byte_t *ptr_msg = mput(env, msg, msg_len);
    byte_t *ptr_sig = mput(env, sig, ecc_sign_bls12_381_SIGNATURESIZE);
    const int fun_ret = ecc_sign_bls12_381_CoreVerify(
        ptr_pk,
        ptr_msg,
        msg_len,
        ptr_sig
    );
    mfree(ptr_pk, ecc_sign_bls12_381_PUBLICKEYSIZE);
    mfree(ptr_msg, msg_len);
    mfree(ptr_sig, ecc_sign_bls12_381_SIGNATURESIZE);
    return fun_ret;
}

// pre

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1pre_1schema1_1MessageGen(
    JNIEnv *env, jclass cls,
    jbyteArray m
) {
    byte_t *ptr_m = mput(env, m, ecc_pre_schema1_MESSAGESIZE);
    ecc_pre_schema1_MessageGen(
        ptr_m
    );
    mget(env, m, ptr_m, ecc_pre_schema1_MESSAGESIZE);
    mfree(ptr_m, ecc_pre_schema1_MESSAGESIZE);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1pre_1schema1_1DeriveKey(
    JNIEnv *env, jclass cls,
    jbyteArray pk,
    jbyteArray sk,
    jbyteArray seed
) {
    byte_t *ptr_pk = mput(env, pk, ecc_pre_schema1_PUBLICKEYSIZE);
    byte_t *ptr_sk = mput(env, sk, ecc_pre_schema1_PRIVATEKEYSIZE);
    byte_t *ptr_seed = mput(env, seed, ecc_pre_schema1_SEEDSIZE);
    ecc_pre_schema1_DeriveKey(
        ptr_pk,
        ptr_sk,
        ptr_seed
    );
    mget(env, pk, ptr_pk, ecc_pre_schema1_PUBLICKEYSIZE);
    mget(env, sk, ptr_sk, ecc_pre_schema1_PRIVATEKEYSIZE);
    mfree(ptr_pk, ecc_pre_schema1_PUBLICKEYSIZE);
    mfree(ptr_sk, ecc_pre_schema1_PRIVATEKEYSIZE);
    mfree(ptr_seed, ecc_pre_schema1_SEEDSIZE);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1pre_1schema1_1KeyGen(
    JNIEnv *env, jclass cls,
    jbyteArray pk,
    jbyteArray sk
) {
    byte_t *ptr_pk = mput(env, pk, ecc_pre_schema1_PUBLICKEYSIZE);
    byte_t *ptr_sk = mput(env, sk, ecc_pre_schema1_PRIVATEKEYSIZE);
    ecc_pre_schema1_KeyGen(
        ptr_pk,
        ptr_sk
    );
    mget(env, pk, ptr_pk, ecc_pre_schema1_PUBLICKEYSIZE);
    mget(env, sk, ptr_sk, ecc_pre_schema1_PRIVATEKEYSIZE);
    mfree(ptr_pk, ecc_pre_schema1_PUBLICKEYSIZE);
    mfree(ptr_sk, ecc_pre_schema1_PRIVATEKEYSIZE);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1pre_1schema1_1DeriveSigningKey(
    JNIEnv *env, jclass cls,
    jbyteArray spk,
    jbyteArray ssk,
    jbyteArray seed
) {
    byte_t *ptr_spk = mput(env, spk, ecc_pre_schema1_SIGNINGPUBLICKEYSIZE);
    byte_t *ptr_ssk = mput(env, ssk, ecc_pre_schema1_SIGNINGPRIVATEKEYSIZE);
    byte_t *ptr_seed = mput(env, seed, ecc_pre_schema1_SEEDSIZE);
    ecc_pre_schema1_DeriveSigningKey(
        ptr_spk,
        ptr_ssk,
        ptr_seed
    );
    mget(env, spk, ptr_spk, ecc_pre_schema1_SIGNINGPUBLICKEYSIZE);
    mget(env, ssk, ptr_ssk, ecc_pre_schema1_SIGNINGPRIVATEKEYSIZE);
    mfree(ptr_spk, ecc_pre_schema1_SIGNINGPUBLICKEYSIZE);
    mfree(ptr_ssk, ecc_pre_schema1_SIGNINGPRIVATEKEYSIZE);
    mfree(ptr_seed, ecc_pre_schema1_SEEDSIZE);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1pre_1schema1_1SigningKeyGen(
    JNIEnv *env, jclass cls,
    jbyteArray spk,
    jbyteArray ssk
) {
    byte_t *ptr_spk = mput(env, spk, ecc_pre_schema1_SIGNINGPUBLICKEYSIZE);
    byte_t *ptr_ssk = mput(env, ssk, ecc_pre_schema1_SIGNINGPRIVATEKEYSIZE);
    ecc_pre_schema1_SigningKeyGen(
        ptr_spk,
        ptr_ssk
    );
    mget(env, spk, ptr_spk, ecc_pre_schema1_SIGNINGPUBLICKEYSIZE);
    mget(env, ssk, ptr_ssk, ecc_pre_schema1_SIGNINGPRIVATEKEYSIZE);
    mfree(ptr_spk, ecc_pre_schema1_SIGNINGPUBLICKEYSIZE);
    mfree(ptr_ssk, ecc_pre_schema1_SIGNINGPRIVATEKEYSIZE);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1pre_1schema1_1EncryptWithSeed(
    JNIEnv *env, jclass cls,
    jbyteArray C_j_raw,
    jbyteArray m,
    jbyteArray pk_j,
    jbyteArray spk_i,
    jbyteArray ssk_i,
    jbyteArray seed
) {
    byte_t *ptr_C_j_raw = mput(env, C_j_raw, ecc_pre_schema1_CIPHERTEXTLEVEL1SIZE);
    byte_t *ptr_m = mput(env, m, ecc_pre_schema1_MESSAGESIZE);
    byte_t *ptr_pk_j = mput(env, pk_j, ecc_pre_schema1_PUBLICKEYSIZE);
    byte_t *ptr_spk_i = mput(env, spk_i, ecc_pre_schema1_SIGNINGPUBLICKEYSIZE);
    byte_t *ptr_ssk_i = mput(env, ssk_i, ecc_pre_schema1_SIGNINGPRIVATEKEYSIZE);
    byte_t *ptr_seed = mput(env, seed, ecc_pre_schema1_SEEDSIZE);
    ecc_pre_schema1_EncryptWithSeed(
        ptr_C_j_raw,
        ptr_m,
        ptr_pk_j,
        ptr_spk_i,
        ptr_ssk_i,
        ptr_seed
    );
    mget(env, C_j_raw, ptr_C_j_raw, ecc_pre_schema1_CIPHERTEXTLEVEL1SIZE);
    mfree(ptr_C_j_raw, ecc_pre_schema1_CIPHERTEXTLEVEL1SIZE);
    mfree(ptr_m, ecc_pre_schema1_MESSAGESIZE);
    mfree(ptr_pk_j, ecc_pre_schema1_PUBLICKEYSIZE);
    mfree(ptr_spk_i, ecc_pre_schema1_SIGNINGPUBLICKEYSIZE);
    mfree(ptr_ssk_i, ecc_pre_schema1_SIGNINGPRIVATEKEYSIZE);
    mfree(ptr_seed, ecc_pre_schema1_SEEDSIZE);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1pre_1schema1_1Encrypt(
    JNIEnv *env, jclass cls,
    jbyteArray C_j_raw,
    jbyteArray m,
    jbyteArray pk_j,
    jbyteArray spk_i,
    jbyteArray ssk_i
) {
    byte_t *ptr_C_j_raw = mput(env, C_j_raw, ecc_pre_schema1_CIPHERTEXTLEVEL1SIZE);
    byte_t *ptr_m = mput(env, m, ecc_pre_schema1_MESSAGESIZE);
    byte_t *ptr_pk_j = mput(env, pk_j, ecc_pre_schema1_PUBLICKEYSIZE);
    byte_t *ptr_spk_i = mput(env, spk_i, ecc_pre_schema1_SIGNINGPUBLICKEYSIZE);
    byte_t *ptr_ssk_i = mput(env, ssk_i, ecc_pre_schema1_SIGNINGPRIVATEKEYSIZE);
    ecc_pre_schema1_Encrypt(
        ptr_C_j_raw,
        ptr_m,
        ptr_pk_j,
        ptr_spk_i,
        ptr_ssk_i
    );
    mget(env, C_j_raw, ptr_C_j_raw, ecc_pre_schema1_CIPHERTEXTLEVEL1SIZE);
    mfree(ptr_C_j_raw, ecc_pre_schema1_CIPHERTEXTLEVEL1SIZE);
    mfree(ptr_m, ecc_pre_schema1_MESSAGESIZE);
    mfree(ptr_pk_j, ecc_pre_schema1_PUBLICKEYSIZE);
    mfree(ptr_spk_i, ecc_pre_schema1_SIGNINGPUBLICKEYSIZE);
    mfree(ptr_ssk_i, ecc_pre_schema1_SIGNINGPRIVATEKEYSIZE);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1pre_1schema1_1ReKeyGen(
    JNIEnv *env, jclass cls,
    jbyteArray tk_i_j_raw,
    jbyteArray sk_i,
    jbyteArray pk_j,
    jbyteArray spk_i,
    jbyteArray ssk_i
) {
    byte_t *ptr_tk_i_j_raw = mput(env, tk_i_j_raw, ecc_pre_schema1_REKEYSIZE);
    byte_t *ptr_sk_i = mput(env, sk_i, ecc_pre_schema1_PRIVATEKEYSIZE);
    byte_t *ptr_pk_j = mput(env, pk_j, ecc_pre_schema1_PUBLICKEYSIZE);
    byte_t *ptr_spk_i = mput(env, spk_i, ecc_pre_schema1_SIGNINGPUBLICKEYSIZE);
    byte_t *ptr_ssk_i = mput(env, ssk_i, ecc_pre_schema1_SIGNINGPRIVATEKEYSIZE);
    ecc_pre_schema1_ReKeyGen(
        ptr_tk_i_j_raw,
        ptr_sk_i,
        ptr_pk_j,
        ptr_spk_i,
        ptr_ssk_i
    );
    mget(env, tk_i_j_raw, ptr_tk_i_j_raw, ecc_pre_schema1_REKEYSIZE);
    mfree(ptr_tk_i_j_raw, ecc_pre_schema1_REKEYSIZE);
    mfree(ptr_sk_i, ecc_pre_schema1_PRIVATEKEYSIZE);
    mfree(ptr_pk_j, ecc_pre_schema1_PUBLICKEYSIZE);
    mfree(ptr_spk_i, ecc_pre_schema1_SIGNINGPUBLICKEYSIZE);
    mfree(ptr_ssk_i, ecc_pre_schema1_SIGNINGPRIVATEKEYSIZE);
}

JNIEXPORT int JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1pre_1schema1_1ReEncrypt(
    JNIEnv *env, jclass cls,
    jbyteArray C_j_raw,
    jbyteArray C_i_raw,
    jbyteArray tk_i_j_raw,
    jbyteArray spk_i,
    jbyteArray pk_j,
    jbyteArray spk,
    jbyteArray ssk
) {
    byte_t *ptr_C_j_raw = mput(env, C_j_raw, ecc_pre_schema1_CIPHERTEXTLEVEL2SIZE);
    byte_t *ptr_C_i_raw = mput(env, C_i_raw, ecc_pre_schema1_CIPHERTEXTLEVEL1SIZE);
    byte_t *ptr_tk_i_j_raw = mput(env, tk_i_j_raw, ecc_pre_schema1_REKEYSIZE);
    byte_t *ptr_spk_i = mput(env, spk_i, ecc_pre_schema1_SIGNINGPUBLICKEYSIZE);
    byte_t *ptr_pk_j = mput(env, pk_j, ecc_pre_schema1_PUBLICKEYSIZE);
    byte_t *ptr_spk = mput(env, spk, ecc_pre_schema1_SIGNINGPUBLICKEYSIZE);
    byte_t *ptr_ssk = mput(env, ssk, ecc_pre_schema1_SIGNINGPRIVATEKEYSIZE);
    const int fun_ret = ecc_pre_schema1_ReEncrypt(
        ptr_C_j_raw,
        ptr_C_i_raw,
        ptr_tk_i_j_raw,
        ptr_spk_i,
        ptr_pk_j,
        ptr_spk,
        ptr_ssk
    );
    mget(env, C_j_raw, ptr_C_j_raw, ecc_pre_schema1_CIPHERTEXTLEVEL2SIZE);
    mfree(ptr_C_j_raw, ecc_pre_schema1_CIPHERTEXTLEVEL2SIZE);
    mfree(ptr_C_i_raw, ecc_pre_schema1_CIPHERTEXTLEVEL1SIZE);
    mfree(ptr_tk_i_j_raw, ecc_pre_schema1_REKEYSIZE);
    mfree(ptr_spk_i, ecc_pre_schema1_SIGNINGPUBLICKEYSIZE);
    mfree(ptr_pk_j, ecc_pre_schema1_PUBLICKEYSIZE);
    mfree(ptr_spk, ecc_pre_schema1_SIGNINGPUBLICKEYSIZE);
    mfree(ptr_ssk, ecc_pre_schema1_SIGNINGPRIVATEKEYSIZE);
    return fun_ret;
}

JNIEXPORT int JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1pre_1schema1_1DecryptLevel1(
    JNIEnv *env, jclass cls,
    jbyteArray m,
    jbyteArray C_i_raw,
    jbyteArray sk_i,
    jbyteArray spk_i
) {
    byte_t *ptr_m = mput(env, m, ecc_pre_schema1_MESSAGESIZE);
    byte_t *ptr_C_i_raw = mput(env, C_i_raw, ecc_pre_schema1_CIPHERTEXTLEVEL1SIZE);
    byte_t *ptr_sk_i = mput(env, sk_i, ecc_pre_schema1_PRIVATEKEYSIZE);
    byte_t *ptr_spk_i = mput(env, spk_i, ecc_pre_schema1_SIGNINGPUBLICKEYSIZE);
    const int fun_ret = ecc_pre_schema1_DecryptLevel1(
        ptr_m,
        ptr_C_i_raw,
        ptr_sk_i,
        ptr_spk_i
    );
    mget(env, m, ptr_m, ecc_pre_schema1_MESSAGESIZE);
    mfree(ptr_m, ecc_pre_schema1_MESSAGESIZE);
    mfree(ptr_C_i_raw, ecc_pre_schema1_CIPHERTEXTLEVEL1SIZE);
    mfree(ptr_sk_i, ecc_pre_schema1_PRIVATEKEYSIZE);
    mfree(ptr_spk_i, ecc_pre_schema1_SIGNINGPUBLICKEYSIZE);
    return fun_ret;
}

JNIEXPORT int JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1pre_1schema1_1DecryptLevel2(
    JNIEnv *env, jclass cls,
    jbyteArray m,
    jbyteArray C_j_raw,
    jbyteArray sk_j,
    jbyteArray spk
) {
    byte_t *ptr_m = mput(env, m, ecc_pre_schema1_MESSAGESIZE);
    byte_t *ptr_C_j_raw = mput(env, C_j_raw, ecc_pre_schema1_CIPHERTEXTLEVEL2SIZE);
    byte_t *ptr_sk_j = mput(env, sk_j, ecc_pre_schema1_PRIVATEKEYSIZE);
    byte_t *ptr_spk = mput(env, spk, ecc_pre_schema1_SIGNINGPUBLICKEYSIZE);
    const int fun_ret = ecc_pre_schema1_DecryptLevel2(
        ptr_m,
        ptr_C_j_raw,
        ptr_sk_j,
        ptr_spk
    );
    mget(env, m, ptr_m, ecc_pre_schema1_MESSAGESIZE);
    mfree(ptr_m, ecc_pre_schema1_MESSAGESIZE);
    mfree(ptr_C_j_raw, ecc_pre_schema1_CIPHERTEXTLEVEL2SIZE);
    mfree(ptr_sk_j, ecc_pre_schema1_PRIVATEKEYSIZE);
    mfree(ptr_spk, ecc_pre_schema1_SIGNINGPUBLICKEYSIZE);
    return fun_ret;
}

#ifdef __cplusplus
}
#endif

