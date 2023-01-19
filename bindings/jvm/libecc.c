/*
 * Copyright (c) 2021-2023, Alden Torres
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
    byte_t *ptr_digest = mput(env, digest, ecc_hash_sha256_HASHSIZE);
    byte_t *ptr_input = mput(env, input, input_len);
    ecc_hash_sha256(
        ptr_digest,
        ptr_input,
        input_len
    );
    mget(env, digest, ptr_digest, ecc_hash_sha256_HASHSIZE);
    mfree(ptr_digest, ecc_hash_sha256_HASHSIZE);
    mfree(ptr_input, input_len);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1hash_1sha512(
    JNIEnv *env, jclass cls,
    jbyteArray digest,
    jbyteArray input,
    jint input_len
) {
    byte_t *ptr_digest = mput(env, digest, ecc_hash_sha512_HASHSIZE);
    byte_t *ptr_input = mput(env, input, input_len);
    ecc_hash_sha512(
        ptr_digest,
        ptr_input,
        input_len
    );
    mget(env, digest, ptr_digest, ecc_hash_sha512_HASHSIZE);
    mfree(ptr_digest, ecc_hash_sha512_HASHSIZE);
    mfree(ptr_input, input_len);
}

// mac

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1mac_1hmac_1sha256(
    JNIEnv *env, jclass cls,
    jbyteArray digest,
    jbyteArray text,
    jint text_len,
    jbyteArray key,
    jint key_len
) {
    byte_t *ptr_digest = mput(env, digest, ecc_mac_hmac_sha256_HASHSIZE);
    byte_t *ptr_text = mput(env, text, text_len);
    byte_t *ptr_key = mput(env, key, key_len);
    ecc_mac_hmac_sha256(
        ptr_digest,
        ptr_text,
        text_len,
        ptr_key,
        key_len
    );
    mget(env, digest, ptr_digest, ecc_mac_hmac_sha256_HASHSIZE);
    mfree(ptr_digest, ecc_mac_hmac_sha256_HASHSIZE);
    mfree(ptr_text, text_len);
    mfree(ptr_key, key_len);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1mac_1hmac_1sha512(
    JNIEnv *env, jclass cls,
    jbyteArray digest,
    jbyteArray text,
    jint text_len,
    jbyteArray key,
    jint key_len
) {
    byte_t *ptr_digest = mput(env, digest, ecc_mac_hmac_sha512_HASHSIZE);
    byte_t *ptr_text = mput(env, text, text_len);
    byte_t *ptr_key = mput(env, key, key_len);
    ecc_mac_hmac_sha512(
        ptr_digest,
        ptr_text,
        text_len,
        ptr_key,
        key_len
    );
    mget(env, digest, ptr_digest, ecc_mac_hmac_sha512_HASHSIZE);
    mfree(ptr_digest, ecc_mac_hmac_sha512_HASHSIZE);
    mfree(ptr_text, text_len);
    mfree(ptr_key, key_len);
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

JNIEXPORT int JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1kdf_1scrypt(
    JNIEnv *env, jclass cls,
    jbyteArray out,
    jbyteArray passphrase,
    jint passphrase_len,
    jbyteArray salt,
    jint salt_len,
    jint cost,
    jint block_size,
    jint parallelization,
    jint len
) {
    byte_t *ptr_out = mput(env, out, len);
    byte_t *ptr_passphrase = mput(env, passphrase, passphrase_len);
    byte_t *ptr_salt = mput(env, salt, salt_len);
    const int fun_ret = ecc_kdf_scrypt(
        ptr_out,
        ptr_passphrase,
        passphrase_len,
        ptr_salt,
        salt_len,
        cost,
        block_size,
        parallelization,
        len
    );
    mget(env, out, ptr_out, len);
    mfree(ptr_out, len);
    mfree(ptr_passphrase, passphrase_len);
    mfree(ptr_salt, salt_len);
    return fun_ret;
}

// ed25519

JNIEXPORT int JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1ed25519_1is_1valid_1point(
    JNIEnv *env, jclass cls,
    jbyteArray p
) {
    byte_t *ptr_p = mput(env, p, ecc_ed25519_ELEMENTSIZE);
    const int fun_ret = ecc_ed25519_is_valid_point(
        ptr_p
    );
    mfree(ptr_p, ecc_ed25519_ELEMENTSIZE);
    return fun_ret;
}

JNIEXPORT int JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1ed25519_1add(
    JNIEnv *env, jclass cls,
    jbyteArray r,
    jbyteArray p,
    jbyteArray q
) {
    byte_t *ptr_r = mput(env, r, ecc_ed25519_ELEMENTSIZE);
    byte_t *ptr_p = mput(env, p, ecc_ed25519_ELEMENTSIZE);
    byte_t *ptr_q = mput(env, q, ecc_ed25519_ELEMENTSIZE);
    const int fun_ret = ecc_ed25519_add(
        ptr_r,
        ptr_p,
        ptr_q
    );
    mget(env, r, ptr_r, ecc_ed25519_ELEMENTSIZE);
    mfree(ptr_r, ecc_ed25519_ELEMENTSIZE);
    mfree(ptr_p, ecc_ed25519_ELEMENTSIZE);
    mfree(ptr_q, ecc_ed25519_ELEMENTSIZE);
    return fun_ret;
}

JNIEXPORT int JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1ed25519_1sub(
    JNIEnv *env, jclass cls,
    jbyteArray r,
    jbyteArray p,
    jbyteArray q
) {
    byte_t *ptr_r = mput(env, r, ecc_ed25519_ELEMENTSIZE);
    byte_t *ptr_p = mput(env, p, ecc_ed25519_ELEMENTSIZE);
    byte_t *ptr_q = mput(env, q, ecc_ed25519_ELEMENTSIZE);
    const int fun_ret = ecc_ed25519_sub(
        ptr_r,
        ptr_p,
        ptr_q
    );
    mget(env, r, ptr_r, ecc_ed25519_ELEMENTSIZE);
    mfree(ptr_r, ecc_ed25519_ELEMENTSIZE);
    mfree(ptr_p, ecc_ed25519_ELEMENTSIZE);
    mfree(ptr_q, ecc_ed25519_ELEMENTSIZE);
    return fun_ret;
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1ed25519_1generator(
    JNIEnv *env, jclass cls,
    jbyteArray g
) {
    byte_t *ptr_g = mput(env, g, ecc_ed25519_ELEMENTSIZE);
    ecc_ed25519_generator(
        ptr_g
    );
    mget(env, g, ptr_g, ecc_ed25519_ELEMENTSIZE);
    mfree(ptr_g, ecc_ed25519_ELEMENTSIZE);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1ed25519_1from_1uniform(
    JNIEnv *env, jclass cls,
    jbyteArray p,
    jbyteArray r
) {
    byte_t *ptr_p = mput(env, p, ecc_ed25519_ELEMENTSIZE);
    byte_t *ptr_r = mput(env, r, ecc_ed25519_UNIFORMSIZE);
    ecc_ed25519_from_uniform(
        ptr_p,
        ptr_r
    );
    mget(env, p, ptr_p, ecc_ed25519_ELEMENTSIZE);
    mfree(ptr_p, ecc_ed25519_ELEMENTSIZE);
    mfree(ptr_r, ecc_ed25519_UNIFORMSIZE);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1ed25519_1random(
    JNIEnv *env, jclass cls,
    jbyteArray p
) {
    byte_t *ptr_p = mput(env, p, ecc_ed25519_ELEMENTSIZE);
    ecc_ed25519_random(
        ptr_p
    );
    mget(env, p, ptr_p, ecc_ed25519_ELEMENTSIZE);
    mfree(ptr_p, ecc_ed25519_ELEMENTSIZE);
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
    byte_t *ptr_q = mput(env, q, ecc_ed25519_ELEMENTSIZE);
    byte_t *ptr_n = mput(env, n, ecc_ed25519_SCALARSIZE);
    byte_t *ptr_p = mput(env, p, ecc_ed25519_ELEMENTSIZE);
    const int fun_ret = ecc_ed25519_scalarmult(
        ptr_q,
        ptr_n,
        ptr_p
    );
    mget(env, q, ptr_q, ecc_ed25519_ELEMENTSIZE);
    mfree(ptr_q, ecc_ed25519_ELEMENTSIZE);
    mfree(ptr_n, ecc_ed25519_SCALARSIZE);
    mfree(ptr_p, ecc_ed25519_ELEMENTSIZE);
    return fun_ret;
}

JNIEXPORT int JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1ed25519_1scalarmult_1base(
    JNIEnv *env, jclass cls,
    jbyteArray q,
    jbyteArray n
) {
    byte_t *ptr_q = mput(env, q, ecc_ed25519_ELEMENTSIZE);
    byte_t *ptr_n = mput(env, n, ecc_ed25519_SCALARSIZE);
    const int fun_ret = ecc_ed25519_scalarmult_base(
        ptr_q,
        ptr_n
    );
    mget(env, q, ptr_q, ecc_ed25519_ELEMENTSIZE);
    mfree(ptr_q, ecc_ed25519_ELEMENTSIZE);
    mfree(ptr_n, ecc_ed25519_SCALARSIZE);
    return fun_ret;
}

// ristretto255

JNIEXPORT int JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1ristretto255_1is_1valid_1point(
    JNIEnv *env, jclass cls,
    jbyteArray p
) {
    byte_t *ptr_p = mput(env, p, ecc_ristretto255_ELEMENTSIZE);
    const int fun_ret = ecc_ristretto255_is_valid_point(
        ptr_p
    );
    mfree(ptr_p, ecc_ristretto255_ELEMENTSIZE);
    return fun_ret;
}

JNIEXPORT int JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1ristretto255_1add(
    JNIEnv *env, jclass cls,
    jbyteArray r,
    jbyteArray p,
    jbyteArray q
) {
    byte_t *ptr_r = mput(env, r, ecc_ristretto255_ELEMENTSIZE);
    byte_t *ptr_p = mput(env, p, ecc_ristretto255_ELEMENTSIZE);
    byte_t *ptr_q = mput(env, q, ecc_ristretto255_ELEMENTSIZE);
    const int fun_ret = ecc_ristretto255_add(
        ptr_r,
        ptr_p,
        ptr_q
    );
    mget(env, r, ptr_r, ecc_ristretto255_ELEMENTSIZE);
    mfree(ptr_r, ecc_ristretto255_ELEMENTSIZE);
    mfree(ptr_p, ecc_ristretto255_ELEMENTSIZE);
    mfree(ptr_q, ecc_ristretto255_ELEMENTSIZE);
    return fun_ret;
}

JNIEXPORT int JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1ristretto255_1sub(
    JNIEnv *env, jclass cls,
    jbyteArray r,
    jbyteArray p,
    jbyteArray q
) {
    byte_t *ptr_r = mput(env, r, ecc_ristretto255_ELEMENTSIZE);
    byte_t *ptr_p = mput(env, p, ecc_ristretto255_ELEMENTSIZE);
    byte_t *ptr_q = mput(env, q, ecc_ristretto255_ELEMENTSIZE);
    const int fun_ret = ecc_ristretto255_sub(
        ptr_r,
        ptr_p,
        ptr_q
    );
    mget(env, r, ptr_r, ecc_ristretto255_ELEMENTSIZE);
    mfree(ptr_r, ecc_ristretto255_ELEMENTSIZE);
    mfree(ptr_p, ecc_ristretto255_ELEMENTSIZE);
    mfree(ptr_q, ecc_ristretto255_ELEMENTSIZE);
    return fun_ret;
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1ristretto255_1generator(
    JNIEnv *env, jclass cls,
    jbyteArray g
) {
    byte_t *ptr_g = mput(env, g, ecc_ristretto255_ELEMENTSIZE);
    ecc_ristretto255_generator(
        ptr_g
    );
    mget(env, g, ptr_g, ecc_ristretto255_ELEMENTSIZE);
    mfree(ptr_g, ecc_ristretto255_ELEMENTSIZE);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1ristretto255_1from_1hash(
    JNIEnv *env, jclass cls,
    jbyteArray p,
    jbyteArray r
) {
    byte_t *ptr_p = mput(env, p, ecc_ristretto255_ELEMENTSIZE);
    byte_t *ptr_r = mput(env, r, ecc_ristretto255_HASHSIZE);
    ecc_ristretto255_from_hash(
        ptr_p,
        ptr_r
    );
    mget(env, p, ptr_p, ecc_ristretto255_ELEMENTSIZE);
    mfree(ptr_p, ecc_ristretto255_ELEMENTSIZE);
    mfree(ptr_r, ecc_ristretto255_HASHSIZE);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1ristretto255_1random(
    JNIEnv *env, jclass cls,
    jbyteArray p
) {
    byte_t *ptr_p = mput(env, p, ecc_ristretto255_ELEMENTSIZE);
    ecc_ristretto255_random(
        ptr_p
    );
    mget(env, p, ptr_p, ecc_ristretto255_ELEMENTSIZE);
    mfree(ptr_p, ecc_ristretto255_ELEMENTSIZE);
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
    byte_t *ptr_q = mput(env, q, ecc_ristretto255_ELEMENTSIZE);
    byte_t *ptr_n = mput(env, n, ecc_ristretto255_SCALARSIZE);
    byte_t *ptr_p = mput(env, p, ecc_ristretto255_ELEMENTSIZE);
    const int fun_ret = ecc_ristretto255_scalarmult(
        ptr_q,
        ptr_n,
        ptr_p
    );
    mget(env, q, ptr_q, ecc_ristretto255_ELEMENTSIZE);
    mfree(ptr_q, ecc_ristretto255_ELEMENTSIZE);
    mfree(ptr_n, ecc_ristretto255_SCALARSIZE);
    mfree(ptr_p, ecc_ristretto255_ELEMENTSIZE);
    return fun_ret;
}

JNIEXPORT int JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1ristretto255_1scalarmult_1base(
    JNIEnv *env, jclass cls,
    jbyteArray q,
    jbyteArray n
) {
    byte_t *ptr_q = mput(env, q, ecc_ristretto255_ELEMENTSIZE);
    byte_t *ptr_n = mput(env, n, ecc_ristretto255_SCALARSIZE);
    const int fun_ret = ecc_ristretto255_scalarmult_base(
        ptr_q,
        ptr_n
    );
    mget(env, q, ptr_q, ecc_ristretto255_ELEMENTSIZE);
    mfree(ptr_q, ecc_ristretto255_ELEMENTSIZE);
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

JNIEXPORT int JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1h2c_1expand_1message_1xmd_1sha256(
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
    const int fun_ret = ecc_h2c_expand_message_xmd_sha256(
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
    return fun_ret;
}

JNIEXPORT int JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1h2c_1expand_1message_1xmd_1sha512(
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
    const int fun_ret = ecc_h2c_expand_message_xmd_sha512(
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
    return fun_ret;
}

// voprf

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1voprf_1ristretto255_1sha512_1GenerateProofWithScalar(
    JNIEnv *env, jclass cls,
    jbyteArray proof,
    jbyteArray k,
    jbyteArray A,
    jbyteArray B,
    jbyteArray C,
    jbyteArray D,
    jint m,
    jint mode,
    jbyteArray r
) {
    byte_t *ptr_proof = mput(env, proof, ecc_voprf_ristretto255_sha512_PROOFSIZE);
    byte_t *ptr_k = mput(env, k, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    byte_t *ptr_A = mput(env, A, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_B = mput(env, B, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_C = mput(env, C, m*ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_D = mput(env, D, m*ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_r = mput(env, r, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    ecc_voprf_ristretto255_sha512_GenerateProofWithScalar(
        ptr_proof,
        ptr_k,
        ptr_A,
        ptr_B,
        ptr_C,
        ptr_D,
        m,
        mode,
        ptr_r
    );
    mget(env, proof, ptr_proof, ecc_voprf_ristretto255_sha512_PROOFSIZE);
    mfree(ptr_proof, ecc_voprf_ristretto255_sha512_PROOFSIZE);
    mfree(ptr_k, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_A, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_B, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_C, m*ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_D, m*ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_r, ecc_voprf_ristretto255_sha512_SCALARSIZE);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1voprf_1ristretto255_1sha512_1GenerateProof(
    JNIEnv *env, jclass cls,
    jbyteArray proof,
    jbyteArray k,
    jbyteArray A,
    jbyteArray B,
    jbyteArray C,
    jbyteArray D,
    jint m,
    jint mode
) {
    byte_t *ptr_proof = mput(env, proof, ecc_voprf_ristretto255_sha512_PROOFSIZE);
    byte_t *ptr_k = mput(env, k, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    byte_t *ptr_A = mput(env, A, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_B = mput(env, B, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_C = mput(env, C, m*ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_D = mput(env, D, m*ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    ecc_voprf_ristretto255_sha512_GenerateProof(
        ptr_proof,
        ptr_k,
        ptr_A,
        ptr_B,
        ptr_C,
        ptr_D,
        m,
        mode
    );
    mget(env, proof, ptr_proof, ecc_voprf_ristretto255_sha512_PROOFSIZE);
    mfree(ptr_proof, ecc_voprf_ristretto255_sha512_PROOFSIZE);
    mfree(ptr_k, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_A, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_B, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_C, m*ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_D, m*ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1voprf_1ristretto255_1sha512_1ComputeCompositesFast(
    JNIEnv *env, jclass cls,
    jbyteArray M,
    jbyteArray Z,
    jbyteArray k,
    jbyteArray B,
    jbyteArray C,
    jbyteArray D,
    jint m,
    jint mode
) {
    byte_t *ptr_M = mput(env, M, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_Z = mput(env, Z, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_k = mput(env, k, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    byte_t *ptr_B = mput(env, B, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_C = mput(env, C, m*ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_D = mput(env, D, m*ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    ecc_voprf_ristretto255_sha512_ComputeCompositesFast(
        ptr_M,
        ptr_Z,
        ptr_k,
        ptr_B,
        ptr_C,
        ptr_D,
        m,
        mode
    );
    mget(env, M, ptr_M, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mget(env, Z, ptr_Z, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_M, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_Z, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_k, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_B, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_C, m*ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_D, m*ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
}

JNIEXPORT int JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1voprf_1ristretto255_1sha512_1VerifyProof(
    JNIEnv *env, jclass cls,
    jbyteArray A,
    jbyteArray B,
    jbyteArray C,
    jbyteArray D,
    jint m,
    jint mode,
    jbyteArray proof
) {
    byte_t *ptr_A = mput(env, A, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_B = mput(env, B, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_C = mput(env, C, m*ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_D = mput(env, D, m*ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_proof = mput(env, proof, ecc_voprf_ristretto255_sha512_PROOFSIZE);
    const int fun_ret = ecc_voprf_ristretto255_sha512_VerifyProof(
        ptr_A,
        ptr_B,
        ptr_C,
        ptr_D,
        m,
        mode,
        ptr_proof
    );
    mfree(ptr_A, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_B, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_C, m*ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_D, m*ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_proof, ecc_voprf_ristretto255_sha512_PROOFSIZE);
    return fun_ret;
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1voprf_1ristretto255_1sha512_1ComputeComposites(
    JNIEnv *env, jclass cls,
    jbyteArray M,
    jbyteArray Z,
    jbyteArray B,
    jbyteArray C,
    jbyteArray D,
    jint m,
    jint mode
) {
    byte_t *ptr_M = mput(env, M, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_Z = mput(env, Z, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_B = mput(env, B, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_C = mput(env, C, m*ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_D = mput(env, D, m*ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    ecc_voprf_ristretto255_sha512_ComputeComposites(
        ptr_M,
        ptr_Z,
        ptr_B,
        ptr_C,
        ptr_D,
        m,
        mode
    );
    mget(env, M, ptr_M, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mget(env, Z, ptr_Z, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_M, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_Z, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_B, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_C, m*ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_D, m*ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1voprf_1ristretto255_1sha512_1GenerateKeyPair(
    JNIEnv *env, jclass cls,
    jbyteArray skS,
    jbyteArray pkS
) {
    byte_t *ptr_skS = mput(env, skS, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    byte_t *ptr_pkS = mput(env, pkS, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    ecc_voprf_ristretto255_sha512_GenerateKeyPair(
        ptr_skS,
        ptr_pkS
    );
    mget(env, skS, ptr_skS, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    mget(env, pkS, ptr_pkS, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_skS, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_pkS, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
}

JNIEXPORT int JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1voprf_1ristretto255_1sha512_1DeriveKeyPair(
    JNIEnv *env, jclass cls,
    jbyteArray skS,
    jbyteArray pkS,
    jbyteArray seed,
    jbyteArray info,
    jint infoLen,
    jint mode
) {
    byte_t *ptr_skS = mput(env, skS, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    byte_t *ptr_pkS = mput(env, pkS, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_seed = mput(env, seed, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    byte_t *ptr_info = mput(env, info, infoLen);
    const int fun_ret = ecc_voprf_ristretto255_sha512_DeriveKeyPair(
        ptr_skS,
        ptr_pkS,
        ptr_seed,
        ptr_info,
        infoLen,
        mode
    );
    mget(env, skS, ptr_skS, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    mget(env, pkS, ptr_pkS, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_skS, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_pkS, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_seed, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_info, infoLen);
    return fun_ret;
}

JNIEXPORT int JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1voprf_1ristretto255_1sha512_1BlindWithScalar(
    JNIEnv *env, jclass cls,
    jbyteArray blindedElement,
    jbyteArray input,
    jint inputLen,
    jbyteArray blind,
    jint mode
) {
    byte_t *ptr_blindedElement = mput(env, blindedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_input = mput(env, input, inputLen);
    byte_t *ptr_blind = mput(env, blind, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    const int fun_ret = ecc_voprf_ristretto255_sha512_BlindWithScalar(
        ptr_blindedElement,
        ptr_input,
        inputLen,
        ptr_blind,
        mode
    );
    mget(env, blindedElement, ptr_blindedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_blindedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_input, inputLen);
    mfree(ptr_blind, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    return fun_ret;
}

JNIEXPORT int JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1voprf_1ristretto255_1sha512_1Blind(
    JNIEnv *env, jclass cls,
    jbyteArray blind,
    jbyteArray blindedElement,
    jbyteArray input,
    jint inputLen,
    jint mode
) {
    byte_t *ptr_blind = mput(env, blind, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    byte_t *ptr_blindedElement = mput(env, blindedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_input = mput(env, input, inputLen);
    const int fun_ret = ecc_voprf_ristretto255_sha512_Blind(
        ptr_blind,
        ptr_blindedElement,
        ptr_input,
        inputLen,
        mode
    );
    mget(env, blind, ptr_blind, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    mget(env, blindedElement, ptr_blindedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_blind, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_blindedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_input, inputLen);
    return fun_ret;
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1voprf_1ristretto255_1sha512_1BlindEvaluate(
    JNIEnv *env, jclass cls,
    jbyteArray evaluatedElement,
    jbyteArray skS,
    jbyteArray blindedElement
) {
    byte_t *ptr_evaluatedElement = mput(env, evaluatedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_skS = mput(env, skS, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    byte_t *ptr_blindedElement = mput(env, blindedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    ecc_voprf_ristretto255_sha512_BlindEvaluate(
        ptr_evaluatedElement,
        ptr_skS,
        ptr_blindedElement
    );
    mget(env, evaluatedElement, ptr_evaluatedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_evaluatedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_skS, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_blindedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1voprf_1ristretto255_1sha512_1Finalize(
    JNIEnv *env, jclass cls,
    jbyteArray output,
    jbyteArray input,
    jint inputLen,
    jbyteArray blind,
    jbyteArray evaluatedElement
) {
    byte_t *ptr_output = mput(env, output, ecc_voprf_ristretto255_sha512_Nh);
    byte_t *ptr_input = mput(env, input, inputLen);
    byte_t *ptr_blind = mput(env, blind, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    byte_t *ptr_evaluatedElement = mput(env, evaluatedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    ecc_voprf_ristretto255_sha512_Finalize(
        ptr_output,
        ptr_input,
        inputLen,
        ptr_blind,
        ptr_evaluatedElement
    );
    mget(env, output, ptr_output, ecc_voprf_ristretto255_sha512_Nh);
    mfree(ptr_output, ecc_voprf_ristretto255_sha512_Nh);
    mfree(ptr_input, inputLen);
    mfree(ptr_blind, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_evaluatedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
}

JNIEXPORT int JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1voprf_1ristretto255_1sha512_1Evaluate(
    JNIEnv *env, jclass cls,
    jbyteArray output,
    jbyteArray skS,
    jbyteArray input,
    jint inputLen,
    jint mode
) {
    byte_t *ptr_output = mput(env, output, ecc_voprf_ristretto255_sha512_Nh);
    byte_t *ptr_skS = mput(env, skS, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    byte_t *ptr_input = mput(env, input, inputLen);
    const int fun_ret = ecc_voprf_ristretto255_sha512_Evaluate(
        ptr_output,
        ptr_skS,
        ptr_input,
        inputLen,
        mode
    );
    mget(env, output, ptr_output, ecc_voprf_ristretto255_sha512_Nh);
    mfree(ptr_output, ecc_voprf_ristretto255_sha512_Nh);
    mfree(ptr_skS, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_input, inputLen);
    return fun_ret;
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1voprf_1ristretto255_1sha512_1VerifiableBlindEvaluateWithScalar(
    JNIEnv *env, jclass cls,
    jbyteArray evaluatedElement,
    jbyteArray proof,
    jbyteArray skS,
    jbyteArray pkS,
    jbyteArray blindedElement,
    jbyteArray r
) {
    byte_t *ptr_evaluatedElement = mput(env, evaluatedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_proof = mput(env, proof, ecc_voprf_ristretto255_sha512_PROOFSIZE);
    byte_t *ptr_skS = mput(env, skS, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    byte_t *ptr_pkS = mput(env, pkS, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_blindedElement = mput(env, blindedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_r = mput(env, r, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    ecc_voprf_ristretto255_sha512_VerifiableBlindEvaluateWithScalar(
        ptr_evaluatedElement,
        ptr_proof,
        ptr_skS,
        ptr_pkS,
        ptr_blindedElement,
        ptr_r
    );
    mget(env, evaluatedElement, ptr_evaluatedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mget(env, proof, ptr_proof, ecc_voprf_ristretto255_sha512_PROOFSIZE);
    mfree(ptr_evaluatedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_proof, ecc_voprf_ristretto255_sha512_PROOFSIZE);
    mfree(ptr_skS, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_pkS, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_blindedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_r, ecc_voprf_ristretto255_sha512_SCALARSIZE);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1voprf_1ristretto255_1sha512_1VerifiableBlindEvaluate(
    JNIEnv *env, jclass cls,
    jbyteArray evaluatedElement,
    jbyteArray proof,
    jbyteArray skS,
    jbyteArray pkS,
    jbyteArray blindedElement
) {
    byte_t *ptr_evaluatedElement = mput(env, evaluatedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_proof = mput(env, proof, ecc_voprf_ristretto255_sha512_PROOFSIZE);
    byte_t *ptr_skS = mput(env, skS, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    byte_t *ptr_pkS = mput(env, pkS, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_blindedElement = mput(env, blindedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    ecc_voprf_ristretto255_sha512_VerifiableBlindEvaluate(
        ptr_evaluatedElement,
        ptr_proof,
        ptr_skS,
        ptr_pkS,
        ptr_blindedElement
    );
    mget(env, evaluatedElement, ptr_evaluatedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mget(env, proof, ptr_proof, ecc_voprf_ristretto255_sha512_PROOFSIZE);
    mfree(ptr_evaluatedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_proof, ecc_voprf_ristretto255_sha512_PROOFSIZE);
    mfree(ptr_skS, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_pkS, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_blindedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
}

JNIEXPORT int JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1voprf_1ristretto255_1sha512_1VerifiableFinalize(
    JNIEnv *env, jclass cls,
    jbyteArray output,
    jbyteArray input,
    jint inputLen,
    jbyteArray blind,
    jbyteArray evaluatedElement,
    jbyteArray blindedElement,
    jbyteArray pkS,
    jbyteArray proof
) {
    byte_t *ptr_output = mput(env, output, ecc_voprf_ristretto255_sha512_Nh);
    byte_t *ptr_input = mput(env, input, inputLen);
    byte_t *ptr_blind = mput(env, blind, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    byte_t *ptr_evaluatedElement = mput(env, evaluatedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_blindedElement = mput(env, blindedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_pkS = mput(env, pkS, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_proof = mput(env, proof, ecc_voprf_ristretto255_sha512_PROOFSIZE);
    const int fun_ret = ecc_voprf_ristretto255_sha512_VerifiableFinalize(
        ptr_output,
        ptr_input,
        inputLen,
        ptr_blind,
        ptr_evaluatedElement,
        ptr_blindedElement,
        ptr_pkS,
        ptr_proof
    );
    mget(env, output, ptr_output, ecc_voprf_ristretto255_sha512_Nh);
    mfree(ptr_output, ecc_voprf_ristretto255_sha512_Nh);
    mfree(ptr_input, inputLen);
    mfree(ptr_blind, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_evaluatedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_blindedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_pkS, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_proof, ecc_voprf_ristretto255_sha512_PROOFSIZE);
    return fun_ret;
}

JNIEXPORT int JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1voprf_1ristretto255_1sha512_1PartiallyBlindWithScalar(
    JNIEnv *env, jclass cls,
    jbyteArray blindedElement,
    jbyteArray tweakedKey,
    jbyteArray input,
    jint inputLen,
    jbyteArray info,
    jint infoLen,
    jbyteArray pkS,
    jbyteArray blind
) {
    byte_t *ptr_blindedElement = mput(env, blindedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_tweakedKey = mput(env, tweakedKey, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_input = mput(env, input, inputLen);
    byte_t *ptr_info = mput(env, info, infoLen);
    byte_t *ptr_pkS = mput(env, pkS, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_blind = mput(env, blind, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    const int fun_ret = ecc_voprf_ristretto255_sha512_PartiallyBlindWithScalar(
        ptr_blindedElement,
        ptr_tweakedKey,
        ptr_input,
        inputLen,
        ptr_info,
        infoLen,
        ptr_pkS,
        ptr_blind
    );
    mget(env, blindedElement, ptr_blindedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mget(env, tweakedKey, ptr_tweakedKey, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_blindedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_tweakedKey, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_input, inputLen);
    mfree(ptr_info, infoLen);
    mfree(ptr_pkS, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_blind, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    return fun_ret;
}

JNIEXPORT int JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1voprf_1ristretto255_1sha512_1PartiallyBlind(
    JNIEnv *env, jclass cls,
    jbyteArray blind,
    jbyteArray blindedElement,
    jbyteArray tweakedKey,
    jbyteArray input,
    jint inputLen,
    jbyteArray info,
    jint infoLen,
    jbyteArray pkS
) {
    byte_t *ptr_blind = mput(env, blind, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    byte_t *ptr_blindedElement = mput(env, blindedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_tweakedKey = mput(env, tweakedKey, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_input = mput(env, input, inputLen);
    byte_t *ptr_info = mput(env, info, infoLen);
    byte_t *ptr_pkS = mput(env, pkS, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    const int fun_ret = ecc_voprf_ristretto255_sha512_PartiallyBlind(
        ptr_blind,
        ptr_blindedElement,
        ptr_tweakedKey,
        ptr_input,
        inputLen,
        ptr_info,
        infoLen,
        ptr_pkS
    );
    mget(env, blind, ptr_blind, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    mget(env, blindedElement, ptr_blindedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mget(env, tweakedKey, ptr_tweakedKey, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_blind, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_blindedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_tweakedKey, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_input, inputLen);
    mfree(ptr_info, infoLen);
    mfree(ptr_pkS, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    return fun_ret;
}

JNIEXPORT int JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1voprf_1ristretto255_1sha512_1PartiallyBlindEvaluateWithScalar(
    JNIEnv *env, jclass cls,
    jbyteArray evaluatedElement,
    jbyteArray proof,
    jbyteArray skS,
    jbyteArray blindedElement,
    jbyteArray info,
    jint infoLen,
    jbyteArray r
) {
    byte_t *ptr_evaluatedElement = mput(env, evaluatedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_proof = mput(env, proof, ecc_voprf_ristretto255_sha512_PROOFSIZE);
    byte_t *ptr_skS = mput(env, skS, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    byte_t *ptr_blindedElement = mput(env, blindedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_info = mput(env, info, infoLen);
    byte_t *ptr_r = mput(env, r, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    const int fun_ret = ecc_voprf_ristretto255_sha512_PartiallyBlindEvaluateWithScalar(
        ptr_evaluatedElement,
        ptr_proof,
        ptr_skS,
        ptr_blindedElement,
        ptr_info,
        infoLen,
        ptr_r
    );
    mget(env, evaluatedElement, ptr_evaluatedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mget(env, proof, ptr_proof, ecc_voprf_ristretto255_sha512_PROOFSIZE);
    mfree(ptr_evaluatedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_proof, ecc_voprf_ristretto255_sha512_PROOFSIZE);
    mfree(ptr_skS, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_blindedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_info, infoLen);
    mfree(ptr_r, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    return fun_ret;
}

JNIEXPORT int JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1voprf_1ristretto255_1sha512_1PartiallyBlindEvaluate(
    JNIEnv *env, jclass cls,
    jbyteArray evaluatedElement,
    jbyteArray proof,
    jbyteArray skS,
    jbyteArray blindedElement,
    jbyteArray info,
    jint infoLen
) {
    byte_t *ptr_evaluatedElement = mput(env, evaluatedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_proof = mput(env, proof, ecc_voprf_ristretto255_sha512_PROOFSIZE);
    byte_t *ptr_skS = mput(env, skS, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    byte_t *ptr_blindedElement = mput(env, blindedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_info = mput(env, info, infoLen);
    const int fun_ret = ecc_voprf_ristretto255_sha512_PartiallyBlindEvaluate(
        ptr_evaluatedElement,
        ptr_proof,
        ptr_skS,
        ptr_blindedElement,
        ptr_info,
        infoLen
    );
    mget(env, evaluatedElement, ptr_evaluatedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mget(env, proof, ptr_proof, ecc_voprf_ristretto255_sha512_PROOFSIZE);
    mfree(ptr_evaluatedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_proof, ecc_voprf_ristretto255_sha512_PROOFSIZE);
    mfree(ptr_skS, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_blindedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_info, infoLen);
    return fun_ret;
}

JNIEXPORT int JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1voprf_1ristretto255_1sha512_1PartiallyFinalize(
    JNIEnv *env, jclass cls,
    jbyteArray output,
    jbyteArray input,
    jint inputLen,
    jbyteArray blind,
    jbyteArray evaluatedElement,
    jbyteArray blindedElement,
    jbyteArray proof,
    jbyteArray info,
    jint infoLen,
    jbyteArray tweakedKey
) {
    byte_t *ptr_output = mput(env, output, ecc_voprf_ristretto255_sha512_Nh);
    byte_t *ptr_input = mput(env, input, inputLen);
    byte_t *ptr_blind = mput(env, blind, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    byte_t *ptr_evaluatedElement = mput(env, evaluatedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_blindedElement = mput(env, blindedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_proof = mput(env, proof, ecc_voprf_ristretto255_sha512_PROOFSIZE);
    byte_t *ptr_info = mput(env, info, infoLen);
    byte_t *ptr_tweakedKey = mput(env, tweakedKey, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    const int fun_ret = ecc_voprf_ristretto255_sha512_PartiallyFinalize(
        ptr_output,
        ptr_input,
        inputLen,
        ptr_blind,
        ptr_evaluatedElement,
        ptr_blindedElement,
        ptr_proof,
        ptr_info,
        infoLen,
        ptr_tweakedKey
    );
    mget(env, output, ptr_output, ecc_voprf_ristretto255_sha512_Nh);
    mfree(ptr_output, ecc_voprf_ristretto255_sha512_Nh);
    mfree(ptr_input, inputLen);
    mfree(ptr_blind, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_evaluatedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_blindedElement, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_proof, ecc_voprf_ristretto255_sha512_PROOFSIZE);
    mfree(ptr_info, infoLen);
    mfree(ptr_tweakedKey, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    return fun_ret;
}

JNIEXPORT int JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1voprf_1ristretto255_1sha512_1PartiallyEvaluate(
    JNIEnv *env, jclass cls,
    jbyteArray output,
    jbyteArray skS,
    jbyteArray input,
    jint inputLen,
    jbyteArray info,
    jint infoLen
) {
    byte_t *ptr_output = mput(env, output, ecc_voprf_ristretto255_sha512_Nh);
    byte_t *ptr_skS = mput(env, skS, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    byte_t *ptr_input = mput(env, input, inputLen);
    byte_t *ptr_info = mput(env, info, infoLen);
    const int fun_ret = ecc_voprf_ristretto255_sha512_PartiallyEvaluate(
        ptr_output,
        ptr_skS,
        ptr_input,
        inputLen,
        ptr_info,
        infoLen
    );
    mget(env, output, ptr_output, ecc_voprf_ristretto255_sha512_Nh);
    mfree(ptr_output, ecc_voprf_ristretto255_sha512_Nh);
    mfree(ptr_skS, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_input, inputLen);
    mfree(ptr_info, infoLen);
    return fun_ret;
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1voprf_1ristretto255_1sha512_1HashToGroupWithDST(
    JNIEnv *env, jclass cls,
    jbyteArray out,
    jbyteArray input,
    jint inputLen,
    jbyteArray dst,
    jint dstLen
) {
    byte_t *ptr_out = mput(env, out, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_input = mput(env, input, inputLen);
    byte_t *ptr_dst = mput(env, dst, dstLen);
    ecc_voprf_ristretto255_sha512_HashToGroupWithDST(
        ptr_out,
        ptr_input,
        inputLen,
        ptr_dst,
        dstLen
    );
    mget(env, out, ptr_out, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_out, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_input, inputLen);
    mfree(ptr_dst, dstLen);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1voprf_1ristretto255_1sha512_1HashToGroup(
    JNIEnv *env, jclass cls,
    jbyteArray out,
    jbyteArray input,
    jint inputLen,
    jint mode
) {
    byte_t *ptr_out = mput(env, out, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_input = mput(env, input, inputLen);
    ecc_voprf_ristretto255_sha512_HashToGroup(
        ptr_out,
        ptr_input,
        inputLen,
        mode
    );
    mget(env, out, ptr_out, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_out, ecc_voprf_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_input, inputLen);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1voprf_1ristretto255_1sha512_1HashToScalarWithDST(
    JNIEnv *env, jclass cls,
    jbyteArray out,
    jbyteArray input,
    jint inputLen,
    jbyteArray dst,
    jint dstLen
) {
    byte_t *ptr_out = mput(env, out, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    byte_t *ptr_input = mput(env, input, inputLen);
    byte_t *ptr_dst = mput(env, dst, dstLen);
    ecc_voprf_ristretto255_sha512_HashToScalarWithDST(
        ptr_out,
        ptr_input,
        inputLen,
        ptr_dst,
        dstLen
    );
    mget(env, out, ptr_out, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_out, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_input, inputLen);
    mfree(ptr_dst, dstLen);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1voprf_1ristretto255_1sha512_1HashToScalar(
    JNIEnv *env, jclass cls,
    jbyteArray out,
    jbyteArray input,
    jint inputLen,
    jint mode
) {
    byte_t *ptr_out = mput(env, out, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    byte_t *ptr_input = mput(env, input, inputLen);
    ecc_voprf_ristretto255_sha512_HashToScalar(
        ptr_out,
        ptr_input,
        inputLen,
        mode
    );
    mget(env, out, ptr_out, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_out, ecc_voprf_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_input, inputLen);
}

// opaque

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1opaque_1ristretto255_1sha512_1DeriveKeyPair(
    JNIEnv *env, jclass cls,
    jbyteArray private_key,
    jbyteArray public_key,
    jbyteArray seed
) {
    byte_t *ptr_private_key = mput(env, private_key, ecc_opaque_ristretto255_sha512_Nsk);
    byte_t *ptr_public_key = mput(env, public_key, ecc_opaque_ristretto255_sha512_Npk);
    byte_t *ptr_seed = mput(env, seed, ecc_opaque_ristretto255_sha512_Nok);
    ecc_opaque_ristretto255_sha512_DeriveKeyPair(
        ptr_private_key,
        ptr_public_key,
        ptr_seed
    );
    mget(env, private_key, ptr_private_key, ecc_opaque_ristretto255_sha512_Nsk);
    mget(env, public_key, ptr_public_key, ecc_opaque_ristretto255_sha512_Npk);
    mfree(ptr_private_key, ecc_opaque_ristretto255_sha512_Nsk);
    mfree(ptr_public_key, ecc_opaque_ristretto255_sha512_Npk);
    mfree(ptr_seed, ecc_opaque_ristretto255_sha512_Nok);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1opaque_1ristretto255_1sha512_1CreateCleartextCredentials(
    JNIEnv *env, jclass cls,
    jbyteArray cleartext_credentials,
    jbyteArray server_public_key,
    jbyteArray client_public_key,
    jbyteArray server_identity,
    jint server_identity_len,
    jbyteArray client_identity,
    jint client_identity_len
) {
    byte_t *ptr_cleartext_credentials = mput(env, cleartext_credentials, ecc_opaque_ristretto255_sha512_CLEARTEXTCREDENTIALSSIZE);
    byte_t *ptr_server_public_key = mput(env, server_public_key, ecc_opaque_ristretto255_sha512_Npk);
    byte_t *ptr_client_public_key = mput(env, client_public_key, ecc_opaque_ristretto255_sha512_Npk);
    byte_t *ptr_server_identity = mput(env, server_identity, server_identity_len);
    byte_t *ptr_client_identity = mput(env, client_identity, client_identity_len);
    ecc_opaque_ristretto255_sha512_CreateCleartextCredentials(
        ptr_cleartext_credentials,
        ptr_server_public_key,
        ptr_client_public_key,
        ptr_server_identity,
        server_identity_len,
        ptr_client_identity,
        client_identity_len
    );
    mget(env, cleartext_credentials, ptr_cleartext_credentials, ecc_opaque_ristretto255_sha512_CLEARTEXTCREDENTIALSSIZE);
    mfree(ptr_cleartext_credentials, ecc_opaque_ristretto255_sha512_CLEARTEXTCREDENTIALSSIZE);
    mfree(ptr_server_public_key, ecc_opaque_ristretto255_sha512_Npk);
    mfree(ptr_client_public_key, ecc_opaque_ristretto255_sha512_Npk);
    mfree(ptr_server_identity, server_identity_len);
    mfree(ptr_client_identity, client_identity_len);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1opaque_1ristretto255_1sha512_1EnvelopeStoreWithNonce(
    JNIEnv *env, jclass cls,
    jbyteArray envelope,
    jbyteArray client_public_key,
    jbyteArray masking_key,
    jbyteArray export_key,
    jbyteArray randomized_pwd,
    jbyteArray server_public_key,
    jbyteArray server_identity,
    jint server_identity_len,
    jbyteArray client_identity,
    jint client_identity_len,
    jbyteArray nonce
) {
    byte_t *ptr_envelope = mput(env, envelope, ecc_opaque_ristretto255_sha512_Ne);
    byte_t *ptr_client_public_key = mput(env, client_public_key, ecc_opaque_ristretto255_sha512_Npk);
    byte_t *ptr_masking_key = mput(env, masking_key, ecc_opaque_ristretto255_sha512_Nh);
    byte_t *ptr_export_key = mput(env, export_key, ecc_opaque_ristretto255_sha512_Nh);
    byte_t *ptr_randomized_pwd = mput(env, randomized_pwd, 64);
    byte_t *ptr_server_public_key = mput(env, server_public_key, ecc_opaque_ristretto255_sha512_Npk);
    byte_t *ptr_server_identity = mput(env, server_identity, server_identity_len);
    byte_t *ptr_client_identity = mput(env, client_identity, client_identity_len);
    byte_t *ptr_nonce = mput(env, nonce, ecc_opaque_ristretto255_sha512_Nn);
    ecc_opaque_ristretto255_sha512_EnvelopeStoreWithNonce(
        ptr_envelope,
        ptr_client_public_key,
        ptr_masking_key,
        ptr_export_key,
        ptr_randomized_pwd,
        ptr_server_public_key,
        ptr_server_identity,
        server_identity_len,
        ptr_client_identity,
        client_identity_len,
        ptr_nonce
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
    mfree(ptr_server_identity, server_identity_len);
    mfree(ptr_client_identity, client_identity_len);
    mfree(ptr_nonce, ecc_opaque_ristretto255_sha512_Nn);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1opaque_1ristretto255_1sha512_1EnvelopeStore(
    JNIEnv *env, jclass cls,
    jbyteArray envelope,
    jbyteArray client_public_key,
    jbyteArray masking_key,
    jbyteArray export_key,
    jbyteArray randomized_pwd,
    jbyteArray server_public_key,
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
    byte_t *ptr_server_identity = mput(env, server_identity, server_identity_len);
    byte_t *ptr_client_identity = mput(env, client_identity, client_identity_len);
    ecc_opaque_ristretto255_sha512_EnvelopeStore(
        ptr_envelope,
        ptr_client_public_key,
        ptr_masking_key,
        ptr_export_key,
        ptr_randomized_pwd,
        ptr_server_public_key,
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
    mfree(ptr_server_identity, server_identity_len);
    mfree(ptr_client_identity, client_identity_len);
}

JNIEXPORT int JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1opaque_1ristretto255_1sha512_1EnvelopeRecover(
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
    const int fun_ret = ecc_opaque_ristretto255_sha512_EnvelopeRecover(
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
    jbyteArray seed
) {
    byte_t *ptr_private_key = mput(env, private_key, ecc_opaque_ristretto255_sha512_Nsk);
    byte_t *ptr_public_key = mput(env, public_key, ecc_opaque_ristretto255_sha512_Npk);
    byte_t *ptr_seed = mput(env, seed, ecc_opaque_ristretto255_sha512_Nok);
    ecc_opaque_ristretto255_sha512_DeriveAuthKeyPair(
        ptr_private_key,
        ptr_public_key,
        ptr_seed
    );
    mget(env, private_key, ptr_private_key, ecc_opaque_ristretto255_sha512_Nsk);
    mget(env, public_key, ptr_public_key, ecc_opaque_ristretto255_sha512_Npk);
    mfree(ptr_private_key, ecc_opaque_ristretto255_sha512_Nsk);
    mfree(ptr_public_key, ecc_opaque_ristretto255_sha512_Npk);
    mfree(ptr_seed, ecc_opaque_ristretto255_sha512_Nok);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1opaque_1ristretto255_1sha512_1CreateRegistrationRequestWithBlind(
    JNIEnv *env, jclass cls,
    jbyteArray request,
    jbyteArray password,
    jint password_len,
    jbyteArray blind
) {
    byte_t *ptr_request = mput(env, request, ecc_opaque_ristretto255_sha512_REGISTRATIONREQUESTSIZE);
    byte_t *ptr_password = mput(env, password, password_len);
    byte_t *ptr_blind = mput(env, blind, ecc_opaque_ristretto255_sha512_Noe);
    ecc_opaque_ristretto255_sha512_CreateRegistrationRequestWithBlind(
        ptr_request,
        ptr_password,
        password_len,
        ptr_blind
    );
    mget(env, request, ptr_request, ecc_opaque_ristretto255_sha512_REGISTRATIONREQUESTSIZE);
    mfree(ptr_request, ecc_opaque_ristretto255_sha512_REGISTRATIONREQUESTSIZE);
    mfree(ptr_password, password_len);
    mfree(ptr_blind, ecc_opaque_ristretto255_sha512_Noe);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1opaque_1ristretto255_1sha512_1CreateRegistrationRequest(
    JNIEnv *env, jclass cls,
    jbyteArray request,
    jbyteArray blind,
    jbyteArray password,
    jint password_len
) {
    byte_t *ptr_request = mput(env, request, ecc_opaque_ristretto255_sha512_REGISTRATIONREQUESTSIZE);
    byte_t *ptr_blind = mput(env, blind, ecc_opaque_ristretto255_sha512_Noe);
    byte_t *ptr_password = mput(env, password, password_len);
    ecc_opaque_ristretto255_sha512_CreateRegistrationRequest(
        ptr_request,
        ptr_blind,
        ptr_password,
        password_len
    );
    mget(env, request, ptr_request, ecc_opaque_ristretto255_sha512_REGISTRATIONREQUESTSIZE);
    mget(env, blind, ptr_blind, ecc_opaque_ristretto255_sha512_Noe);
    mfree(ptr_request, ecc_opaque_ristretto255_sha512_REGISTRATIONREQUESTSIZE);
    mfree(ptr_blind, ecc_opaque_ristretto255_sha512_Noe);
    mfree(ptr_password, password_len);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1opaque_1ristretto255_1sha512_1CreateRegistrationResponseWithOprfKey(
    JNIEnv *env, jclass cls,
    jbyteArray response,
    jbyteArray request,
    jbyteArray server_public_key,
    jbyteArray credential_identifier,
    jint credential_identifier_len,
    jbyteArray oprf_key
) {
    byte_t *ptr_response = mput(env, response, ecc_opaque_ristretto255_sha512_REGISTRATIONRESPONSESIZE);
    byte_t *ptr_request = mput(env, request, ecc_opaque_ristretto255_sha512_REGISTRATIONREQUESTSIZE);
    byte_t *ptr_server_public_key = mput(env, server_public_key, ecc_opaque_ristretto255_sha512_Npk);
    byte_t *ptr_credential_identifier = mput(env, credential_identifier, credential_identifier_len);
    byte_t *ptr_oprf_key = mput(env, oprf_key, 32);
    ecc_opaque_ristretto255_sha512_CreateRegistrationResponseWithOprfKey(
        ptr_response,
        ptr_request,
        ptr_server_public_key,
        ptr_credential_identifier,
        credential_identifier_len,
        ptr_oprf_key
    );
    mget(env, response, ptr_response, ecc_opaque_ristretto255_sha512_REGISTRATIONRESPONSESIZE);
    mfree(ptr_response, ecc_opaque_ristretto255_sha512_REGISTRATIONRESPONSESIZE);
    mfree(ptr_request, ecc_opaque_ristretto255_sha512_REGISTRATIONREQUESTSIZE);
    mfree(ptr_server_public_key, ecc_opaque_ristretto255_sha512_Npk);
    mfree(ptr_credential_identifier, credential_identifier_len);
    mfree(ptr_oprf_key, 32);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1opaque_1ristretto255_1sha512_1CreateRegistrationResponse(
    JNIEnv *env, jclass cls,
    jbyteArray response,
    jbyteArray oprf_key,
    jbyteArray request,
    jbyteArray server_public_key,
    jbyteArray credential_identifier,
    jint credential_identifier_len,
    jbyteArray oprf_seed
) {
    byte_t *ptr_response = mput(env, response, ecc_opaque_ristretto255_sha512_REGISTRATIONRESPONSESIZE);
    byte_t *ptr_oprf_key = mput(env, oprf_key, ecc_opaque_ristretto255_sha512_Nsk);
    byte_t *ptr_request = mput(env, request, ecc_opaque_ristretto255_sha512_REGISTRATIONREQUESTSIZE);
    byte_t *ptr_server_public_key = mput(env, server_public_key, ecc_opaque_ristretto255_sha512_Npk);
    byte_t *ptr_credential_identifier = mput(env, credential_identifier, credential_identifier_len);
    byte_t *ptr_oprf_seed = mput(env, oprf_seed, ecc_opaque_ristretto255_sha512_Nh);
    ecc_opaque_ristretto255_sha512_CreateRegistrationResponse(
        ptr_response,
        ptr_oprf_key,
        ptr_request,
        ptr_server_public_key,
        ptr_credential_identifier,
        credential_identifier_len,
        ptr_oprf_seed
    );
    mget(env, response, ptr_response, ecc_opaque_ristretto255_sha512_REGISTRATIONRESPONSESIZE);
    mget(env, oprf_key, ptr_oprf_key, ecc_opaque_ristretto255_sha512_Nsk);
    mfree(ptr_response, ecc_opaque_ristretto255_sha512_REGISTRATIONRESPONSESIZE);
    mfree(ptr_oprf_key, ecc_opaque_ristretto255_sha512_Nsk);
    mfree(ptr_request, ecc_opaque_ristretto255_sha512_REGISTRATIONREQUESTSIZE);
    mfree(ptr_server_public_key, ecc_opaque_ristretto255_sha512_Npk);
    mfree(ptr_credential_identifier, credential_identifier_len);
    mfree(ptr_oprf_seed, ecc_opaque_ristretto255_sha512_Nh);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1opaque_1ristretto255_1sha512_1FinalizeRequestWithNonce(
    JNIEnv *env, jclass cls,
    jbyteArray record,
    jbyteArray export_key,
    jbyteArray password,
    jint password_len,
    jbyteArray blind,
    jbyteArray response,
    jbyteArray server_identity,
    jint server_identity_len,
    jbyteArray client_identity,
    jint client_identity_len,
    jint mhf,
    jbyteArray nonce
) {
    byte_t *ptr_record = mput(env, record, ecc_opaque_ristretto255_sha512_REGISTRATIONUPLOADSIZE);
    byte_t *ptr_export_key = mput(env, export_key, ecc_opaque_ristretto255_sha512_Nh);
    byte_t *ptr_password = mput(env, password, password_len);
    byte_t *ptr_blind = mput(env, blind, ecc_opaque_ristretto255_sha512_Noe);
    byte_t *ptr_response = mput(env, response, ecc_opaque_ristretto255_sha512_REGISTRATIONRESPONSESIZE);
    byte_t *ptr_server_identity = mput(env, server_identity, server_identity_len);
    byte_t *ptr_client_identity = mput(env, client_identity, client_identity_len);
    byte_t *ptr_nonce = mput(env, nonce, ecc_opaque_ristretto255_sha512_Nn);
    ecc_opaque_ristretto255_sha512_FinalizeRequestWithNonce(
        ptr_record,
        ptr_export_key,
        ptr_password,
        password_len,
        ptr_blind,
        ptr_response,
        ptr_server_identity,
        server_identity_len,
        ptr_client_identity,
        client_identity_len,
        mhf,
        ptr_nonce
    );
    mget(env, record, ptr_record, ecc_opaque_ristretto255_sha512_REGISTRATIONUPLOADSIZE);
    mget(env, export_key, ptr_export_key, ecc_opaque_ristretto255_sha512_Nh);
    mfree(ptr_record, ecc_opaque_ristretto255_sha512_REGISTRATIONUPLOADSIZE);
    mfree(ptr_export_key, ecc_opaque_ristretto255_sha512_Nh);
    mfree(ptr_password, password_len);
    mfree(ptr_blind, ecc_opaque_ristretto255_sha512_Noe);
    mfree(ptr_response, ecc_opaque_ristretto255_sha512_REGISTRATIONRESPONSESIZE);
    mfree(ptr_server_identity, server_identity_len);
    mfree(ptr_client_identity, client_identity_len);
    mfree(ptr_nonce, ecc_opaque_ristretto255_sha512_Nn);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1opaque_1ristretto255_1sha512_1FinalizeRequest(
    JNIEnv *env, jclass cls,
    jbyteArray record,
    jbyteArray export_key,
    jbyteArray password,
    jint password_len,
    jbyteArray blind,
    jbyteArray response,
    jbyteArray server_identity,
    jint server_identity_len,
    jbyteArray client_identity,
    jint client_identity_len,
    jint mhf
) {
    byte_t *ptr_record = mput(env, record, ecc_opaque_ristretto255_sha512_REGISTRATIONUPLOADSIZE);
    byte_t *ptr_export_key = mput(env, export_key, ecc_opaque_ristretto255_sha512_Nh);
    byte_t *ptr_password = mput(env, password, password_len);
    byte_t *ptr_blind = mput(env, blind, ecc_opaque_ristretto255_sha512_Noe);
    byte_t *ptr_response = mput(env, response, ecc_opaque_ristretto255_sha512_REGISTRATIONRESPONSESIZE);
    byte_t *ptr_server_identity = mput(env, server_identity, server_identity_len);
    byte_t *ptr_client_identity = mput(env, client_identity, client_identity_len);
    ecc_opaque_ristretto255_sha512_FinalizeRequest(
        ptr_record,
        ptr_export_key,
        ptr_password,
        password_len,
        ptr_blind,
        ptr_response,
        ptr_server_identity,
        server_identity_len,
        ptr_client_identity,
        client_identity_len,
        mhf
    );
    mget(env, record, ptr_record, ecc_opaque_ristretto255_sha512_REGISTRATIONUPLOADSIZE);
    mget(env, export_key, ptr_export_key, ecc_opaque_ristretto255_sha512_Nh);
    mfree(ptr_record, ecc_opaque_ristretto255_sha512_REGISTRATIONUPLOADSIZE);
    mfree(ptr_export_key, ecc_opaque_ristretto255_sha512_Nh);
    mfree(ptr_password, password_len);
    mfree(ptr_blind, ecc_opaque_ristretto255_sha512_Noe);
    mfree(ptr_response, ecc_opaque_ristretto255_sha512_REGISTRATIONRESPONSESIZE);
    mfree(ptr_server_identity, server_identity_len);
    mfree(ptr_client_identity, client_identity_len);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1opaque_1ristretto255_1sha512_1CreateCredentialRequestWithBlind(
    JNIEnv *env, jclass cls,
    jbyteArray request,
    jbyteArray password,
    jint password_len,
    jbyteArray blind
) {
    byte_t *ptr_request = mput(env, request, ecc_opaque_ristretto255_sha512_CREDENTIALREQUESTSIZE);
    byte_t *ptr_password = mput(env, password, password_len);
    byte_t *ptr_blind = mput(env, blind, ecc_opaque_ristretto255_sha512_Noe);
    ecc_opaque_ristretto255_sha512_CreateCredentialRequestWithBlind(
        ptr_request,
        ptr_password,
        password_len,
        ptr_blind
    );
    mget(env, request, ptr_request, ecc_opaque_ristretto255_sha512_CREDENTIALREQUESTSIZE);
    mfree(ptr_request, ecc_opaque_ristretto255_sha512_CREDENTIALREQUESTSIZE);
    mfree(ptr_password, password_len);
    mfree(ptr_blind, ecc_opaque_ristretto255_sha512_Noe);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1opaque_1ristretto255_1sha512_1CreateCredentialRequest(
    JNIEnv *env, jclass cls,
    jbyteArray request,
    jbyteArray blind,
    jbyteArray password,
    jint password_len
) {
    byte_t *ptr_request = mput(env, request, ecc_opaque_ristretto255_sha512_CREDENTIALREQUESTSIZE);
    byte_t *ptr_blind = mput(env, blind, ecc_opaque_ristretto255_sha512_Noe);
    byte_t *ptr_password = mput(env, password, password_len);
    ecc_opaque_ristretto255_sha512_CreateCredentialRequest(
        ptr_request,
        ptr_blind,
        ptr_password,
        password_len
    );
    mget(env, request, ptr_request, ecc_opaque_ristretto255_sha512_CREDENTIALREQUESTSIZE);
    mget(env, blind, ptr_blind, ecc_opaque_ristretto255_sha512_Noe);
    mfree(ptr_request, ecc_opaque_ristretto255_sha512_CREDENTIALREQUESTSIZE);
    mfree(ptr_blind, ecc_opaque_ristretto255_sha512_Noe);
    mfree(ptr_password, password_len);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1opaque_1ristretto255_1sha512_1CreateCredentialResponseWithMasking(
    JNIEnv *env, jclass cls,
    jbyteArray response_raw,
    jbyteArray request_raw,
    jbyteArray server_public_key,
    jbyteArray record_raw,
    jbyteArray credential_identifier,
    jint credential_identifier_len,
    jbyteArray oprf_seed,
    jbyteArray masking_nonce
) {
    byte_t *ptr_response_raw = mput(env, response_raw, ecc_opaque_ristretto255_sha512_CREDENTIALRESPONSESIZE);
    byte_t *ptr_request_raw = mput(env, request_raw, ecc_opaque_ristretto255_sha512_CREDENTIALREQUESTSIZE);
    byte_t *ptr_server_public_key = mput(env, server_public_key, ecc_opaque_ristretto255_sha512_Npk);
    byte_t *ptr_record_raw = mput(env, record_raw, ecc_opaque_ristretto255_sha512_REGISTRATIONUPLOADSIZE);
    byte_t *ptr_credential_identifier = mput(env, credential_identifier, credential_identifier_len);
    byte_t *ptr_oprf_seed = mput(env, oprf_seed, ecc_opaque_ristretto255_sha512_Nh);
    byte_t *ptr_masking_nonce = mput(env, masking_nonce, ecc_opaque_ristretto255_sha512_Nn);
    ecc_opaque_ristretto255_sha512_CreateCredentialResponseWithMasking(
        ptr_response_raw,
        ptr_request_raw,
        ptr_server_public_key,
        ptr_record_raw,
        ptr_credential_identifier,
        credential_identifier_len,
        ptr_oprf_seed,
        ptr_masking_nonce
    );
    mget(env, response_raw, ptr_response_raw, ecc_opaque_ristretto255_sha512_CREDENTIALRESPONSESIZE);
    mfree(ptr_response_raw, ecc_opaque_ristretto255_sha512_CREDENTIALRESPONSESIZE);
    mfree(ptr_request_raw, ecc_opaque_ristretto255_sha512_CREDENTIALREQUESTSIZE);
    mfree(ptr_server_public_key, ecc_opaque_ristretto255_sha512_Npk);
    mfree(ptr_record_raw, ecc_opaque_ristretto255_sha512_REGISTRATIONUPLOADSIZE);
    mfree(ptr_credential_identifier, credential_identifier_len);
    mfree(ptr_oprf_seed, ecc_opaque_ristretto255_sha512_Nh);
    mfree(ptr_masking_nonce, ecc_opaque_ristretto255_sha512_Nn);
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
    jint client_identity_len,
    jint mhf
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
        client_identity_len,
        mhf
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
    jbyteArray client_public_key,
    jbyteArray ke1,
    jbyteArray server_identity,
    jint server_identity_len,
    jbyteArray server_public_key,
    jbyteArray ke2
) {
    byte_t *ptr_preamble = mput(env, preamble, preamble_len);
    byte_t *ptr_context = mput(env, context, context_len);
    byte_t *ptr_client_identity = mput(env, client_identity, client_identity_len);
    byte_t *ptr_client_public_key = mput(env, client_public_key, ecc_opaque_ristretto255_sha512_Npk);
    byte_t *ptr_ke1 = mput(env, ke1, ecc_opaque_ristretto255_sha512_KE1SIZE);
    byte_t *ptr_server_identity = mput(env, server_identity, server_identity_len);
    byte_t *ptr_server_public_key = mput(env, server_public_key, ecc_opaque_ristretto255_sha512_Npk);
    byte_t *ptr_ke2 = mput(env, ke2, ecc_opaque_ristretto255_sha512_KE2SIZE);
    const int fun_ret = ecc_opaque_ristretto255_sha512_3DH_Preamble(
        ptr_preamble,
        preamble_len,
        ptr_context,
        context_len,
        ptr_client_identity,
        client_identity_len,
        ptr_client_public_key,
        ptr_ke1,
        ptr_server_identity,
        server_identity_len,
        ptr_server_public_key,
        ptr_ke2
    );
    mget(env, preamble, ptr_preamble, preamble_len);
    mfree(ptr_preamble, preamble_len);
    mfree(ptr_context, context_len);
    mfree(ptr_client_identity, client_identity_len);
    mfree(ptr_client_public_key, ecc_opaque_ristretto255_sha512_Npk);
    mfree(ptr_ke1, ecc_opaque_ristretto255_sha512_KE1SIZE);
    mfree(ptr_server_identity, server_identity_len);
    mfree(ptr_server_public_key, ecc_opaque_ristretto255_sha512_Npk);
    mfree(ptr_ke2, ecc_opaque_ristretto255_sha512_KE2SIZE);
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

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1opaque_1ristretto255_1sha512_13DH_1ClientInitWithSecrets(
    JNIEnv *env, jclass cls,
    jbyteArray ke1,
    jbyteArray state,
    jbyteArray password,
    jint password_len,
    jbyteArray blind,
    jbyteArray client_nonce,
    jbyteArray client_secret,
    jbyteArray client_keyshare
) {
    byte_t *ptr_ke1 = mput(env, ke1, ecc_opaque_ristretto255_sha512_KE1SIZE);
    byte_t *ptr_state = mput(env, state, ecc_opaque_ristretto255_sha512_CLIENTSTATESIZE);
    byte_t *ptr_password = mput(env, password, password_len);
    byte_t *ptr_blind = mput(env, blind, ecc_opaque_ristretto255_sha512_Noe);
    byte_t *ptr_client_nonce = mput(env, client_nonce, ecc_opaque_ristretto255_sha512_Nn);
    byte_t *ptr_client_secret = mput(env, client_secret, ecc_opaque_ristretto255_sha512_Nsk);
    byte_t *ptr_client_keyshare = mput(env, client_keyshare, ecc_opaque_ristretto255_sha512_Npk);
    ecc_opaque_ristretto255_sha512_3DH_ClientInitWithSecrets(
        ptr_ke1,
        ptr_state,
        ptr_password,
        password_len,
        ptr_blind,
        ptr_client_nonce,
        ptr_client_secret,
        ptr_client_keyshare
    );
    mget(env, ke1, ptr_ke1, ecc_opaque_ristretto255_sha512_KE1SIZE);
    mget(env, state, ptr_state, ecc_opaque_ristretto255_sha512_CLIENTSTATESIZE);
    mfree(ptr_ke1, ecc_opaque_ristretto255_sha512_KE1SIZE);
    mfree(ptr_state, ecc_opaque_ristretto255_sha512_CLIENTSTATESIZE);
    mfree(ptr_password, password_len);
    mfree(ptr_blind, ecc_opaque_ristretto255_sha512_Noe);
    mfree(ptr_client_nonce, ecc_opaque_ristretto255_sha512_Nn);
    mfree(ptr_client_secret, ecc_opaque_ristretto255_sha512_Nsk);
    mfree(ptr_client_keyshare, ecc_opaque_ristretto255_sha512_Npk);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1opaque_1ristretto255_1sha512_13DH_1ClientInit(
    JNIEnv *env, jclass cls,
    jbyteArray ke1,
    jbyteArray state,
    jbyteArray password,
    jint password_len
) {
    byte_t *ptr_ke1 = mput(env, ke1, ecc_opaque_ristretto255_sha512_KE1SIZE);
    byte_t *ptr_state = mput(env, state, ecc_opaque_ristretto255_sha512_CLIENTSTATESIZE);
    byte_t *ptr_password = mput(env, password, password_len);
    ecc_opaque_ristretto255_sha512_3DH_ClientInit(
        ptr_ke1,
        ptr_state,
        ptr_password,
        password_len
    );
    mget(env, ke1, ptr_ke1, ecc_opaque_ristretto255_sha512_KE1SIZE);
    mget(env, state, ptr_state, ecc_opaque_ristretto255_sha512_CLIENTSTATESIZE);
    mfree(ptr_ke1, ecc_opaque_ristretto255_sha512_KE1SIZE);
    mfree(ptr_state, ecc_opaque_ristretto255_sha512_CLIENTSTATESIZE);
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
    jbyteArray ke2,
    jint mhf,
    jbyteArray context,
    jint context_len
) {
    byte_t *ptr_ke3_raw = mput(env, ke3_raw, ecc_opaque_ristretto255_sha512_KE3SIZE);
    byte_t *ptr_session_key = mput(env, session_key, 64);
    byte_t *ptr_export_key = mput(env, export_key, 64);
    byte_t *ptr_state_raw = mput(env, state_raw, ecc_opaque_ristretto255_sha512_CLIENTSTATESIZE);
    byte_t *ptr_password = mput(env, password, password_len);
    byte_t *ptr_client_identity = mput(env, client_identity, client_identity_len);
    byte_t *ptr_server_identity = mput(env, server_identity, server_identity_len);
    byte_t *ptr_ke2 = mput(env, ke2, ecc_opaque_ristretto255_sha512_KE2SIZE);
    byte_t *ptr_context = mput(env, context, context_len);
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
        ptr_ke2,
        mhf,
        ptr_context,
        context_len
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
    mfree(ptr_ke2, ecc_opaque_ristretto255_sha512_KE2SIZE);
    mfree(ptr_context, context_len);
    return fun_ret;
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1opaque_1ristretto255_1sha512_13DH_1StartWithSecrets(
    JNIEnv *env, jclass cls,
    jbyteArray ke1,
    jbyteArray state,
    jbyteArray credential_request,
    jbyteArray client_nonce,
    jbyteArray client_secret,
    jbyteArray client_keyshare
) {
    byte_t *ptr_ke1 = mput(env, ke1, ecc_opaque_ristretto255_sha512_KE1SIZE);
    byte_t *ptr_state = mput(env, state, ecc_opaque_ristretto255_sha512_CLIENTSTATESIZE);
    byte_t *ptr_credential_request = mput(env, credential_request, ecc_opaque_ristretto255_sha512_CREDENTIALREQUESTSIZE);
    byte_t *ptr_client_nonce = mput(env, client_nonce, ecc_opaque_ristretto255_sha512_Nn);
    byte_t *ptr_client_secret = mput(env, client_secret, ecc_opaque_ristretto255_sha512_Nsk);
    byte_t *ptr_client_keyshare = mput(env, client_keyshare, ecc_opaque_ristretto255_sha512_Npk);
    ecc_opaque_ristretto255_sha512_3DH_StartWithSecrets(
        ptr_ke1,
        ptr_state,
        ptr_credential_request,
        ptr_client_nonce,
        ptr_client_secret,
        ptr_client_keyshare
    );
    mget(env, ke1, ptr_ke1, ecc_opaque_ristretto255_sha512_KE1SIZE);
    mget(env, state, ptr_state, ecc_opaque_ristretto255_sha512_CLIENTSTATESIZE);
    mfree(ptr_ke1, ecc_opaque_ristretto255_sha512_KE1SIZE);
    mfree(ptr_state, ecc_opaque_ristretto255_sha512_CLIENTSTATESIZE);
    mfree(ptr_credential_request, ecc_opaque_ristretto255_sha512_CREDENTIALREQUESTSIZE);
    mfree(ptr_client_nonce, ecc_opaque_ristretto255_sha512_Nn);
    mfree(ptr_client_secret, ecc_opaque_ristretto255_sha512_Nsk);
    mfree(ptr_client_keyshare, ecc_opaque_ristretto255_sha512_Npk);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1opaque_1ristretto255_1sha512_13DH_1Start(
    JNIEnv *env, jclass cls,
    jbyteArray ke1,
    jbyteArray state,
    jbyteArray credential_request
) {
    byte_t *ptr_ke1 = mput(env, ke1, ecc_opaque_ristretto255_sha512_KE1SIZE);
    byte_t *ptr_state = mput(env, state, ecc_opaque_ristretto255_sha512_CLIENTSTATESIZE);
    byte_t *ptr_credential_request = mput(env, credential_request, ecc_opaque_ristretto255_sha512_CREDENTIALREQUESTSIZE);
    ecc_opaque_ristretto255_sha512_3DH_Start(
        ptr_ke1,
        ptr_state,
        ptr_credential_request
    );
    mget(env, ke1, ptr_ke1, ecc_opaque_ristretto255_sha512_KE1SIZE);
    mget(env, state, ptr_state, ecc_opaque_ristretto255_sha512_CLIENTSTATESIZE);
    mfree(ptr_ke1, ecc_opaque_ristretto255_sha512_KE1SIZE);
    mfree(ptr_state, ecc_opaque_ristretto255_sha512_CLIENTSTATESIZE);
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

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1opaque_1ristretto255_1sha512_13DH_1ServerInitWithSecrets(
    JNIEnv *env, jclass cls,
    jbyteArray ke2_raw,
    jbyteArray state_raw,
    jbyteArray server_identity,
    jint server_identity_len,
    jbyteArray server_private_key,
    jbyteArray server_public_key,
    jbyteArray client_identity,
    jint client_identity_len,
    jbyteArray record_raw,
    jbyteArray credential_identifier,
    jint credential_identifier_len,
    jbyteArray oprf_seed,
    jbyteArray ke1_raw,
    jbyteArray context,
    jint context_len,
    jbyteArray masking_nonce,
    jbyteArray server_nonce,
    jbyteArray server_secret,
    jbyteArray server_keyshare
) {
    byte_t *ptr_ke2_raw = mput(env, ke2_raw, ecc_opaque_ristretto255_sha512_KE2SIZE);
    byte_t *ptr_state_raw = mput(env, state_raw, ecc_opaque_ristretto255_sha512_SERVERSTATESIZE);
    byte_t *ptr_server_identity = mput(env, server_identity, server_identity_len);
    byte_t *ptr_server_private_key = mput(env, server_private_key, ecc_opaque_ristretto255_sha512_Nsk);
    byte_t *ptr_server_public_key = mput(env, server_public_key, ecc_opaque_ristretto255_sha512_Npk);
    byte_t *ptr_client_identity = mput(env, client_identity, client_identity_len);
    byte_t *ptr_record_raw = mput(env, record_raw, ecc_opaque_ristretto255_sha512_REGISTRATIONUPLOADSIZE);
    byte_t *ptr_credential_identifier = mput(env, credential_identifier, credential_identifier_len);
    byte_t *ptr_oprf_seed = mput(env, oprf_seed, ecc_opaque_ristretto255_sha512_Nh);
    byte_t *ptr_ke1_raw = mput(env, ke1_raw, ecc_opaque_ristretto255_sha512_KE1SIZE);
    byte_t *ptr_context = mput(env, context, context_len);
    byte_t *ptr_masking_nonce = mput(env, masking_nonce, ecc_opaque_ristretto255_sha512_Nn);
    byte_t *ptr_server_nonce = mput(env, server_nonce, ecc_opaque_ristretto255_sha512_Nn);
    byte_t *ptr_server_secret = mput(env, server_secret, ecc_opaque_ristretto255_sha512_Nsk);
    byte_t *ptr_server_keyshare = mput(env, server_keyshare, ecc_opaque_ristretto255_sha512_Npk);
    ecc_opaque_ristretto255_sha512_3DH_ServerInitWithSecrets(
        ptr_ke2_raw,
        ptr_state_raw,
        ptr_server_identity,
        server_identity_len,
        ptr_server_private_key,
        ptr_server_public_key,
        ptr_client_identity,
        client_identity_len,
        ptr_record_raw,
        ptr_credential_identifier,
        credential_identifier_len,
        ptr_oprf_seed,
        ptr_ke1_raw,
        ptr_context,
        context_len,
        ptr_masking_nonce,
        ptr_server_nonce,
        ptr_server_secret,
        ptr_server_keyshare
    );
    mget(env, ke2_raw, ptr_ke2_raw, ecc_opaque_ristretto255_sha512_KE2SIZE);
    mget(env, state_raw, ptr_state_raw, ecc_opaque_ristretto255_sha512_SERVERSTATESIZE);
    mfree(ptr_ke2_raw, ecc_opaque_ristretto255_sha512_KE2SIZE);
    mfree(ptr_state_raw, ecc_opaque_ristretto255_sha512_SERVERSTATESIZE);
    mfree(ptr_server_identity, server_identity_len);
    mfree(ptr_server_private_key, ecc_opaque_ristretto255_sha512_Nsk);
    mfree(ptr_server_public_key, ecc_opaque_ristretto255_sha512_Npk);
    mfree(ptr_client_identity, client_identity_len);
    mfree(ptr_record_raw, ecc_opaque_ristretto255_sha512_REGISTRATIONUPLOADSIZE);
    mfree(ptr_credential_identifier, credential_identifier_len);
    mfree(ptr_oprf_seed, ecc_opaque_ristretto255_sha512_Nh);
    mfree(ptr_ke1_raw, ecc_opaque_ristretto255_sha512_KE1SIZE);
    mfree(ptr_context, context_len);
    mfree(ptr_masking_nonce, ecc_opaque_ristretto255_sha512_Nn);
    mfree(ptr_server_nonce, ecc_opaque_ristretto255_sha512_Nn);
    mfree(ptr_server_secret, ecc_opaque_ristretto255_sha512_Nsk);
    mfree(ptr_server_keyshare, ecc_opaque_ristretto255_sha512_Npk);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1opaque_1ristretto255_1sha512_13DH_1ServerInit(
    JNIEnv *env, jclass cls,
    jbyteArray ke2_raw,
    jbyteArray state_raw,
    jbyteArray server_identity,
    jint server_identity_len,
    jbyteArray server_private_key,
    jbyteArray server_public_key,
    jbyteArray client_identity,
    jint client_identity_len,
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
    byte_t *ptr_client_identity = mput(env, client_identity, client_identity_len);
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
        ptr_client_identity,
        client_identity_len,
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
    mfree(ptr_client_identity, client_identity_len);
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

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1opaque_1ristretto255_1sha512_13DH_1ResponseWithSecrets(
    JNIEnv *env, jclass cls,
    jbyteArray ke2_raw,
    jbyteArray state_raw,
    jbyteArray server_identity,
    jint server_identity_len,
    jbyteArray server_private_key,
    jbyteArray server_public_key,
    jbyteArray client_identity,
    jint client_identity_len,
    jbyteArray client_public_key,
    jbyteArray ke1_raw,
    jbyteArray credential_response_raw,
    jbyteArray context,
    jint context_len,
    jbyteArray server_nonce,
    jbyteArray server_secret,
    jbyteArray server_keyshare
) {
    byte_t *ptr_ke2_raw = mput(env, ke2_raw, ecc_opaque_ristretto255_sha512_KE2SIZE);
    byte_t *ptr_state_raw = mput(env, state_raw, ecc_opaque_ristretto255_sha512_SERVERSTATESIZE);
    byte_t *ptr_server_identity = mput(env, server_identity, server_identity_len);
    byte_t *ptr_server_private_key = mput(env, server_private_key, ecc_opaque_ristretto255_sha512_Nsk);
    byte_t *ptr_server_public_key = mput(env, server_public_key, ecc_opaque_ristretto255_sha512_Npk);
    byte_t *ptr_client_identity = mput(env, client_identity, client_identity_len);
    byte_t *ptr_client_public_key = mput(env, client_public_key, ecc_opaque_ristretto255_sha512_Npk);
    byte_t *ptr_ke1_raw = mput(env, ke1_raw, ecc_opaque_ristretto255_sha512_KE1SIZE);
    byte_t *ptr_credential_response_raw = mput(env, credential_response_raw, ecc_opaque_ristretto255_sha512_CREDENTIALRESPONSESIZE);
    byte_t *ptr_context = mput(env, context, context_len);
    byte_t *ptr_server_nonce = mput(env, server_nonce, ecc_opaque_ristretto255_sha512_Nn);
    byte_t *ptr_server_secret = mput(env, server_secret, ecc_opaque_ristretto255_sha512_Nsk);
    byte_t *ptr_server_keyshare = mput(env, server_keyshare, ecc_opaque_ristretto255_sha512_Npk);
    ecc_opaque_ristretto255_sha512_3DH_ResponseWithSecrets(
        ptr_ke2_raw,
        ptr_state_raw,
        ptr_server_identity,
        server_identity_len,
        ptr_server_private_key,
        ptr_server_public_key,
        ptr_client_identity,
        client_identity_len,
        ptr_client_public_key,
        ptr_ke1_raw,
        ptr_credential_response_raw,
        ptr_context,
        context_len,
        ptr_server_nonce,
        ptr_server_secret,
        ptr_server_keyshare
    );
    mget(env, ke2_raw, ptr_ke2_raw, ecc_opaque_ristretto255_sha512_KE2SIZE);
    mget(env, state_raw, ptr_state_raw, ecc_opaque_ristretto255_sha512_SERVERSTATESIZE);
    mfree(ptr_ke2_raw, ecc_opaque_ristretto255_sha512_KE2SIZE);
    mfree(ptr_state_raw, ecc_opaque_ristretto255_sha512_SERVERSTATESIZE);
    mfree(ptr_server_identity, server_identity_len);
    mfree(ptr_server_private_key, ecc_opaque_ristretto255_sha512_Nsk);
    mfree(ptr_server_public_key, ecc_opaque_ristretto255_sha512_Npk);
    mfree(ptr_client_identity, client_identity_len);
    mfree(ptr_client_public_key, ecc_opaque_ristretto255_sha512_Npk);
    mfree(ptr_ke1_raw, ecc_opaque_ristretto255_sha512_KE1SIZE);
    mfree(ptr_credential_response_raw, ecc_opaque_ristretto255_sha512_CREDENTIALRESPONSESIZE);
    mfree(ptr_context, context_len);
    mfree(ptr_server_nonce, ecc_opaque_ristretto255_sha512_Nn);
    mfree(ptr_server_secret, ecc_opaque_ristretto255_sha512_Nsk);
    mfree(ptr_server_keyshare, ecc_opaque_ristretto255_sha512_Npk);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1opaque_1ristretto255_1sha512_13DH_1Response(
    JNIEnv *env, jclass cls,
    jbyteArray ke2_raw,
    jbyteArray state_raw,
    jbyteArray server_identity,
    jint server_identity_len,
    jbyteArray server_private_key,
    jbyteArray server_public_key,
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
    byte_t *ptr_server_public_key = mput(env, server_public_key, ecc_opaque_ristretto255_sha512_Npk);
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
        ptr_server_public_key,
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
    mfree(ptr_server_public_key, ecc_opaque_ristretto255_sha512_Npk);
    mfree(ptr_client_identity, client_identity_len);
    mfree(ptr_client_public_key, ecc_opaque_ristretto255_sha512_Npk);
    mfree(ptr_ke1_raw, ecc_opaque_ristretto255_sha512_KE1SIZE);
    mfree(ptr_credential_response_raw, ecc_opaque_ristretto255_sha512_CREDENTIALRESPONSESIZE);
    mfree(ptr_context, context_len);
}

// sign

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1sign_1ed25519_1Sign(
    JNIEnv *env, jclass cls,
    jbyteArray signature,
    jbyteArray message,
    jint message_len,
    jbyteArray sk
) {
    byte_t *ptr_signature = mput(env, signature, ecc_sign_ed25519_SIGNATURESIZE);
    byte_t *ptr_message = mput(env, message, message_len);
    byte_t *ptr_sk = mput(env, sk, ecc_sign_ed25519_SECRETKEYSIZE);
    ecc_sign_ed25519_Sign(
        ptr_signature,
        ptr_message,
        message_len,
        ptr_sk
    );
    mget(env, signature, ptr_signature, ecc_sign_ed25519_SIGNATURESIZE);
    mfree(ptr_signature, ecc_sign_ed25519_SIGNATURESIZE);
    mfree(ptr_message, message_len);
    mfree(ptr_sk, ecc_sign_ed25519_SECRETKEYSIZE);
}

JNIEXPORT int JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1sign_1ed25519_1Verify(
    JNIEnv *env, jclass cls,
    jbyteArray signature,
    jbyteArray message,
    jint message_len,
    jbyteArray pk
) {
    byte_t *ptr_signature = mput(env, signature, ecc_sign_ed25519_SIGNATURESIZE);
    byte_t *ptr_message = mput(env, message, message_len);
    byte_t *ptr_pk = mput(env, pk, ecc_sign_ed25519_PUBLICKEYSIZE);
    const int fun_ret = ecc_sign_ed25519_Verify(
        ptr_signature,
        ptr_message,
        message_len,
        ptr_pk
    );
    mfree(ptr_signature, ecc_sign_ed25519_SIGNATURESIZE);
    mfree(ptr_message, message_len);
    mfree(ptr_pk, ecc_sign_ed25519_PUBLICKEYSIZE);
    return fun_ret;
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1sign_1ed25519_1KeyPair(
    JNIEnv *env, jclass cls,
    jbyteArray pk,
    jbyteArray sk
) {
    byte_t *ptr_pk = mput(env, pk, ecc_sign_ed25519_PUBLICKEYSIZE);
    byte_t *ptr_sk = mput(env, sk, ecc_sign_ed25519_SECRETKEYSIZE);
    ecc_sign_ed25519_KeyPair(
        ptr_pk,
        ptr_sk
    );
    mget(env, pk, ptr_pk, ecc_sign_ed25519_PUBLICKEYSIZE);
    mget(env, sk, ptr_sk, ecc_sign_ed25519_SECRETKEYSIZE);
    mfree(ptr_pk, ecc_sign_ed25519_PUBLICKEYSIZE);
    mfree(ptr_sk, ecc_sign_ed25519_SECRETKEYSIZE);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1sign_1ed25519_1SeedKeyPair(
    JNIEnv *env, jclass cls,
    jbyteArray pk,
    jbyteArray sk,
    jbyteArray seed
) {
    byte_t *ptr_pk = mput(env, pk, ecc_sign_ed25519_PUBLICKEYSIZE);
    byte_t *ptr_sk = mput(env, sk, ecc_sign_ed25519_SECRETKEYSIZE);
    byte_t *ptr_seed = mput(env, seed, ecc_sign_ed25519_SEEDSIZE);
    ecc_sign_ed25519_SeedKeyPair(
        ptr_pk,
        ptr_sk,
        ptr_seed
    );
    mget(env, pk, ptr_pk, ecc_sign_ed25519_PUBLICKEYSIZE);
    mget(env, sk, ptr_sk, ecc_sign_ed25519_SECRETKEYSIZE);
    mfree(ptr_pk, ecc_sign_ed25519_PUBLICKEYSIZE);
    mfree(ptr_sk, ecc_sign_ed25519_SECRETKEYSIZE);
    mfree(ptr_seed, ecc_sign_ed25519_SEEDSIZE);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1sign_1ed25519_1SkToSeed(
    JNIEnv *env, jclass cls,
    jbyteArray seed,
    jbyteArray sk
) {
    byte_t *ptr_seed = mput(env, seed, ecc_sign_ed25519_SEEDSIZE);
    byte_t *ptr_sk = mput(env, sk, ecc_sign_ed25519_SECRETKEYSIZE);
    ecc_sign_ed25519_SkToSeed(
        ptr_seed,
        ptr_sk
    );
    mget(env, seed, ptr_seed, ecc_sign_ed25519_SEEDSIZE);
    mfree(ptr_seed, ecc_sign_ed25519_SEEDSIZE);
    mfree(ptr_sk, ecc_sign_ed25519_SECRETKEYSIZE);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1sign_1ed25519_1SkToPk(
    JNIEnv *env, jclass cls,
    jbyteArray pk,
    jbyteArray sk
) {
    byte_t *ptr_pk = mput(env, pk, ecc_sign_ed25519_PUBLICKEYSIZE);
    byte_t *ptr_sk = mput(env, sk, ecc_sign_ed25519_SECRETKEYSIZE);
    ecc_sign_ed25519_SkToPk(
        ptr_pk,
        ptr_sk
    );
    mget(env, pk, ptr_pk, ecc_sign_ed25519_PUBLICKEYSIZE);
    mfree(ptr_pk, ecc_sign_ed25519_PUBLICKEYSIZE);
    mfree(ptr_sk, ecc_sign_ed25519_SECRETKEYSIZE);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1sign_1eth_1bls_1KeyGen(
    JNIEnv *env, jclass cls,
    jbyteArray sk,
    jbyteArray ikm,
    jint ikm_len
) {
    byte_t *ptr_sk = mput(env, sk, ecc_sign_eth_bls_PRIVATEKEYSIZE);
    byte_t *ptr_ikm = mput(env, ikm, ikm_len);
    ecc_sign_eth_bls_KeyGen(
        ptr_sk,
        ptr_ikm,
        ikm_len
    );
    mget(env, sk, ptr_sk, ecc_sign_eth_bls_PRIVATEKEYSIZE);
    mfree(ptr_sk, ecc_sign_eth_bls_PRIVATEKEYSIZE);
    mfree(ptr_ikm, ikm_len);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1sign_1eth_1bls_1SkToPk(
    JNIEnv *env, jclass cls,
    jbyteArray pk,
    jbyteArray sk
) {
    byte_t *ptr_pk = mput(env, pk, ecc_sign_eth_bls_PUBLICKEYSIZE);
    byte_t *ptr_sk = mput(env, sk, ecc_sign_eth_bls_PRIVATEKEYSIZE);
    ecc_sign_eth_bls_SkToPk(
        ptr_pk,
        ptr_sk
    );
    mget(env, pk, ptr_pk, ecc_sign_eth_bls_PUBLICKEYSIZE);
    mfree(ptr_pk, ecc_sign_eth_bls_PUBLICKEYSIZE);
    mfree(ptr_sk, ecc_sign_eth_bls_PRIVATEKEYSIZE);
}

JNIEXPORT int JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1sign_1eth_1bls_1KeyValidate(
    JNIEnv *env, jclass cls,
    jbyteArray pk
) {
    byte_t *ptr_pk = mput(env, pk, ecc_sign_eth_bls_PUBLICKEYSIZE);
    const int fun_ret = ecc_sign_eth_bls_KeyValidate(
        ptr_pk
    );
    mfree(ptr_pk, ecc_sign_eth_bls_PUBLICKEYSIZE);
    return fun_ret;
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1sign_1eth_1bls_1Sign(
    JNIEnv *env, jclass cls,
    jbyteArray signature,
    jbyteArray sk,
    jbyteArray message,
    jint message_len
) {
    byte_t *ptr_signature = mput(env, signature, ecc_sign_eth_bls_SIGNATURESIZE);
    byte_t *ptr_sk = mput(env, sk, ecc_sign_eth_bls_PRIVATEKEYSIZE);
    byte_t *ptr_message = mput(env, message, message_len);
    ecc_sign_eth_bls_Sign(
        ptr_signature,
        ptr_sk,
        ptr_message,
        message_len
    );
    mget(env, signature, ptr_signature, ecc_sign_eth_bls_SIGNATURESIZE);
    mfree(ptr_signature, ecc_sign_eth_bls_SIGNATURESIZE);
    mfree(ptr_sk, ecc_sign_eth_bls_PRIVATEKEYSIZE);
    mfree(ptr_message, message_len);
}

JNIEXPORT int JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1sign_1eth_1bls_1Verify(
    JNIEnv *env, jclass cls,
    jbyteArray pk,
    jbyteArray message,
    jint message_len,
    jbyteArray signature
) {
    byte_t *ptr_pk = mput(env, pk, ecc_sign_eth_bls_PUBLICKEYSIZE);
    byte_t *ptr_message = mput(env, message, message_len);
    byte_t *ptr_signature = mput(env, signature, ecc_sign_eth_bls_SIGNATURESIZE);
    const int fun_ret = ecc_sign_eth_bls_Verify(
        ptr_pk,
        ptr_message,
        message_len,
        ptr_signature
    );
    mfree(ptr_pk, ecc_sign_eth_bls_PUBLICKEYSIZE);
    mfree(ptr_message, message_len);
    mfree(ptr_signature, ecc_sign_eth_bls_SIGNATURESIZE);
    return fun_ret;
}

JNIEXPORT int JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1sign_1eth_1bls_1Aggregate(
    JNIEnv *env, jclass cls,
    jbyteArray signature,
    jbyteArray signatures,
    jint n
) {
    byte_t *ptr_signature = mput(env, signature, ecc_sign_eth_bls_SIGNATURESIZE);
    byte_t *ptr_signatures = mput(env, signatures, n*ecc_sign_eth_bls_SIGNATURESIZE);
    const int fun_ret = ecc_sign_eth_bls_Aggregate(
        ptr_signature,
        ptr_signatures,
        n
    );
    mget(env, signature, ptr_signature, ecc_sign_eth_bls_SIGNATURESIZE);
    mfree(ptr_signature, ecc_sign_eth_bls_SIGNATURESIZE);
    mfree(ptr_signatures, n*ecc_sign_eth_bls_SIGNATURESIZE);
    return fun_ret;
}

JNIEXPORT int JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1sign_1eth_1bls_1FastAggregateVerify(
    JNIEnv *env, jclass cls,
    jbyteArray pks,
    jint n,
    jbyteArray message,
    jint message_len,
    jbyteArray signature
) {
    byte_t *ptr_pks = mput(env, pks, n*ecc_sign_eth_bls_PUBLICKEYSIZE);
    byte_t *ptr_message = mput(env, message, message_len);
    byte_t *ptr_signature = mput(env, signature, ecc_sign_eth_bls_SIGNATURESIZE);
    const int fun_ret = ecc_sign_eth_bls_FastAggregateVerify(
        ptr_pks,
        n,
        ptr_message,
        message_len,
        ptr_signature
    );
    mfree(ptr_pks, n*ecc_sign_eth_bls_PUBLICKEYSIZE);
    mfree(ptr_message, message_len);
    mfree(ptr_signature, ecc_sign_eth_bls_SIGNATURESIZE);
    return fun_ret;
}

JNIEXPORT int JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1sign_1eth_1bls_1AggregateVerify(
    JNIEnv *env, jclass cls,
    jint n,
    jbyteArray pks,
    jbyteArray messages,
    jint messages_len,
    jbyteArray signature
) {
    byte_t *ptr_pks = mput(env, pks, n*ecc_sign_eth_bls_PUBLICKEYSIZE);
    byte_t *ptr_messages = mput(env, messages, messages_len);
    byte_t *ptr_signature = mput(env, signature, ecc_sign_eth_bls_SIGNATURESIZE);
    const int fun_ret = ecc_sign_eth_bls_AggregateVerify(
        n,
        ptr_pks,
        ptr_messages,
        messages_len,
        ptr_signature
    );
    mfree(ptr_pks, n*ecc_sign_eth_bls_PUBLICKEYSIZE);
    mfree(ptr_messages, messages_len);
    mfree(ptr_signature, ecc_sign_eth_bls_SIGNATURESIZE);
    return fun_ret;
}

// frost

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1frost_1ristretto255_1sha512_1nonce_1generate_1with_1randomness(
    JNIEnv *env, jclass cls,
    jbyteArray nonce,
    jbyteArray secret,
    jbyteArray random_bytes
) {
    byte_t *ptr_nonce = mput(env, nonce, ecc_frost_ristretto255_sha512_SCALARSIZE);
    byte_t *ptr_secret = mput(env, secret, ecc_frost_ristretto255_sha512_SCALARSIZE);
    byte_t *ptr_random_bytes = mput(env, random_bytes, 32);
    ecc_frost_ristretto255_sha512_nonce_generate_with_randomness(
        ptr_nonce,
        ptr_secret,
        ptr_random_bytes
    );
    mget(env, nonce, ptr_nonce, ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_nonce, ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_secret, ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_random_bytes, 32);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1frost_1ristretto255_1sha512_1nonce_1generate(
    JNIEnv *env, jclass cls,
    jbyteArray nonce,
    jbyteArray secret
) {
    byte_t *ptr_nonce = mput(env, nonce, ecc_frost_ristretto255_sha512_SCALARSIZE);
    byte_t *ptr_secret = mput(env, secret, ecc_frost_ristretto255_sha512_SCALARSIZE);
    ecc_frost_ristretto255_sha512_nonce_generate(
        ptr_nonce,
        ptr_secret
    );
    mget(env, nonce, ptr_nonce, ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_nonce, ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_secret, ecc_frost_ristretto255_sha512_SCALARSIZE);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1frost_1ristretto255_1sha512_1derive_1interpolating_1value(
    JNIEnv *env, jclass cls,
    jbyteArray L_i,
    jbyteArray x_i,
    jbyteArray L,
    jint L_len
) {
    byte_t *ptr_L_i = mput(env, L_i, ecc_frost_ristretto255_sha512_SCALARSIZE);
    byte_t *ptr_x_i = mput(env, x_i, ecc_frost_ristretto255_sha512_SCALARSIZE);
    byte_t *ptr_L = mput(env, L, L_len*ecc_frost_ristretto255_sha512_SCALARSIZE);
    ecc_frost_ristretto255_sha512_derive_interpolating_value(
        ptr_L_i,
        ptr_x_i,
        ptr_L,
        L_len
    );
    mget(env, L_i, ptr_L_i, ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_L_i, ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_x_i, ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_L, L_len*ecc_frost_ristretto255_sha512_SCALARSIZE);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1frost_1ristretto255_1sha512_1derive_1interpolating_1value_1with_1points(
    JNIEnv *env, jclass cls,
    jbyteArray L_i,
    jbyteArray x_i,
    jbyteArray L,
    jint L_len
) {
    byte_t *ptr_L_i = mput(env, L_i, ecc_frost_ristretto255_sha512_SCALARSIZE);
    byte_t *ptr_x_i = mput(env, x_i, ecc_frost_ristretto255_sha512_SCALARSIZE);
    byte_t *ptr_L = mput(env, L, L_len*ecc_frost_ristretto255_sha512_POINTSIZE);
    ecc_frost_ristretto255_sha512_derive_interpolating_value_with_points(
        ptr_L_i,
        ptr_x_i,
        ptr_L,
        L_len
    );
    mget(env, L_i, ptr_L_i, ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_L_i, ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_x_i, ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_L, L_len*ecc_frost_ristretto255_sha512_POINTSIZE);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1frost_1ristretto255_1sha512_1encode_1group_1commitment_1list(
    JNIEnv *env, jclass cls,
    jbyteArray out,
    jbyteArray commitment_list,
    jint commitment_list_len
) {
    byte_t *ptr_out = mput(env, out, commitment_list_len*ecc_frost_ristretto255_sha512_COMMITMENTSIZE);
    byte_t *ptr_commitment_list = mput(env, commitment_list, commitment_list_len*ecc_frost_ristretto255_sha512_COMMITMENTSIZE);
    ecc_frost_ristretto255_sha512_encode_group_commitment_list(
        ptr_out,
        ptr_commitment_list,
        commitment_list_len
    );
    mget(env, out, ptr_out, commitment_list_len*ecc_frost_ristretto255_sha512_COMMITMENTSIZE);
    mfree(ptr_out, commitment_list_len*ecc_frost_ristretto255_sha512_COMMITMENTSIZE);
    mfree(ptr_commitment_list, commitment_list_len*ecc_frost_ristretto255_sha512_COMMITMENTSIZE);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1frost_1ristretto255_1sha512_1participants_1from_1commitment_1list(
    JNIEnv *env, jclass cls,
    jbyteArray identifiers,
    jbyteArray commitment_list,
    jint commitment_list_len
) {
    byte_t *ptr_identifiers = mput(env, identifiers, commitment_list_len*ecc_frost_ristretto255_sha512_SCALARSIZE);
    byte_t *ptr_commitment_list = mput(env, commitment_list, commitment_list_len*ecc_frost_ristretto255_sha512_COMMITMENTSIZE);
    ecc_frost_ristretto255_sha512_participants_from_commitment_list(
        ptr_identifiers,
        ptr_commitment_list,
        commitment_list_len
    );
    mget(env, identifiers, ptr_identifiers, commitment_list_len*ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_identifiers, commitment_list_len*ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_commitment_list, commitment_list_len*ecc_frost_ristretto255_sha512_COMMITMENTSIZE);
}

JNIEXPORT int JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1frost_1ristretto255_1sha512_1binding_1factor_1for_1participant(
    JNIEnv *env, jclass cls,
    jbyteArray binding_factor,
    jbyteArray binding_factor_list,
    jint binding_factor_list_len,
    jbyteArray identifier
) {
    byte_t *ptr_binding_factor = mput(env, binding_factor, ecc_frost_ristretto255_sha512_SCALARSIZE);
    byte_t *ptr_binding_factor_list = mput(env, binding_factor_list, binding_factor_list_len*ecc_frost_ristretto255_sha512_BINDINGFACTORSIZE);
    byte_t *ptr_identifier = mput(env, identifier, ecc_frost_ristretto255_sha512_SCALARSIZE);
    const int fun_ret = ecc_frost_ristretto255_sha512_binding_factor_for_participant(
        ptr_binding_factor,
        ptr_binding_factor_list,
        binding_factor_list_len,
        ptr_identifier
    );
    mget(env, binding_factor, ptr_binding_factor, ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_binding_factor, ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_binding_factor_list, binding_factor_list_len*ecc_frost_ristretto255_sha512_BINDINGFACTORSIZE);
    mfree(ptr_identifier, ecc_frost_ristretto255_sha512_SCALARSIZE);
    return fun_ret;
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1frost_1ristretto255_1sha512_1compute_1binding_1factors(
    JNIEnv *env, jclass cls,
    jbyteArray binding_factor_list,
    jbyteArray commitment_list,
    jint commitment_list_len,
    jbyteArray msg,
    jint msg_len
) {
    byte_t *ptr_binding_factor_list = mput(env, binding_factor_list, commitment_list_len*ecc_frost_ristretto255_sha512_BINDINGFACTORSIZE);
    byte_t *ptr_commitment_list = mput(env, commitment_list, commitment_list_len*ecc_frost_ristretto255_sha512_COMMITMENTSIZE);
    byte_t *ptr_msg = mput(env, msg, msg_len);
    ecc_frost_ristretto255_sha512_compute_binding_factors(
        ptr_binding_factor_list,
        ptr_commitment_list,
        commitment_list_len,
        ptr_msg,
        msg_len
    );
    mget(env, binding_factor_list, ptr_binding_factor_list, commitment_list_len*ecc_frost_ristretto255_sha512_BINDINGFACTORSIZE);
    mfree(ptr_binding_factor_list, commitment_list_len*ecc_frost_ristretto255_sha512_BINDINGFACTORSIZE);
    mfree(ptr_commitment_list, commitment_list_len*ecc_frost_ristretto255_sha512_COMMITMENTSIZE);
    mfree(ptr_msg, msg_len);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1frost_1ristretto255_1sha512_1compute_1group_1commitment(
    JNIEnv *env, jclass cls,
    jbyteArray group_comm,
    jbyteArray commitment_list,
    jint commitment_list_len,
    jbyteArray binding_factor_list,
    jint binding_factor_list_len
) {
    byte_t *ptr_group_comm = mput(env, group_comm, ecc_frost_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_commitment_list = mput(env, commitment_list, commitment_list_len*ecc_frost_ristretto255_sha512_COMMITMENTSIZE);
    byte_t *ptr_binding_factor_list = mput(env, binding_factor_list, ecc_frost_ristretto255_sha512_BINDINGFACTORSIZE);
    ecc_frost_ristretto255_sha512_compute_group_commitment(
        ptr_group_comm,
        ptr_commitment_list,
        commitment_list_len,
        ptr_binding_factor_list,
        binding_factor_list_len
    );
    mget(env, group_comm, ptr_group_comm, ecc_frost_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_group_comm, ecc_frost_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_commitment_list, commitment_list_len*ecc_frost_ristretto255_sha512_COMMITMENTSIZE);
    mfree(ptr_binding_factor_list, ecc_frost_ristretto255_sha512_BINDINGFACTORSIZE);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1frost_1ristretto255_1sha512_1compute_1challenge(
    JNIEnv *env, jclass cls,
    jbyteArray challenge,
    jbyteArray group_commitment,
    jbyteArray group_public_key,
    jbyteArray msg,
    jint msg_len
) {
    byte_t *ptr_challenge = mput(env, challenge, ecc_frost_ristretto255_sha512_SCALARSIZE);
    byte_t *ptr_group_commitment = mput(env, group_commitment, ecc_frost_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_group_public_key = mput(env, group_public_key, ecc_frost_ristretto255_sha512_PUBLICKEYSIZE);
    byte_t *ptr_msg = mput(env, msg, msg_len);
    ecc_frost_ristretto255_sha512_compute_challenge(
        ptr_challenge,
        ptr_group_commitment,
        ptr_group_public_key,
        ptr_msg,
        msg_len
    );
    mget(env, challenge, ptr_challenge, ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_challenge, ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_group_commitment, ecc_frost_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_group_public_key, ecc_frost_ristretto255_sha512_PUBLICKEYSIZE);
    mfree(ptr_msg, msg_len);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1frost_1ristretto255_1sha512_1commit_1with_1randomness(
    JNIEnv *env, jclass cls,
    jbyteArray nonce,
    jbyteArray comm,
    jbyteArray sk_i,
    jbyteArray hiding_nonce_randomness,
    jbyteArray binding_nonce_randomness
) {
    byte_t *ptr_nonce = mput(env, nonce, ecc_frost_ristretto255_sha512_NONCEPAIRSIZE);
    byte_t *ptr_comm = mput(env, comm, ecc_frost_ristretto255_sha512_NONCECOMMITMENTPAIRSIZE);
    byte_t *ptr_sk_i = mput(env, sk_i, ecc_frost_ristretto255_sha512_SCALARSIZE);
    byte_t *ptr_hiding_nonce_randomness = mput(env, hiding_nonce_randomness, 32);
    byte_t *ptr_binding_nonce_randomness = mput(env, binding_nonce_randomness, 32);
    ecc_frost_ristretto255_sha512_commit_with_randomness(
        ptr_nonce,
        ptr_comm,
        ptr_sk_i,
        ptr_hiding_nonce_randomness,
        ptr_binding_nonce_randomness
    );
    mget(env, nonce, ptr_nonce, ecc_frost_ristretto255_sha512_NONCEPAIRSIZE);
    mget(env, comm, ptr_comm, ecc_frost_ristretto255_sha512_NONCECOMMITMENTPAIRSIZE);
    mfree(ptr_nonce, ecc_frost_ristretto255_sha512_NONCEPAIRSIZE);
    mfree(ptr_comm, ecc_frost_ristretto255_sha512_NONCECOMMITMENTPAIRSIZE);
    mfree(ptr_sk_i, ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_hiding_nonce_randomness, 32);
    mfree(ptr_binding_nonce_randomness, 32);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1frost_1ristretto255_1sha512_1commit(
    JNIEnv *env, jclass cls,
    jbyteArray nonce,
    jbyteArray comm,
    jbyteArray sk_i
) {
    byte_t *ptr_nonce = mput(env, nonce, ecc_frost_ristretto255_sha512_NONCEPAIRSIZE);
    byte_t *ptr_comm = mput(env, comm, ecc_frost_ristretto255_sha512_NONCECOMMITMENTPAIRSIZE);
    byte_t *ptr_sk_i = mput(env, sk_i, ecc_frost_ristretto255_sha512_SCALARSIZE);
    ecc_frost_ristretto255_sha512_commit(
        ptr_nonce,
        ptr_comm,
        ptr_sk_i
    );
    mget(env, nonce, ptr_nonce, ecc_frost_ristretto255_sha512_NONCEPAIRSIZE);
    mget(env, comm, ptr_comm, ecc_frost_ristretto255_sha512_NONCECOMMITMENTPAIRSIZE);
    mfree(ptr_nonce, ecc_frost_ristretto255_sha512_NONCEPAIRSIZE);
    mfree(ptr_comm, ecc_frost_ristretto255_sha512_NONCECOMMITMENTPAIRSIZE);
    mfree(ptr_sk_i, ecc_frost_ristretto255_sha512_SCALARSIZE);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1frost_1ristretto255_1sha512_1sign(
    JNIEnv *env, jclass cls,
    jbyteArray sig_share,
    jbyteArray identifier,
    jbyteArray sk_i,
    jbyteArray group_public_key,
    jbyteArray nonce_i,
    jbyteArray msg,
    jint msg_len,
    jbyteArray commitment_list,
    jint commitment_list_len
) {
    byte_t *ptr_sig_share = mput(env, sig_share, ecc_frost_ristretto255_sha512_SCALARSIZE);
    byte_t *ptr_identifier = mput(env, identifier, ecc_frost_ristretto255_sha512_SCALARSIZE);
    byte_t *ptr_sk_i = mput(env, sk_i, ecc_frost_ristretto255_sha512_SECRETKEYSIZE);
    byte_t *ptr_group_public_key = mput(env, group_public_key, ecc_frost_ristretto255_sha512_PUBLICKEYSIZE);
    byte_t *ptr_nonce_i = mput(env, nonce_i, ecc_frost_ristretto255_sha512_NONCEPAIRSIZE);
    byte_t *ptr_msg = mput(env, msg, msg_len);
    byte_t *ptr_commitment_list = mput(env, commitment_list, commitment_list_len*ecc_frost_ristretto255_sha512_COMMITMENTSIZE);
    ecc_frost_ristretto255_sha512_sign(
        ptr_sig_share,
        ptr_identifier,
        ptr_sk_i,
        ptr_group_public_key,
        ptr_nonce_i,
        ptr_msg,
        msg_len,
        ptr_commitment_list,
        commitment_list_len
    );
    mget(env, sig_share, ptr_sig_share, ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_sig_share, ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_identifier, ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_sk_i, ecc_frost_ristretto255_sha512_SECRETKEYSIZE);
    mfree(ptr_group_public_key, ecc_frost_ristretto255_sha512_PUBLICKEYSIZE);
    mfree(ptr_nonce_i, ecc_frost_ristretto255_sha512_NONCEPAIRSIZE);
    mfree(ptr_msg, msg_len);
    mfree(ptr_commitment_list, commitment_list_len*ecc_frost_ristretto255_sha512_COMMITMENTSIZE);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1frost_1ristretto255_1sha512_1aggregate(
    JNIEnv *env, jclass cls,
    jbyteArray signature,
    jbyteArray commitment_list,
    jint commitment_list_len,
    jbyteArray msg,
    jint msg_len,
    jbyteArray sig_shares,
    jint sig_shares_len
) {
    byte_t *ptr_signature = mput(env, signature, ecc_frost_ristretto255_sha512_SIGNATURESIZE);
    byte_t *ptr_commitment_list = mput(env, commitment_list, commitment_list_len*ecc_frost_ristretto255_sha512_PUBLICKEYSIZE);
    byte_t *ptr_msg = mput(env, msg, msg_len);
    byte_t *ptr_sig_shares = mput(env, sig_shares, sig_shares_len*ecc_frost_ristretto255_sha512_SCALARSIZE);
    ecc_frost_ristretto255_sha512_aggregate(
        ptr_signature,
        ptr_commitment_list,
        commitment_list_len,
        ptr_msg,
        msg_len,
        ptr_sig_shares,
        sig_shares_len
    );
    mget(env, signature, ptr_signature, ecc_frost_ristretto255_sha512_SIGNATURESIZE);
    mfree(ptr_signature, ecc_frost_ristretto255_sha512_SIGNATURESIZE);
    mfree(ptr_commitment_list, commitment_list_len*ecc_frost_ristretto255_sha512_PUBLICKEYSIZE);
    mfree(ptr_msg, msg_len);
    mfree(ptr_sig_shares, sig_shares_len*ecc_frost_ristretto255_sha512_SCALARSIZE);
}

JNIEXPORT int JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1frost_1ristretto255_1sha512_1verify_1signature_1share(
    JNIEnv *env, jclass cls,
    jbyteArray identifier,
    jbyteArray public_key_share_i,
    jbyteArray comm_i,
    jbyteArray sig_share_i,
    jbyteArray commitment_list,
    jint commitment_list_len,
    jbyteArray group_public_key,
    jbyteArray msg,
    jint msg_len
) {
    byte_t *ptr_identifier = mput(env, identifier, ecc_frost_ristretto255_sha512_SCALARSIZE);
    byte_t *ptr_public_key_share_i = mput(env, public_key_share_i, ecc_frost_ristretto255_sha512_PUBLICKEYSIZE);
    byte_t *ptr_comm_i = mput(env, comm_i, ecc_frost_ristretto255_sha512_NONCECOMMITMENTPAIRSIZE);
    byte_t *ptr_sig_share_i = mput(env, sig_share_i, ecc_frost_ristretto255_sha512_SCALARSIZE);
    byte_t *ptr_commitment_list = mput(env, commitment_list, commitment_list_len*ecc_frost_ristretto255_sha512_COMMITMENTSIZE);
    byte_t *ptr_group_public_key = mput(env, group_public_key, ecc_frost_ristretto255_sha512_PUBLICKEYSIZE);
    byte_t *ptr_msg = mput(env, msg, msg_len);
    const int fun_ret = ecc_frost_ristretto255_sha512_verify_signature_share(
        ptr_identifier,
        ptr_public_key_share_i,
        ptr_comm_i,
        ptr_sig_share_i,
        ptr_commitment_list,
        commitment_list_len,
        ptr_group_public_key,
        ptr_msg,
        msg_len
    );
    mfree(ptr_identifier, ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_public_key_share_i, ecc_frost_ristretto255_sha512_PUBLICKEYSIZE);
    mfree(ptr_comm_i, ecc_frost_ristretto255_sha512_NONCECOMMITMENTPAIRSIZE);
    mfree(ptr_sig_share_i, ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_commitment_list, commitment_list_len*ecc_frost_ristretto255_sha512_COMMITMENTSIZE);
    mfree(ptr_group_public_key, ecc_frost_ristretto255_sha512_PUBLICKEYSIZE);
    mfree(ptr_msg, msg_len);
    return fun_ret;
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1frost_1ristretto255_1sha512_1H1(
    JNIEnv *env, jclass cls,
    jbyteArray h1,
    jbyteArray m,
    jint m_len
) {
    byte_t *ptr_h1 = mput(env, h1, ecc_frost_ristretto255_sha512_SCALARSIZE);
    byte_t *ptr_m = mput(env, m, m_len);
    ecc_frost_ristretto255_sha512_H1(
        ptr_h1,
        ptr_m,
        m_len
    );
    mget(env, h1, ptr_h1, ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_h1, ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_m, m_len);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1frost_1ristretto255_1sha512_1H1_12(
    JNIEnv *env, jclass cls,
    jbyteArray h1,
    jbyteArray m1,
    jint m1_len,
    jbyteArray m2,
    jint m2_len
) {
    byte_t *ptr_h1 = mput(env, h1, ecc_frost_ristretto255_sha512_SCALARSIZE);
    byte_t *ptr_m1 = mput(env, m1, m1_len);
    byte_t *ptr_m2 = mput(env, m2, m2_len);
    ecc_frost_ristretto255_sha512_H1_2(
        ptr_h1,
        ptr_m1,
        m1_len,
        ptr_m2,
        m2_len
    );
    mget(env, h1, ptr_h1, ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_h1, ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_m1, m1_len);
    mfree(ptr_m2, m2_len);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1frost_1ristretto255_1sha512_1H2(
    JNIEnv *env, jclass cls,
    jbyteArray h2,
    jbyteArray m,
    jint m_len
) {
    byte_t *ptr_h2 = mput(env, h2, ecc_frost_ristretto255_sha512_SCALARSIZE);
    byte_t *ptr_m = mput(env, m, m_len);
    ecc_frost_ristretto255_sha512_H2(
        ptr_h2,
        ptr_m,
        m_len
    );
    mget(env, h2, ptr_h2, ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_h2, ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_m, m_len);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1frost_1ristretto255_1sha512_1H2_13(
    JNIEnv *env, jclass cls,
    jbyteArray h2,
    jbyteArray m1,
    jint m1_len,
    jbyteArray m2,
    jint m2_len,
    jbyteArray m3,
    jint m3_len
) {
    byte_t *ptr_h2 = mput(env, h2, ecc_frost_ristretto255_sha512_SCALARSIZE);
    byte_t *ptr_m1 = mput(env, m1, m1_len);
    byte_t *ptr_m2 = mput(env, m2, m2_len);
    byte_t *ptr_m3 = mput(env, m3, m3_len);
    ecc_frost_ristretto255_sha512_H2_3(
        ptr_h2,
        ptr_m1,
        m1_len,
        ptr_m2,
        m2_len,
        ptr_m3,
        m3_len
    );
    mget(env, h2, ptr_h2, ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_h2, ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_m1, m1_len);
    mfree(ptr_m2, m2_len);
    mfree(ptr_m3, m3_len);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1frost_1ristretto255_1sha512_1H3(
    JNIEnv *env, jclass cls,
    jbyteArray h3,
    jbyteArray m,
    jint m_len
) {
    byte_t *ptr_h3 = mput(env, h3, ecc_frost_ristretto255_sha512_SCALARSIZE);
    byte_t *ptr_m = mput(env, m, m_len);
    ecc_frost_ristretto255_sha512_H3(
        ptr_h3,
        ptr_m,
        m_len
    );
    mget(env, h3, ptr_h3, ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_h3, ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_m, m_len);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1frost_1ristretto255_1sha512_1H3_12(
    JNIEnv *env, jclass cls,
    jbyteArray h3,
    jbyteArray m1,
    jint m1_len,
    jbyteArray m2,
    jint m2_len
) {
    byte_t *ptr_h3 = mput(env, h3, ecc_frost_ristretto255_sha512_SCALARSIZE);
    byte_t *ptr_m1 = mput(env, m1, m1_len);
    byte_t *ptr_m2 = mput(env, m2, m2_len);
    ecc_frost_ristretto255_sha512_H3_2(
        ptr_h3,
        ptr_m1,
        m1_len,
        ptr_m2,
        m2_len
    );
    mget(env, h3, ptr_h3, ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_h3, ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_m1, m1_len);
    mfree(ptr_m2, m2_len);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1frost_1ristretto255_1sha512_1H4(
    JNIEnv *env, jclass cls,
    jbyteArray h4,
    jbyteArray m,
    jint m_len
) {
    byte_t *ptr_h4 = mput(env, h4, 64);
    byte_t *ptr_m = mput(env, m, m_len);
    ecc_frost_ristretto255_sha512_H4(
        ptr_h4,
        ptr_m,
        m_len
    );
    mget(env, h4, ptr_h4, 64);
    mfree(ptr_h4, 64);
    mfree(ptr_m, m_len);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1frost_1ristretto255_1sha512_1H5(
    JNIEnv *env, jclass cls,
    jbyteArray h5,
    jbyteArray m,
    jint m_len
) {
    byte_t *ptr_h5 = mput(env, h5, 64);
    byte_t *ptr_m = mput(env, m, m_len);
    ecc_frost_ristretto255_sha512_H5(
        ptr_h5,
        ptr_m,
        m_len
    );
    mget(env, h5, ptr_h5, 64);
    mfree(ptr_h5, 64);
    mfree(ptr_m, m_len);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1frost_1ristretto255_1sha512_1prime_1order_1sign(
    JNIEnv *env, jclass cls,
    jbyteArray signature,
    jbyteArray msg,
    jint msg_len,
    jbyteArray SK
) {
    byte_t *ptr_signature = mput(env, signature, ecc_frost_ristretto255_sha512_SIGNATURESIZE);
    byte_t *ptr_msg = mput(env, msg, msg_len);
    byte_t *ptr_SK = mput(env, SK, ecc_frost_ristretto255_sha512_SECRETKEYSIZE);
    ecc_frost_ristretto255_sha512_prime_order_sign(
        ptr_signature,
        ptr_msg,
        msg_len,
        ptr_SK
    );
    mget(env, signature, ptr_signature, ecc_frost_ristretto255_sha512_SIGNATURESIZE);
    mfree(ptr_signature, ecc_frost_ristretto255_sha512_SIGNATURESIZE);
    mfree(ptr_msg, msg_len);
    mfree(ptr_SK, ecc_frost_ristretto255_sha512_SECRETKEYSIZE);
}

JNIEXPORT int JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1frost_1ristretto255_1sha512_1prime_1order_1verify(
    JNIEnv *env, jclass cls,
    jbyteArray msg,
    jint msg_len,
    jbyteArray signature,
    jbyteArray PK
) {
    byte_t *ptr_msg = mput(env, msg, msg_len);
    byte_t *ptr_signature = mput(env, signature, ecc_frost_ristretto255_sha512_SIGNATURESIZE);
    byte_t *ptr_PK = mput(env, PK, ecc_frost_ristretto255_sha512_PUBLICKEYSIZE);
    const int fun_ret = ecc_frost_ristretto255_sha512_prime_order_verify(
        ptr_msg,
        msg_len,
        ptr_signature,
        ptr_PK
    );
    mfree(ptr_msg, msg_len);
    mfree(ptr_signature, ecc_frost_ristretto255_sha512_SIGNATURESIZE);
    mfree(ptr_PK, ecc_frost_ristretto255_sha512_PUBLICKEYSIZE);
    return fun_ret;
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1frost_1ristretto255_1sha512_1trusted_1dealer_1keygen_1with_1coefficients(
    JNIEnv *env, jclass cls,
    jbyteArray participant_private_keys,
    jbyteArray group_public_key,
    jbyteArray vss_commitment,
    jbyteArray polynomial_coefficients,
    jbyteArray secret_key,
    jint n,
    jint t,
    jbyteArray coefficients
) {
    byte_t *ptr_participant_private_keys = mput(env, participant_private_keys, n*ecc_frost_ristretto255_sha512_POINTSIZE);
    byte_t *ptr_group_public_key = mput(env, group_public_key, ecc_frost_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_vss_commitment = mput(env, vss_commitment, t*ecc_frost_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_polynomial_coefficients = mput(env, polynomial_coefficients, t*ecc_frost_ristretto255_sha512_SCALARSIZE);
    byte_t *ptr_secret_key = mput(env, secret_key, ecc_frost_ristretto255_sha512_SCALARSIZE);
    byte_t *ptr_coefficients = mput(env, coefficients, (t-1)*ecc_frost_ristretto255_sha512_SCALARSIZE);
    ecc_frost_ristretto255_sha512_trusted_dealer_keygen_with_coefficients(
        ptr_participant_private_keys,
        ptr_group_public_key,
        ptr_vss_commitment,
        ptr_polynomial_coefficients,
        ptr_secret_key,
        n,
        t,
        ptr_coefficients
    );
    mget(env, participant_private_keys, ptr_participant_private_keys, n*ecc_frost_ristretto255_sha512_POINTSIZE);
    mget(env, group_public_key, ptr_group_public_key, ecc_frost_ristretto255_sha512_ELEMENTSIZE);
    mget(env, vss_commitment, ptr_vss_commitment, t*ecc_frost_ristretto255_sha512_ELEMENTSIZE);
    mget(env, polynomial_coefficients, ptr_polynomial_coefficients, t*ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_participant_private_keys, n*ecc_frost_ristretto255_sha512_POINTSIZE);
    mfree(ptr_group_public_key, ecc_frost_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_vss_commitment, t*ecc_frost_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_polynomial_coefficients, t*ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_secret_key, ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_coefficients, (t-1)*ecc_frost_ristretto255_sha512_SCALARSIZE);
}

JNIEXPORT int JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1frost_1ristretto255_1sha512_1secret_1share_1shard(
    JNIEnv *env, jclass cls,
    jbyteArray secret_key_shares,
    jbyteArray polynomial_coefficients,
    jbyteArray s,
    jbyteArray coefficients,
    jint n,
    jint t
) {
    byte_t *ptr_secret_key_shares = mput(env, secret_key_shares, n*ecc_frost_ristretto255_sha512_POINTSIZE);
    byte_t *ptr_polynomial_coefficients = mput(env, polynomial_coefficients, t*ecc_frost_ristretto255_sha512_SCALARSIZE);
    byte_t *ptr_s = mput(env, s, ecc_frost_ristretto255_sha512_SCALARSIZE);
    byte_t *ptr_coefficients = mput(env, coefficients, (t-1)*ecc_frost_ristretto255_sha512_SCALARSIZE);
    const int fun_ret = ecc_frost_ristretto255_sha512_secret_share_shard(
        ptr_secret_key_shares,
        ptr_polynomial_coefficients,
        ptr_s,
        ptr_coefficients,
        n,
        t
    );
    mget(env, secret_key_shares, ptr_secret_key_shares, n*ecc_frost_ristretto255_sha512_POINTSIZE);
    mget(env, polynomial_coefficients, ptr_polynomial_coefficients, t*ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_secret_key_shares, n*ecc_frost_ristretto255_sha512_POINTSIZE);
    mfree(ptr_polynomial_coefficients, t*ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_s, ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_coefficients, (t-1)*ecc_frost_ristretto255_sha512_SCALARSIZE);
    return fun_ret;
}

JNIEXPORT int JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1frost_1ristretto255_1sha512_1secret_1share_1combine(
    JNIEnv *env, jclass cls,
    jbyteArray s,
    jbyteArray shares,
    jint shares_len
) {
    byte_t *ptr_s = mput(env, s, ecc_frost_ristretto255_sha512_SCALARSIZE);
    byte_t *ptr_shares = mput(env, shares, shares_len*ecc_frost_ristretto255_sha512_POINTSIZE);
    const int fun_ret = ecc_frost_ristretto255_sha512_secret_share_combine(
        ptr_s,
        ptr_shares,
        shares_len
    );
    mget(env, s, ptr_s, ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_s, ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_shares, shares_len*ecc_frost_ristretto255_sha512_POINTSIZE);
    return fun_ret;
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1frost_1ristretto255_1sha512_1polynomial_1evaluate(
    JNIEnv *env, jclass cls,
    jbyteArray value,
    jbyteArray x,
    jbyteArray coeffs,
    jint coeffs_len
) {
    byte_t *ptr_value = mput(env, value, ecc_frost_ristretto255_sha512_SCALARSIZE);
    byte_t *ptr_x = mput(env, x, ecc_frost_ristretto255_sha512_SCALARSIZE);
    byte_t *ptr_coeffs = mput(env, coeffs, coeffs_len*ecc_frost_ristretto255_sha512_SCALARSIZE);
    ecc_frost_ristretto255_sha512_polynomial_evaluate(
        ptr_value,
        ptr_x,
        ptr_coeffs,
        coeffs_len
    );
    mget(env, value, ptr_value, ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_value, ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_x, ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_coeffs, coeffs_len*ecc_frost_ristretto255_sha512_SCALARSIZE);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1frost_1ristretto255_1sha512_1polynomial_1interpolate_1constant(
    JNIEnv *env, jclass cls,
    jbyteArray f_zero,
    jbyteArray points,
    jint points_len
) {
    byte_t *ptr_f_zero = mput(env, f_zero, ecc_frost_ristretto255_sha512_SCALARSIZE);
    byte_t *ptr_points = mput(env, points, points_len*ecc_frost_ristretto255_sha512_POINTSIZE);
    ecc_frost_ristretto255_sha512_polynomial_interpolate_constant(
        ptr_f_zero,
        ptr_points,
        points_len
    );
    mget(env, f_zero, ptr_f_zero, ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_f_zero, ecc_frost_ristretto255_sha512_SCALARSIZE);
    mfree(ptr_points, points_len*ecc_frost_ristretto255_sha512_POINTSIZE);
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1frost_1ristretto255_1sha512_1vss_1commit(
    JNIEnv *env, jclass cls,
    jbyteArray vss_commitment,
    jbyteArray coeffs,
    jint coeffs_len
) {
    byte_t *ptr_vss_commitment = mput(env, vss_commitment, coeffs_len*ecc_frost_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_coeffs = mput(env, coeffs, coeffs_len*ecc_frost_ristretto255_sha512_SCALARSIZE);
    ecc_frost_ristretto255_sha512_vss_commit(
        ptr_vss_commitment,
        ptr_coeffs,
        coeffs_len
    );
    mget(env, vss_commitment, ptr_vss_commitment, coeffs_len*ecc_frost_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_vss_commitment, coeffs_len*ecc_frost_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_coeffs, coeffs_len*ecc_frost_ristretto255_sha512_SCALARSIZE);
}

JNIEXPORT int JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1frost_1ristretto255_1sha512_1vss_1verify(
    JNIEnv *env, jclass cls,
    jbyteArray share_i,
    jbyteArray vss_commitment,
    jint t
) {
    byte_t *ptr_share_i = mput(env, share_i, ecc_frost_ristretto255_sha512_POINTSIZE);
    byte_t *ptr_vss_commitment = mput(env, vss_commitment, t*ecc_frost_ristretto255_sha512_ELEMENTSIZE);
    const int fun_ret = ecc_frost_ristretto255_sha512_vss_verify(
        ptr_share_i,
        ptr_vss_commitment,
        t
    );
    mfree(ptr_share_i, ecc_frost_ristretto255_sha512_POINTSIZE);
    mfree(ptr_vss_commitment, t*ecc_frost_ristretto255_sha512_ELEMENTSIZE);
    return fun_ret;
}

JNIEXPORT void JNICALL Java_org_ssohub_crypto_ecc_libecc_ecc_1frost_1ristretto255_1sha512_1derive_1group_1info(
    JNIEnv *env, jclass cls,
    jbyteArray PK,
    jbyteArray participant_public_keys,
    jint n,
    jint t,
    jbyteArray vss_commitment
) {
    byte_t *ptr_PK = mput(env, PK, ecc_frost_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_participant_public_keys = mput(env, participant_public_keys, n*ecc_frost_ristretto255_sha512_ELEMENTSIZE);
    byte_t *ptr_vss_commitment = mput(env, vss_commitment, t*ecc_frost_ristretto255_sha512_ELEMENTSIZE);
    ecc_frost_ristretto255_sha512_derive_group_info(
        ptr_PK,
        ptr_participant_public_keys,
        n,
        t,
        ptr_vss_commitment
    );
    mget(env, PK, ptr_PK, ecc_frost_ristretto255_sha512_ELEMENTSIZE);
    mget(env, participant_public_keys, ptr_participant_public_keys, n*ecc_frost_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_PK, ecc_frost_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_participant_public_keys, n*ecc_frost_ristretto255_sha512_ELEMENTSIZE);
    mfree(ptr_vss_commitment, t*ecc_frost_ristretto255_sha512_ELEMENTSIZE);
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

