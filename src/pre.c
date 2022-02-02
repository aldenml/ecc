/*
 * Copyright (c) 2021-2022, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#include "pre.h"
#include <string.h>
#include <assert.h>
#include <blst.h>
#include "util.h"
#include "hash.h"
#include "ed25519.h"
#include "bls12_381.h"
#include "h2c.h"
#include "sign.h"

#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcpp"
#endif

#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wcpp"
#endif

#include <sodium.h>

#ifdef __clang__
#pragma clang diagnostic pop
#endif

#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

typedef struct {
    byte_t epk[ecc_pre_schema1_PUBLICKEYSIZE];
    byte_t em[ecc_pre_schema1_MESSAGESIZE];
    byte_t ah[ecc_hash_sha256_HASHSIZE];
    byte_t spk_i[ecc_pre_schema1_SIGNINGPUBLICKEYSIZE];
    byte_t sig[ecc_pre_schema1_SIGNATURESIZE];
} CiphertextLevel1_t;

typedef struct {
    CiphertextLevel1_t C_i;
    byte_t tpk[ecc_pre_schema1_PUBLICKEYSIZE];
    byte_t eK[ecc_pre_schema1_MESSAGESIZE];
    byte_t rpk[ecc_pre_schema1_PUBLICKEYSIZE];
    byte_t reK[ecc_pre_schema1_MESSAGESIZE];
    byte_t spk[ecc_pre_schema1_SIGNINGPUBLICKEYSIZE];
    byte_t sig[ecc_pre_schema1_SIGNATURESIZE];
} CiphertextLevel2_t;

typedef struct {
    byte_t tpk[ecc_pre_schema1_PUBLICKEYSIZE];
    byte_t eK[ecc_pre_schema1_MESSAGESIZE];
    byte_t spk_i[ecc_pre_schema1_SIGNINGPUBLICKEYSIZE];
    byte_t sig[ecc_pre_schema1_SIGNATURESIZE];
    byte_t tep[ecc_bls12_381_G2SIZE];
} ReKey_t;

static_assert(
    ecc_pre_schema1_CIPHERTEXTLEVEL1SIZE ==
    ecc_pre_schema1_PUBLICKEYSIZE +
    ecc_pre_schema1_MESSAGESIZE +
    32 + // 32 is ecc_hash_sha256_HASHSIZE
    ecc_pre_schema1_SIGNINGPUBLICKEYSIZE +
    ecc_pre_schema1_SIGNATURESIZE,
    "");
static_assert(
    ecc_pre_schema1_CIPHERTEXTLEVEL2SIZE ==
    ecc_pre_schema1_CIPHERTEXTLEVEL1SIZE +
    ecc_pre_schema1_PUBLICKEYSIZE +
    ecc_pre_schema1_MESSAGESIZE +
    ecc_pre_schema1_PUBLICKEYSIZE +
    ecc_pre_schema1_MESSAGESIZE +
    ecc_pre_schema1_SIGNINGPUBLICKEYSIZE +
    ecc_pre_schema1_SIGNATURESIZE,
    "");
static_assert(
    ecc_pre_schema1_REKEYSIZE ==
    ecc_pre_schema1_PUBLICKEYSIZE +
    ecc_pre_schema1_MESSAGESIZE +
    ecc_pre_schema1_SIGNINGPUBLICKEYSIZE +
    ecc_pre_schema1_SIGNATURESIZE +
    ecc_bls12_381_G2SIZE,
    "");

static_assert(sizeof(CiphertextLevel1_t) == ecc_pre_schema1_CIPHERTEXTLEVEL1SIZE, "");
static_assert(sizeof(CiphertextLevel2_t) == ecc_pre_schema1_CIPHERTEXTLEVEL2SIZE, "");
static_assert(sizeof(ReKey_t) == ecc_pre_schema1_REKEYSIZE, "");

void pairing_g2(byte_t *e, const byte_t *p, const byte_t *s);
void pairing_g2_mul(byte_t *r, const byte_t *a, const byte_t *p, const byte_t *s);
void pairing_g2_mul_neg(byte_t *r, const byte_t *a, const byte_t *p, const byte_t *s);
void hash2(byte_t *r, const byte_t *a);
void hash2_neg(byte_t *r, const byte_t *a);

void ecc_pre_schema1_MessageGen(
    byte_t *m
) {
    ecc_bls12_381_fp12_random(m);
}

void ecc_pre_schema1_DeriveKey(
    byte_t *pk, byte_t *sk,
    const byte_t *seed
) {
    byte_t dst[21] = "PRE-SCHEMA1-DeriveKey";
    byte_t s[ecc_bls12_381_SCALARSIZE];
    ecc_h2c_expand_message_xmd_sha256(
        s,
        seed, ecc_pre_schema1_SEEDSIZE,
        dst, sizeof dst,
        sizeof s
    );

    // the secret key
    blst_scalar_from_le_bytes((blst_scalar *) sk, s, sizeof s);

    // public key pk = sk * g
    ecc_bls12_381_g1_scalarmult_base(pk, sk);

    // cleanup stack memory
    ecc_memzero(s, sizeof s);
}

void ecc_pre_schema1_KeyGen(
    byte_t *pk,
    byte_t *sk
) {
    byte_t seed[ecc_pre_schema1_SEEDSIZE];
    ecc_randombytes(seed, sizeof seed);

    ecc_pre_schema1_DeriveKey(pk, sk, seed);

    // cleanup stack memory
    ecc_memzero(seed, sizeof seed);
}

void ecc_pre_schema1_DeriveSigningKey(
    byte_t *spk, byte_t *ssk,
    const byte_t *seed
) {
    byte_t dst[28] = "PRE-SCHEMA1-DeriveSigningKey";
    byte_t s[ecc_sign_ed25519_SEEDSIZE];
    ecc_h2c_expand_message_xmd_sha256(
        s,
        seed, ecc_pre_schema1_SEEDSIZE,
        dst, sizeof dst,
        sizeof s
    );

    ecc_sign_ed25519_SeedKeyPair(spk, ssk, s);

    // cleanup stack memory
    ecc_memzero(s, sizeof s);
}

void ecc_pre_schema1_SigningKeyGen(
    byte_t *spk,
    byte_t *ssk
) {
    byte_t seed[ecc_pre_schema1_SEEDSIZE];
    ecc_randombytes(seed, sizeof seed);

    ecc_pre_schema1_DeriveSigningKey(spk, ssk, seed);

    // cleanup stack memory
    ecc_memzero(seed, sizeof seed);
}

// helper functions

/**
 * Calculates the pairing e(p, s * g2).
 *
 * @param e (output) the result
 * @param p point in G1
 * @param s scalar
 */
void pairing_g2(byte_t *e, const byte_t *p, const byte_t *s) {
    byte_t sg2[ecc_bls12_381_G2SIZE]; // s * g2
    ecc_bls12_381_g2_scalarmult_base(sg2, s);
    ecc_bls12_381_pairing(e, p, sg2);

    // cleanup stack memory
    ecc_memzero(sg2, sizeof sg2);
}

/**
 * Calculates the pairing and multiplication a * e(p, s * g2).
 *
 * @param r (output) the result
 * @param a multiplication factor
 * @param p point in G1
 * @param s scalar
 */
void pairing_g2_mul(byte_t *r, const byte_t *a, const byte_t *p, const byte_t *s) {
    byte_t e[ecc_bls12_381_FP12SIZE];
    pairing_g2(e, p, s);
    ecc_bls12_381_fp12_mul(r, a, e);

    // cleanup stack memory
    ecc_memzero(e, sizeof e);
}

/**
 * Calculates the pairing and multiplication a * e(p, (-s) * g2).
 *
 * @param r (output) the result
 * @param a multiplication factor
 * @param p point in G1
 * @param s scalar
 */
void pairing_g2_mul_neg(byte_t *r, const byte_t *a, const byte_t *p, const byte_t *s) {
    byte_t sg2[ecc_bls12_381_G2SIZE]; // sg2 = s * g2
    ecc_bls12_381_g2_scalarmult_base(sg2, s);
    ecc_bls12_381_g2_negate(sg2, sg2); // sg2 = (-s) * g2
    byte_t e[ecc_bls12_381_FP12SIZE];
    ecc_bls12_381_pairing(e, p, sg2);
    ecc_bls12_381_fp12_mul(r, a, e);

    // cleanup stack memory
    ecc_memzero(sg2, sizeof sg2);
    ecc_memzero(e, sizeof e);
}

/**
 * Calculates the H2(a), H2:Fp12 -> G2
 *
 * @param r (output) the result
 * @param a the element in Fp12
 */
void hash2(byte_t *r, const byte_t *a) {
    blst_p2 p;
    blst_hash_to_g2(
        &p,
        a, ecc_bls12_381_FP12SIZE,
        NULL, 0,
        NULL, 0
    );
    blst_p2_compress(r, &p);

    // cleanup stack memory
    ecc_memzero((byte_t *) &p, sizeof p);
}

/**
 * Calculates the -H2(a), H2:Fp12 -> G2
 *
 * @param r (output) the result
 * @param a the element in Fp12
 */
void hash2_neg(byte_t *r, const byte_t *a) {
    blst_p2 p;
    blst_hash_to_g2(
        &p,
        a, ecc_bls12_381_FP12SIZE,
        NULL, 0,
        NULL, 0
    );
    blst_p2_cneg(&p, 1);
    blst_p2_compress(r, &p);

    // cleanup stack memory
    ecc_memzero((byte_t *) &p, sizeof p);
}

void ecc_pre_schema1_EncryptWithSeed(
    byte_t *C_j_raw,
    const byte_t *m,
    const byte_t *pk_j,
    const byte_t *spk_i,
    const byte_t *ssk_i,
    const byte_t *seed
) {
    CiphertextLevel1_t *C_j = (CiphertextLevel1_t *) C_j_raw;

    // ephemeral key pair (epk, esk)
    byte_t esk[ecc_pre_schema1_PRIVATEKEYSIZE];
    ecc_pre_schema1_DeriveKey(C_j->epk, esk, seed);

    // encrypted message em = m * e(pk_j, g2)^esk
    pairing_g2_mul(C_j->em, m, pk_j, esk);

    // authentication hash ah = SHA256(epk||m)
    crypto_hash_sha256_state ah_st;
    crypto_hash_sha256_init(&ah_st);
    crypto_hash_sha256_update(&ah_st, C_j->epk, sizeof C_j->epk);
    crypto_hash_sha256_update(&ah_st, m, ecc_pre_schema1_MESSAGESIZE);
    crypto_hash_sha256_final(&ah_st, C_j->ah);

    // signature sig = S(epk||em||ah||spk_i, ssk_i)
    memcpy(C_j->spk_i, spk_i, ecc_pre_schema1_SIGNINGPUBLICKEYSIZE);
    crypto_sign_ed25519ph_state sig_st;
    crypto_sign_ed25519ph_init(&sig_st);
    crypto_sign_ed25519ph_update(
        &sig_st,
        (byte_t *) C_j,
        sizeof(CiphertextLevel1_t) - ecc_pre_schema1_SIGNATURESIZE
    );
    crypto_sign_ed25519ph_final_create(&sig_st, C_j->sig, NULL, ssk_i);

    // ciphertext Cj = (epk, em, ah, spk_i, sig)

    // cleanup stack memory
    ecc_memzero(esk, sizeof esk);
    ecc_memzero((byte_t *) &ah_st, sizeof ah_st);
    ecc_memzero((byte_t *) &sig_st, sizeof sig_st);
}

void ecc_pre_schema1_Encrypt(
    byte_t *C_j_raw,
    const byte_t *m,
    const byte_t *pk_j,
    const byte_t *spk_i,
    const byte_t *ssk_i
) {
    byte_t seed[ecc_pre_schema1_SEEDSIZE];
    ecc_randombytes(seed, sizeof seed);

    ecc_pre_schema1_EncryptWithSeed(
        C_j_raw,
        m,
        pk_j,
        spk_i,
        ssk_i,
        seed
    );

    // cleanup stack memory
    ecc_memzero(seed, sizeof seed);
}

void ecc_pre_schema1_ReKeyGen(
    byte_t *tk_i_j_raw,
    const byte_t *sk_i,
    const byte_t *pk_j,
    const byte_t *spk_i,
    const byte_t *ssk_i
) {
    ReKey_t *tk_i_j = (ReKey_t *) tk_i_j_raw;

    // transform key pair (tpk, tsk) = KeyGen
    byte_t tsk[ecc_pre_schema1_PRIVATEKEYSIZE];
    ecc_pre_schema1_KeyGen(tk_i_j->tpk, tsk);

    // transform value K from GT
    byte_t K[ecc_bls12_381_FP12SIZE];
    ecc_bls12_381_fp12_random(K);

    // encrypted transform value eK = K * e(pk_j, g2)^tsk
    pairing_g2_mul(tk_i_j->eK, K, pk_j, tsk);

    // signature sig = S(tpk||eK||spk_i, ssk_i)
    memcpy(tk_i_j->spk_i, spk_i, ecc_pre_schema1_SIGNINGPUBLICKEYSIZE);
    crypto_sign_ed25519ph_state sig_st;
    crypto_sign_ed25519ph_init(&sig_st);
    crypto_sign_ed25519ph_update(
        &sig_st,
        (byte_t *) tk_i_j,
        sizeof(ReKey_t) - ecc_pre_schema1_SIGNATURESIZE - ecc_bls12_381_G2SIZE
    );
    crypto_sign_ed25519ph_final_create(&sig_st, tk_i_j->sig, NULL, ssk_i);

    // transform point tep = H2(K) + (-sk_i) * g2
    byte_t H2K[ecc_bls12_381_G2SIZE];
    hash2(H2K, K);
    byte_t sk_i_times_g2[ecc_bls12_381_G2SIZE];
    ecc_bls12_381_g2_scalarmult_base(sk_i_times_g2, sk_i);
    byte_t sk_i_times_g2_neg[ecc_bls12_381_G2SIZE];
    ecc_bls12_381_g2_negate(sk_i_times_g2_neg, sk_i_times_g2);
    ecc_bls12_381_g2_add(tk_i_j->tep, H2K, sk_i_times_g2_neg);

    // transform key tk_i_j = (tpk, eK, spk_i, sig, tep)

    // cleanup stack memory
    ecc_memzero(tsk, sizeof tsk);
    ecc_memzero(K, sizeof K);
    ecc_memzero((byte_t *) &sig_st, sizeof sig_st);
    ecc_memzero(H2K, sizeof H2K);
    ecc_memzero(sk_i_times_g2, sizeof sk_i_times_g2);
    ecc_memzero(sk_i_times_g2_neg, sizeof sk_i_times_g2_neg);
}

int ecc_pre_schema1_ReEncrypt(
    byte_t *C_j_raw,
    const byte_t *C_i_raw,
    const byte_t *tk_i_j_raw,
    const byte_t *spk_i,
    const byte_t *pk_j,
    const byte_t *spk,
    const byte_t *ssk
) {
    CiphertextLevel2_t *C_j = (CiphertextLevel2_t *) C_j_raw;
    const CiphertextLevel1_t *C_i = (const CiphertextLevel1_t *) C_i_raw;
    const ReKey_t *tk_i_j = (const ReKey_t *) tk_i_j_raw;

    // validate signature of encrypted message
    crypto_sign_ed25519ph_state sig_st;
    crypto_sign_ed25519ph_init(&sig_st);
    crypto_sign_ed25519ph_update(
        &sig_st,
        (const byte_t *) C_i,
        sizeof(CiphertextLevel1_t) - ecc_pre_schema1_SIGNATURESIZE
    );
    if (crypto_sign_ed25519ph_final_verify(&sig_st, C_i->sig, spk_i)) {
        return -1;
    }
    if (ecc_compare(C_i->spk_i, spk_i, ecc_pre_schema1_SIGNINGPUBLICKEYSIZE)) {
        return -1;
    }

    // validate signature of re-encryption key
    crypto_sign_ed25519ph_init(&sig_st);
    crypto_sign_ed25519ph_update(
        &sig_st,
        (const byte_t *) tk_i_j,
        sizeof(ReKey_t) - ecc_pre_schema1_SIGNATURESIZE - ecc_bls12_381_G2SIZE
    );
    if (crypto_sign_ed25519ph_final_verify(&sig_st, tk_i_j->sig, spk_i)) {
        return -1;
    }
    if (ecc_compare(tk_i_j->spk_i, spk_i, ecc_pre_schema1_SIGNINGPUBLICKEYSIZE)) {
        return -1;
    }

    // random key pair (rpk, rsk) = KeyGen
    byte_t rsk[ecc_pre_schema1_PRIVATEKEYSIZE];
    ecc_pre_schema1_KeyGen(C_j->rpk, rsk);

    // random transform value rK from GT
    byte_t rK[ecc_bls12_381_FP12SIZE];
    ecc_bls12_381_fp12_random(rK);

    // random encrypted transform value reK = rK * e(pk_j, g2)^rsk
    pairing_g2_mul(C_j->reK, rK, pk_j, rsk);

    // transformed encrypted message em′ = em * e(epk, tep + H2(rK))
    byte_t H2rK[ecc_bls12_381_G2SIZE];
    hash2(H2rK, rK);
    byte_t tep_plus_H2rK[ecc_bls12_381_G2SIZE];
    ecc_bls12_381_g2_add(tep_plus_H2rK, tk_i_j->tep, H2rK);
    byte_t pairing_em[ecc_bls12_381_FP12SIZE];
    ecc_bls12_381_pairing(pairing_em, C_i->epk, tep_plus_H2rK);
    byte_t em_prima[ecc_bls12_381_FP12SIZE];
    ecc_bls12_381_fp12_mul(em_prima, C_i->em, pairing_em);

    // modified ciphertext C_i′ = (epk, em′, ah)
    // transform block TB = (tpk, eK, rpk, reK)
    // transformed ciphertext C_j = (C_i′, TB)
    memcpy(&C_j->C_i, C_i, sizeof(CiphertextLevel1_t));
    memcpy(C_j->C_i.em, em_prima, sizeof em_prima);
    memcpy(C_j->tpk, tk_i_j->tpk, ecc_pre_schema1_PUBLICKEYSIZE);
    memcpy(C_j->eK, tk_i_j->eK, ecc_pre_schema1_MESSAGESIZE);
    memcpy(C_j->spk, spk, ecc_pre_schema1_SIGNINGPUBLICKEYSIZE);

    // signature sig = S(C_j || spk, ssk)
    // C_j = (C_j, spk, sig)
    crypto_sign_ed25519ph_init(&sig_st);
    crypto_sign_ed25519ph_update(
        &sig_st,
        (byte_t *) C_j,
        sizeof(CiphertextLevel2_t) - ecc_pre_schema1_SIGNATURESIZE
    );
    crypto_sign_ed25519ph_final_create(&sig_st, C_j->sig, NULL, ssk);

    // cleanup stack memory
    ecc_memzero((byte_t *) &sig_st, sizeof sig_st);
    ecc_memzero(rsk, sizeof rsk);
    ecc_memzero(rK, sizeof rK);
    ecc_memzero(H2rK, sizeof H2rK);
    ecc_memzero(tep_plus_H2rK, sizeof tep_plus_H2rK);
    ecc_memzero(pairing_em, sizeof pairing_em);
    ecc_memzero(em_prima, sizeof em_prima);

    return 0;
}

int ecc_pre_schema1_DecryptLevel1(
    byte_t *m,
    const byte_t *C_i_raw,
    const byte_t *sk_i,
    const byte_t *spk_i
) {
    const CiphertextLevel1_t *C_i = (const CiphertextLevel1_t *) C_i_raw;

    // validate the signature on the ciphertext
    crypto_sign_ed25519ph_state sig_st;
    crypto_sign_ed25519ph_init(&sig_st);
    crypto_sign_ed25519ph_update(
        &sig_st,
        (const byte_t *) C_i,
        sizeof(CiphertextLevel1_t) - ecc_pre_schema1_SIGNATURESIZE
    );
    if (crypto_sign_ed25519ph_final_verify(&sig_st, C_i->sig, spk_i)) {
        return -1;
    }
    if (ecc_compare(C_i->spk_i, spk_i, ecc_pre_schema1_SIGNINGPUBLICKEYSIZE)) {
        return -1;
    }

    // decrypt a first-level ciphertext, m = em * e(epk, (-sk_i) * g2)
    pairing_g2_mul_neg(m, C_i->em, C_i->epk, sk_i);

    // cleanup stack memory
    ecc_memzero((byte_t *) &sig_st, sizeof sig_st);

    return 0;
}

int ecc_pre_schema1_DecryptLevel2(
    byte_t *m,
    const byte_t *C_j_raw,
    const byte_t *sk_j,
    const byte_t *spk
) {
    const CiphertextLevel2_t *C_j = (const CiphertextLevel2_t *) C_j_raw;

    // validate the signature on the ciphertext
    crypto_sign_ed25519ph_state sig_st;
    crypto_sign_ed25519ph_init(&sig_st);
    crypto_sign_ed25519ph_update(
        &sig_st,
        (const byte_t *) C_j,
        sizeof(CiphertextLevel2_t) - ecc_pre_schema1_SIGNINGPUBLICKEYSIZE - ecc_pre_schema1_SIGNATURESIZE
    );
    crypto_sign_ed25519ph_update(&sig_st, spk, ecc_pre_schema1_SIGNINGPUBLICKEYSIZE);
    if (crypto_sign_ed25519ph_final_verify(&sig_st, C_j->sig, spk)) {
        return -1;
    }
    if (ecc_compare(C_j->spk, spk, ecc_pre_schema1_SIGNINGPUBLICKEYSIZE)) {
        return -1;
    }

    // K = eK * e(tpk, (-sk_j) * g2)
    byte_t K[ecc_bls12_381_FP12SIZE];
    pairing_g2_mul_neg(K, C_j->eK, C_j->tpk, sk_j);

    // rK = reK * e(rpk, (-sk_j) * g2)
    byte_t rK[ecc_bls12_381_FP12SIZE];
    pairing_g2_mul_neg(rK, C_j->reK, C_j->rpk, sk_j);

    // m = em′ * e(epk, −H2(K) − H2(rK))
    byte_t H2K_neg[ecc_bls12_381_G2SIZE];
    hash2_neg(H2K_neg, K); // −H2(K)
    byte_t H2rK_neg[ecc_bls12_381_G2SIZE];
    hash2_neg(H2rK_neg, rK); // -H2(rK)
    byte_t H2_sum_neg[ecc_bls12_381_G2SIZE];
    ecc_bls12_381_g2_add(H2_sum_neg, H2K_neg, H2rK_neg); // (−H2(K)) + (−H2(rK))
    byte_t pairing_m[ecc_bls12_381_FP12SIZE];
    ecc_bls12_381_pairing(pairing_m, C_j->C_i.epk, H2_sum_neg);
    ecc_bls12_381_fp12_mul(m, C_j->C_i.em, pairing_m);

    // verify SHA256(epk||m) = ah
    byte_t ah[ecc_hash_sha256_HASHSIZE];
    crypto_hash_sha256_state ah_st;
    crypto_hash_sha256_init(&ah_st);
    crypto_hash_sha256_update(&ah_st, C_j->C_i.epk, ecc_pre_schema1_PUBLICKEYSIZE);
    crypto_hash_sha256_update(&ah_st, m, ecc_pre_schema1_MESSAGESIZE);
    crypto_hash_sha256_final(&ah_st, ah);
    int r = ecc_compare(ah, C_j->C_i.ah, ecc_hash_sha256_HASHSIZE);

    // cleanup stack memory
    ecc_memzero((byte_t *) &sig_st, sizeof sig_st);
    ecc_memzero(K, sizeof K);
    ecc_memzero(rK, sizeof rK);
    ecc_memzero(H2K_neg, sizeof H2K_neg);
    ecc_memzero(H2rK_neg, sizeof H2rK_neg);
    ecc_memzero(H2_sum_neg, sizeof H2_sum_neg);
    ecc_memzero(pairing_m, sizeof pairing_m);
    ecc_memzero((byte_t *) &ah_st, sizeof ah_st);

    return r;
}
