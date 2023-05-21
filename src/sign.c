/*
 * Copyright (c) 2021-2023, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#include "sign.h"
#include <assert.h>
#include <string.h>
#include <sodium.h>
#include <blst.h>
#include "util.h"
#include "bls12_381.h"

static_assert(sizeof(blst_scalar) == ecc_sign_eth_bls_PRIVATEKEYSIZE, "");

void ecc_sign_ed25519_Sign(byte_t *signature, const byte_t *message, const int message_len, const byte_t *sk) {
    crypto_sign_ed25519_detached(signature, NULL, message, (unsigned long long) message_len, sk);
}

int ecc_sign_ed25519_Verify(const byte_t *signature, const byte_t *message, const int message_len, const byte_t *pk) {
    return crypto_sign_ed25519_verify_detached(signature, message, (unsigned long long) message_len, pk);
}

void ecc_sign_ed25519_KeyPair(byte_t *pk, byte_t *sk) {
    crypto_sign_ed25519_keypair(pk, sk);
}

void ecc_sign_ed25519_SeedKeyPair(byte_t *pk, byte_t *sk, const byte_t *seed) {
    crypto_sign_ed25519_seed_keypair(pk, sk, seed);
}

void ecc_sign_ed25519_SkToSeed(byte_t *seed, const byte_t *sk) {
    crypto_sign_ed25519_sk_to_seed(seed, sk);
}

void ecc_sign_ed25519_SkToPk(byte_t *pk, const byte_t *sk) {
    crypto_sign_ed25519_sk_to_pk(pk, sk);
}

void ecc_sign_eth_bls_KeyGen(
    byte_t *sk,
    const byte_t *ikm, const int ikm_len,
    const byte_t *salt, const int salt_len,
    const byte_t *key_info, const int key_info_len
) {
    blst_scalar bsk;
    blst_keygen_v5(
        &bsk,
        ikm, (size_t) ikm_len,
        salt, (size_t) salt_len,
        key_info, (size_t) key_info_len
    );
    blst_bendian_from_scalar(sk, &bsk);

    // cleanup stack memory
    ecc_memzero((byte_t *) &bsk, sizeof bsk);
}

void ecc_sign_eth_bls_SkToPk(byte_t *pk, const byte_t *sk) {
    blst_scalar bsk;
    blst_scalar_from_bendian(&bsk, sk);

    blst_p1 bpk;
    blst_sk_to_pk_in_g1(&bpk,  &bsk);
    blst_p1_compress(pk, &bpk);

    // cleanup stack memory
    ecc_memzero((byte_t *) &bsk, sizeof bsk);
    ecc_memzero((byte_t *) &bpk, sizeof bpk);
}

int ecc_sign_eth_bls_KeyValidate(const byte_t *pk) {
    // 1. xP = pubkey_to_point(PK)
    // 2. If xP is INVALID, return INVALID
    // 3. If xP is the identity element, return INVALID
    // 4. If pubkey_subgroup_check(xP) is INVALID, return INVALID
    // 5. return VALID

    blst_p1_affine p_affine;
    if (blst_p1_uncompress(&p_affine, pk) != BLST_SUCCESS)
        return -1;

    blst_p1 p;
    blst_p1_from_affine(&p, &p_affine);

    if (blst_p1_is_inf(&p))
        return -1;

    if (!blst_p1_in_g1(&p))
        return -1;

    return 0;
}

void ecc_sign_eth_bls_Sign(
    byte_t *signature,
    const byte_t *sk,
    const byte_t *message, const int message_len
) {
    blst_scalar bsk;
    blst_scalar_from_bendian(&bsk, sk);

    byte_t DST[43] = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
    blst_p2 Q;
    blst_hash_to_g2(&Q, message, (size_t) message_len, DST, sizeof DST, NULL, 0);
    blst_p2 sig;
    blst_sign_pk_in_g1(&sig, &Q, &bsk);

    blst_p2_compress(signature, &sig);

    // cleanup stack memory
    ecc_memzero((byte_t *) &bsk, sizeof bsk);
    ecc_memzero((byte_t *) &Q, sizeof Q);
    ecc_memzero((byte_t *) &sig, sizeof sig);
}

int ecc_sign_eth_bls_Verify(
    const byte_t *pk,
    const byte_t *message, const int message_len,
    const byte_t *signature
) {
    if (ecc_sign_eth_bls_KeyValidate(pk) != 0)
        return -1;

    byte_t DST[43] = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

    blst_p2_affine sig;
    if (blst_p2_uncompress(&sig, signature) != BLST_SUCCESS)
        return -1;
    if (!blst_p2_affine_in_g2(&sig))
        return -1;

    blst_p1_affine bpk;
    blst_p1_uncompress(&bpk, pk);

    const BLST_ERROR r = blst_core_verify_pk_in_g1(
        &bpk, &sig, 1,
        message, (size_t) message_len,
        DST, sizeof DST,
        NULL, 0
    );

    return r == BLST_SUCCESS ? 0 : -1;
}

int ecc_sign_eth_bls_Aggregate(
    byte_t *signature,
    const byte_t *signatures, int n
) {
    blst_p2 aggregate;
    if (blst_aggregate_in_g2(&aggregate, NULL, &signatures[0]) != BLST_SUCCESS)
        return -1;

    for (int i = 1; i < n; i++) {
        if (blst_aggregate_in_g2(
            &aggregate,
            &aggregate,
            &signatures[i * ecc_sign_eth_bls_SIGNATURESIZE]
        ) != BLST_SUCCESS)
            return -1;
    }

    blst_p2_compress(signature, &aggregate);

    return 0;
}

int ecc_sign_eth_bls_FastAggregateVerify(
    const byte_t *pks, const int n,
    const byte_t *message, const int message_len,
    const byte_t *signature
) {
    if (n < 1)
        return -1;
    // NOTE: the caller MUST know a proof of possession for all PK_i, and the
    // result of evaluating PopVerify on PK_i and this proof MUST be VALID.

    byte_t DST[43] = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

    blst_p2_affine sig;
    if (blst_p2_uncompress(&sig, signature) != BLST_SUCCESS)
        return -1;
    if (!blst_p2_affine_in_g2(&sig))
        return -1;

    blst_p1_affine first;
    if (blst_p1_uncompress(&first, &pks[0]) != BLST_SUCCESS)
        return -1;
    if (!blst_p1_affine_in_g1(&first))
        return -1;

    blst_p1 aggregate;
    blst_p1_from_affine(&aggregate, &first);

    blst_p1_affine next;
    for (int i = 1; i < n; i++) {
        if (blst_p1_uncompress(&next, &pks[i * ecc_sign_eth_bls_PUBLICKEYSIZE]) != BLST_SUCCESS)
            return -1;
        if (!blst_p1_affine_in_g1(&first))
            return -1;

        blst_p1_add_affine(&aggregate, &aggregate, &next);
    }

    blst_p1_affine pk;
    blst_p1_to_affine(&pk, &aggregate);

    const BLST_ERROR r = blst_core_verify_pk_in_g1(
        &pk, &sig, 1,
        message, (size_t) message_len,
        DST, sizeof DST,
        NULL, 0
    );

    return r == BLST_SUCCESS ? 0 : -1;
}

int ecc_sign_eth_bls_AggregateVerify(
    const int n,
    const byte_t *pks,
    const byte_t *messages, const int messages_len,
    const byte_t *signature
) {
    ECC_UNUSED(messages_len);

    byte_t DST[43] = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

    blst_p2_affine sig;
    if (blst_p2_uncompress(&sig, signature) != BLST_SUCCESS)
        return -1;
    if (!blst_p2_affine_in_g2(&sig))
        return -1;

    blst_fp12 C1;
    memcpy(&C1, blst_fp12_one(), ecc_bls12_381_FP12SIZE);

    blst_p1_affine pk;
    int message_offset = 0;
    for (int i = 0; i < n; i++) {
#if ECC_LOG
        ecc_log("pk", &pks[i * ecc_sign_eth_bls_PUBLICKEYSIZE], ecc_sign_eth_bls_PUBLICKEYSIZE);
        ecc_log("message",  &messages[message_offset + 1], messages[message_offset]);
#endif
        if (ecc_sign_eth_bls_KeyValidate(&pks[i * ecc_sign_eth_bls_PUBLICKEYSIZE]) != 0)
            return -1;
        blst_p1_uncompress(&pk, &pks[i * ecc_sign_eth_bls_PUBLICKEYSIZE]);

        blst_p2 Q;
        blst_hash_to_g2(&Q, &messages[message_offset + 1], messages[message_offset], DST, sizeof DST, NULL, 0);
        blst_p2_affine Q_affine;
        blst_p2_to_affine(&Q_affine, &Q);

        // C1 = C1 * pairing(Q, xP)
        blst_fp12 pairing;
        blst_miller_loop(&pairing, &Q_affine, &pk);
        blst_fp12_mul(&C1, &C1, &pairing);

        message_offset += (1 + messages[message_offset]);
    }

    // C2 = pairing(R, P)
    blst_fp12 C2;
    blst_miller_loop(&C2, &sig, blst_p1_affine_generator());
    if (!blst_fp12_finalverify(&C1, &C2))
        return -1;

    return 0;
}
