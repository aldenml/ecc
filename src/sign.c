/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#include "sign.h"
#include <assert.h>
#include <sodium.h>
#include <blst.h>
#include "util.h"

static_assert(sizeof(blst_scalar) == ecc_sign_bls12_381_PRIVATEKEYSIZE, "");

void ecc_sign_ed25519_sign(byte_t *sig, const byte_t *msg, int msg_len, const byte_t *sk) {
    crypto_sign_ed25519_detached(sig, NULL, msg, msg_len, sk);
}

int ecc_sign_ed25519_verify(const byte_t *sig, const byte_t *msg, int msg_len, const byte_t *pk) {
    return crypto_sign_ed25519_verify_detached(sig, msg, msg_len, pk);
}

void ecc_sign_ed25519_keypair(byte_t *pk, byte_t *sk) {
    crypto_sign_ed25519_keypair(pk, sk);
}

void ecc_sign_ed25519_seed_keypair(byte_t *pk, byte_t *sk, const byte_t *seed) {
    crypto_sign_ed25519_seed_keypair(pk, sk, seed);
}

void ecc_sign_ed25519_sk_to_seed(byte_t *seed, const byte_t *sk) {
    crypto_sign_ed25519_sk_to_seed(seed, sk);
}

void ecc_sign_ed25519_sk_to_pk(byte_t *pk, const byte_t *sk) {
    crypto_sign_ed25519_sk_to_pk(pk, sk);
}

void ecc_sign_bls12_381_KeyGen(byte_t *sk, const byte_t *ikm, int ikm_len) {
    blst_keygen((blst_scalar *) sk, ikm, ikm_len, 0, 0);
}

void ecc_sign_bls12_381_SkToPk(byte_t *pk, const byte_t *sk) {
    blst_p1 p;
    blst_sk_to_pk_in_g1(&p, (blst_scalar *) sk);
    blst_p1_compress(pk, &p);
    // cleanup stack memory
    ecc_memzero((byte_t *) &p, sizeof p);
}

int ecc_sign_bls12_381_KeyValidate(const byte_t *pk) {
    // 1. xP = pubkey_to_point(PK)
    // 2. If xP is INVALID, return INVALID
    // 3. If xP is the identity element, return INVALID
    // 4. If pubkey_subgroup_check(xP) is INVALID, return INVALID
    // 5. return VALID

    // 1. xP = pubkey_to_point(PK)
    blst_p1_affine p;
    if (blst_p1_uncompress(&p, pk) != BLST_SUCCESS)
        return -1;

    // TODO: check for identity

    // cleanup stack memory
    ecc_memzero((byte_t *) &p, sizeof p);

    return 0;
}

void ecc_sign_bls12_381_CoreSign(
    byte_t *sig,
    const byte_t *msg, int msg_len,
    const byte_t *sk
) {
    // 1. Q = hash_to_point(message)
    // 2. R = SK * Q
    // 3. signature = point_to_signature(R)
    // 4. return signature

    byte_t DST[43] = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
    blst_p2 Q;
    blst_hash_to_g2(&Q, msg, msg_len, DST, sizeof DST, NULL, 0);
    blst_p2 R;
    blst_sign_pk_in_g1(&R, &Q, (blst_scalar *) sk);

    blst_p2_compress(sig, &R);

    // cleanup stack memory
    ecc_memzero((byte_t *) &Q, sizeof Q);
    ecc_memzero((byte_t *) &R, sizeof R);
}

int ecc_sign_bls12_381_CoreVerify(
    const byte_t *pk,
    const byte_t *msg, int msg_len,
    const byte_t *sig
) {
    // 1. R = signature_to_point(signature)
    // 2. If R is INVALID, return INVALID
    // 3. If signature_subgroup_check(R) is INVALID, return INVALID
    // 4. If KeyValidate(PK) is INVALID, return INVALID
    // 5. xP = pubkey_to_point(PK)
    // 6. Q = hash_to_point(message)
    // 7. C1 = pairing(Q, xP)
    // 8. C2 = pairing(R, P)
    // 9. If C1 == C2, return VALID, else return INVALID

    byte_t DST[43] = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

    blst_p2_affine R;
    if (blst_p2_uncompress(&R, sig) != BLST_SUCCESS)
        return -1;
    if (ecc_sign_bls12_381_KeyValidate(pk) != 0)
        return -1;
    blst_p1_affine xP;
    blst_p1_uncompress(&xP, pk);

    int r = blst_core_verify_pk_in_g1(
        &xP, &R, 1,
        msg, msg_len,
        DST, sizeof DST,
        NULL, 0
    );

    return r == BLST_SUCCESS ? 0 : -1;
}

int ecc_sign_bls12_381_Aggregate(
    byte_t *sig,
    const byte_t **signatures, int n
) {
    // 1. aggregate = signature_to_point(signature_1)
    // 2. If aggregate is INVALID, return INVALID
    // 3. for i in 2, ..., n:
    // 4.     next = signature_to_point(signature_i)
    // 5.     If next is INVALID, return INVALID
    // 6.     aggregate = aggregate + next
    // 7. signature = point_to_signature(aggregate)
    // 8. return signature

    blst_p2_affine first;
    if (blst_p2_uncompress(&first, sig) != BLST_SUCCESS)
        return -1;

    blst_p2 aggregate;
    blst_p2_from_affine(&aggregate, &first);

    blst_p2_affine next;
    for (int i = 1; i < n; i++) {
        if (blst_p2_uncompress(&next, sig) != BLST_SUCCESS)
            return -1;

        blst_p2_add_affine(&aggregate, &aggregate, &next);
    }

    blst_p2_compress(sig, &aggregate);

    // cleanup stack memory
    ecc_memzero((byte_t *) &first, sizeof first);
    ecc_memzero((byte_t *) &aggregate, sizeof aggregate);
    ecc_memzero((byte_t *) &next, sizeof next);

    return 0;
}
