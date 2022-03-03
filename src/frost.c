/*
 * Copyright (c) 2022, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#include "frost.h"
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include "util.h"
#include "hash.h"
#include "ristretto255.h"

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
    byte_t R[ecc_ristretto255_ELEMENTSIZE];
    byte_t z[ecc_ristretto255_SCALARSIZE];
} Signature_t;

typedef struct {
    byte_t x[ecc_frost_ristretto255_sha512_SCALARSIZE];
    byte_t y[ecc_frost_ristretto255_sha512_SCALARSIZE];
} Point_t;

typedef struct {
    byte_t hiding_nonce[ecc_ristretto255_SCALARSIZE];
    byte_t binding_nonce[ecc_ristretto255_SCALARSIZE];
} NoncePair_t;

typedef struct {
    byte_t hiding_nonce_commitment[ecc_ristretto255_ELEMENTSIZE];
    byte_t binding_nonce_commitment[ecc_ristretto255_ELEMENTSIZE];
} NonceCommitmentPair_t;

typedef struct {
    byte_t index[2];
    byte_t hiding_nonce_commitment[ecc_ristretto255_ELEMENTSIZE];
    byte_t binding_nonce_commitment[ecc_ristretto255_ELEMENTSIZE];
} SigningCommitment_t;

static_assert(ecc_frost_ristretto255_sha512_SCALARSIZE == ecc_ristretto255_SCALARSIZE, "");
static_assert(ecc_frost_ristretto255_sha512_ELEMENTSIZE == ecc_ristretto255_ELEMENTSIZE, "");
static_assert(ecc_frost_ristretto255_sha512_SECRETKEYSIZE == ecc_ristretto255_SCALARSIZE, "");
static_assert(ecc_frost_ristretto255_sha512_PUBLICKEYSIZE == ecc_ristretto255_ELEMENTSIZE, "");
static_assert(ecc_frost_ristretto255_sha512_SIGNATURESIZE == 2 * ecc_ristretto255_SCALARSIZE, "");
static_assert(ecc_frost_ristretto255_sha512_POINTSIZE == 2 * ecc_ristretto255_SCALARSIZE, "");
static_assert(ecc_frost_ristretto255_sha512_NONCEPAIRSIZE == 2 * ecc_ristretto255_SCALARSIZE, "");
static_assert(ecc_frost_ristretto255_sha512_NONCECOMMITMENTPAIRSIZE == 2 * ecc_ristretto255_ELEMENTSIZE, "");
static_assert(ecc_frost_ristretto255_sha512_SIGNINGCOMMITMENTSIZE == 2 + 2 * ecc_ristretto255_ELEMENTSIZE, "");

static_assert(sizeof(Signature_t) == ecc_frost_ristretto255_sha512_SIGNATURESIZE, "");
static_assert(sizeof(Point_t) == ecc_frost_ristretto255_sha512_POINTSIZE, "");
static_assert(sizeof(NoncePair_t) == ecc_frost_ristretto255_sha512_NONCEPAIRSIZE, "");
static_assert(sizeof(NonceCommitmentPair_t) == ecc_frost_ristretto255_sha512_NONCECOMMITMENTPAIRSIZE, "");
static_assert(sizeof(SigningCommitment_t) == ecc_frost_ristretto255_sha512_SIGNINGCOMMITMENTSIZE, "");

void ecc_frost_ristretto255_sha512_H1(
    byte_t *h1,
    const byte_t *m, const int m_len
) {
    byte_t contextString[28] = "FROST-RISTRETTO255-SHA512rho";

    byte_t digest[ecc_hash_sha512_HASHSIZE];
    crypto_hash_sha512_state st;
    crypto_hash_sha512_init(&st);
    crypto_hash_sha512_update(&st, contextString, sizeof contextString);
    crypto_hash_sha512_update(&st, m, (unsigned long long) m_len);
    crypto_hash_sha512_final(&st, digest);

    ecc_ristretto255_scalar_reduce(h1, digest);

    // cleanup stack memory
    ecc_memzero(digest, sizeof digest);
    ecc_memzero((byte_t *) &st, sizeof st);
}

void ecc_frost_ristretto255_sha512_H1_2(
    byte_t *h1,
    const byte_t *m1, const int m1_len,
    const byte_t *m2, const int m2_len
) {
    byte_t contextString[28] = "FROST-RISTRETTO255-SHA512rho";

    byte_t digest[ecc_hash_sha512_HASHSIZE];
    crypto_hash_sha512_state st;
    crypto_hash_sha512_init(&st);
    crypto_hash_sha512_update(&st, contextString, sizeof contextString);
    crypto_hash_sha512_update(&st, m1, (unsigned long long) m1_len);
    crypto_hash_sha512_update(&st, m2, (unsigned long long) m2_len);
    crypto_hash_sha512_final(&st, digest);

    ecc_ristretto255_scalar_reduce(h1, digest);

    // cleanup stack memory
    ecc_memzero(digest, sizeof digest);
    ecc_memzero((byte_t *) &st, sizeof st);
}

void ecc_frost_ristretto255_sha512_H2(
    byte_t *h2,
    const byte_t *m, const int m_len
) {
    byte_t contextString[29] = "FROST-RISTRETTO255-SHA512chal";

    byte_t digest[ecc_hash_sha512_HASHSIZE];
    crypto_hash_sha512_state st;
    crypto_hash_sha512_init(&st);
    crypto_hash_sha512_update(&st, contextString, sizeof contextString);
    crypto_hash_sha512_update(&st, m, (unsigned long long) m_len);
    crypto_hash_sha512_final(&st, digest);

    ecc_ristretto255_scalar_reduce(h2, digest);

    // cleanup stack memory
    ecc_memzero(digest, sizeof digest);
    ecc_memzero((byte_t *) &st, sizeof st);
}

void ecc_frost_ristretto255_sha512_H2_3(
    byte_t *h2,
    const byte_t *m1, const int m1_len,
    const byte_t *m2, const int m2_len,
    const byte_t *m3, const int m3_len
) {
    byte_t contextString[29] = "FROST-RISTRETTO255-SHA512chal";

    byte_t digest[ecc_hash_sha512_HASHSIZE];
    crypto_hash_sha512_state st;
    crypto_hash_sha512_init(&st);
    crypto_hash_sha512_update(&st, contextString, sizeof contextString);
    crypto_hash_sha512_update(&st, m1, (unsigned long long) m1_len);
    crypto_hash_sha512_update(&st, m2, (unsigned long long) m2_len);
    crypto_hash_sha512_update(&st, m3, (unsigned long long) m3_len);
    crypto_hash_sha512_final(&st, digest);

    ecc_ristretto255_scalar_reduce(h2, digest);

    // cleanup stack memory
    ecc_memzero(digest, sizeof digest);
    ecc_memzero((byte_t *) &st, sizeof st);
}

void ecc_frost_ristretto255_sha512_H3(
    byte_t *h3,
    const byte_t *m, const int m_len
) {
    byte_t contextString[31] = "FROST-RISTRETTO255-SHA512digest";

    crypto_hash_sha512_state st;
    crypto_hash_sha512_init(&st);
    crypto_hash_sha512_update(&st, contextString, sizeof contextString);
    crypto_hash_sha512_update(&st, m, (unsigned long long) m_len);
    crypto_hash_sha512_final(&st, h3);

    // cleanup stack memory
    ecc_memzero((byte_t *) &st, sizeof st);
}

void ecc_frost_ristretto255_sha512_schnorr_signature_generate(
    byte_t *signature_ptr,
    const byte_t *msg, const int msg_len,
    const byte_t *SK
) {
//    PK = G.ScalarBaseMult(SK)
//    k = G.RandomScalar()
//    R = G.ScalarBaseMult(k)
//
//    comm_enc = G.SerializeElement(R)
//    pk_enc = G.SerializeElement(PK)
//    challenge_input = comm_enc || pk_enc || msg
//    c = H2(challenge_input)
//
//    z = k + (c * SK)
//    return (R, z)

    Signature_t *signature = (Signature_t *) signature_ptr;

    byte_t PK[ecc_ristretto255_ELEMENTSIZE];
    ecc_ristretto255_scalarmult_base(PK, SK);
    byte_t k[ecc_ristretto255_SCALARSIZE];
    ecc_ristretto255_scalar_random(k);
    byte_t R[ecc_ristretto255_ELEMENTSIZE];
    ecc_ristretto255_scalarmult_base(R, k);

    byte_t c[ecc_ristretto255_SCALARSIZE];
    ecc_frost_ristretto255_sha512_H2_3(
        c,
        R, sizeof R,
        PK, sizeof PK,
        msg, sizeof msg_len
    );

    // z = k + (c * SK)
    byte_t t[ecc_ristretto255_SCALARSIZE];
    ecc_ristretto255_scalar_mul(t, c, SK); // c * SK
    byte_t z[ecc_ristretto255_SCALARSIZE];
    ecc_ristretto255_scalar_add(z, k, t); // k + (c * SK)

#if ECC_LOG
    ecc_log("schnorr_signature_generate:PK", PK, sizeof PK);
    ecc_log("schnorr_signature_generate:c", c, sizeof c);
    ecc_log("schnorr_signature_generate:R", R, sizeof R);
    ecc_log("schnorr_signature_generate:z", z, sizeof z);
#endif

    memcpy(signature->R, R, sizeof R);
    memcpy(signature->z, z, sizeof z);

    // cleanup stack memory
    ecc_memzero(PK, sizeof PK);
    ecc_memzero(k, sizeof k);
    ecc_memzero(R, sizeof R);
    ecc_memzero(c, sizeof c);
    ecc_memzero(t, sizeof t);
    ecc_memzero(z, sizeof z);
}

int ecc_frost_ristretto255_sha512_schnorr_signature_verify(
    const byte_t *msg, const int msg_len,
    const byte_t *signature_ptr,
    const byte_t *PK
) {
//    comm_enc = G.SerializeElement(R)
//    pk_enc = G.SerializeElement(PK)
//    challenge_input = comm_enc || pk_enc || msg
//    c = H2(challenge_input)
//
//    l = G.ScalarBaseMult(z)
//    r = R + (c * PK)
//    if l == r:
//      return 1
//    return 0

    const Signature_t *signature = (const Signature_t *) signature_ptr;

    byte_t c[ecc_ristretto255_SCALARSIZE];
    ecc_frost_ristretto255_sha512_H2_3(
        c,
        signature->R, sizeof signature->R,
        PK, ecc_frost_ristretto255_sha512_PUBLICKEYSIZE,
        msg, sizeof msg_len
    );

#if ECC_LOG
    ecc_log("schnorr_signature_generate:PK", PK, ecc_frost_ristretto255_sha512_PUBLICKEYSIZE);
    ecc_log("schnorr_signature_verify:c", c, sizeof c);
    ecc_log("schnorr_signature_generate:R", signature->R, sizeof signature->R);
    ecc_log("schnorr_signature_generate:z", signature->z, sizeof signature->z);
#endif

    byte_t l[ecc_ristretto255_ELEMENTSIZE];
    ecc_ristretto255_scalarmult_base(l, signature->z);

    // r = R + (c * PK)
    byte_t t[ecc_ristretto255_ELEMENTSIZE];
    ecc_ristretto255_scalarmult(t, c, PK); // c * PK
    byte_t r[ecc_ristretto255_ELEMENTSIZE];
    ecc_ristretto255_add(r, signature->R, t); // R + (c * PK)

    int cmp = ecc_compare(l, r, ecc_ristretto255_ELEMENTSIZE);

    // cleanup stack memory
    ecc_memzero(c, sizeof c);
    ecc_memzero(l, sizeof l);
    ecc_memzero(t, sizeof t);
    ecc_memzero(r, sizeof r);

    if (cmp == 0)
        return 1;
    return 0;
}

void ecc_frost_ristretto255_sha512_polynomial_evaluate(
    byte_t *value,
    const byte_t *x,
    const byte_t *coeffs, const int coeffs_len
) {
    // https://en.wikipedia.org/wiki/Horner%27s_method

    ecc_memzero(value, ecc_frost_ristretto255_sha512_SCALARSIZE);

    for (int i = coeffs_len - 1; i >= 1; i--) {
        ecc_ristretto255_scalar_add(value, value, &coeffs[i * ecc_frost_ristretto255_sha512_SCALARSIZE]);
        ecc_ristretto255_scalar_mul(value, value, x);
    }

    ecc_ristretto255_scalar_add(value, value, &coeffs[0]);
}

void ecc_frost_ristretto255_sha512_derive_lagrange_coefficient(
    byte_t *L_i,
    const byte_t *x_i,
    const byte_t *L, const int L_len
) {
    byte_t numerator[ecc_frost_ristretto255_sha512_SCALARSIZE] = {1, 0};
    byte_t denominator[ecc_frost_ristretto255_sha512_SCALARSIZE] = {1, 0};

    byte_t t[ecc_frost_ristretto255_sha512_SCALARSIZE];

    for (int n = 0; n < L_len; n++) {
        const byte_t *x_j = &L[n * ecc_frost_ristretto255_sha512_SCALARSIZE];
        if (ecc_compare(x_j, x_i, ecc_frost_ristretto255_sha512_SCALARSIZE) == 0) continue;

        // numerator *= x_j
        // denominator *= x_j - x_i

        ecc_ristretto255_scalar_mul(numerator, numerator, x_j);

        ecc_ristretto255_scalar_sub(t, x_j, x_i);
        ecc_ristretto255_scalar_mul(denominator, denominator, t);
    }

    // L_i = numerator / denominator
    byte_t denominator_inv[ecc_frost_ristretto255_sha512_SCALARSIZE];
    ecc_ristretto255_scalar_invert(denominator_inv, denominator);
    ecc_ristretto255_scalar_mul(L_i, numerator, denominator_inv);

    // cleanup stack memory
    ecc_memzero(numerator, sizeof numerator);
    ecc_memzero(denominator, sizeof denominator);
    ecc_memzero(t, sizeof t);
    ecc_memzero(denominator_inv, sizeof denominator_inv);
}

void ecc_frost_ristretto255_sha512_derive_lagrange_coefficient_with_points(
    byte_t *L_i,
    const byte_t *x_i,
    const byte_t *L, const int L_len
) {
    byte_t numerator[ecc_frost_ristretto255_sha512_SCALARSIZE] = {1, 0};
    byte_t denominator[ecc_frost_ristretto255_sha512_SCALARSIZE] = {1, 0};

    byte_t t[ecc_frost_ristretto255_sha512_SCALARSIZE];

    for (int n = 0; n < L_len; n++) {
        const Point_t *point = (const Point_t *) &L[n * ecc_frost_ristretto255_sha512_POINTSIZE];
        const byte_t *x_j = point->x;
        if (ecc_compare(x_j, x_i, ecc_frost_ristretto255_sha512_SCALARSIZE) == 0) continue;

        // numerator *= x_j
        // denominator *= x_j - x_i

        ecc_ristretto255_scalar_mul(numerator, numerator, x_j);

        ecc_ristretto255_scalar_sub(t, x_j, x_i);
        ecc_ristretto255_scalar_mul(denominator, denominator, t);
    }

    // L_i = numerator / denominator
    byte_t denominator_inv[ecc_frost_ristretto255_sha512_SCALARSIZE];
    ecc_ristretto255_scalar_invert(denominator_inv, denominator);
    ecc_ristretto255_scalar_mul(L_i, numerator, denominator_inv);

    // cleanup stack memory
    ecc_memzero(numerator, sizeof numerator);
    ecc_memzero(denominator, sizeof denominator);
    ecc_memzero(t, sizeof t);
    ecc_memzero(denominator_inv, sizeof denominator_inv);
}

void ecc_frost_ristretto255_sha512_polynomial_interpolation(
    byte_t *constant_term,
    const byte_t *points, const int points_len
) {
    // f_zero = F(0)
    // for point in points:
    //   delta = point.y * derive_lagrange_coefficient(point.x, L)
    //   f_zero = f_zero + delta

    ecc_memzero(constant_term, ecc_frost_ristretto255_sha512_SCALARSIZE);

    byte_t L_i[ecc_frost_ristretto255_sha512_SCALARSIZE];
    byte_t delta[ecc_frost_ristretto255_sha512_SCALARSIZE];

    for (int i = 0; i < points_len; i++) {
        const Point_t *point = (const Point_t *) &points[i * ecc_frost_ristretto255_sha512_POINTSIZE];

        ecc_frost_ristretto255_sha512_derive_lagrange_coefficient_with_points(L_i, point->x, points, points_len);
        ecc_ristretto255_scalar_mul(delta, point->y, L_i);

        ecc_ristretto255_scalar_add(constant_term, constant_term, delta);
    }

    // cleanup stack memory
    ecc_memzero(L_i, sizeof L_i);
    ecc_memzero(delta, sizeof delta);
}

void ecc_frost_ristretto255_sha512_compute_binding_factor(
    byte_t *binding_factor,
    const byte_t *encoded_commitment_list, const int encoded_commitment_list_len,
    const byte_t *msg, const int msg_len
) {
    byte_t msg_hash[64];
    ecc_frost_ristretto255_sha512_H3(msg_hash, msg, msg_len);

    ecc_frost_ristretto255_sha512_H1_2(
        binding_factor,
        encoded_commitment_list, encoded_commitment_list_len * ecc_frost_ristretto255_sha512_SIGNINGCOMMITMENTSIZE,
        msg_hash, sizeof msg_hash
    );

    // cleanup stack memory
    ecc_memzero(msg_hash, sizeof msg_hash);
}

void ecc_frost_ristretto255_sha512_compute_challenge(
    byte_t *challenge,
    const byte_t *group_commitment,
    const byte_t *group_public_key,
    const byte_t *msg, const int msg_len
) {
    ecc_frost_ristretto255_sha512_H2_3(
        challenge,
        group_commitment, ecc_frost_ristretto255_sha512_ELEMENTSIZE,
        group_public_key, ecc_ristretto255_ELEMENTSIZE,
        msg, msg_len
    );
}

void ecc_frost_ristretto255_sha512_commit_with_nonce(
    byte_t *comm_ptr,
    const byte_t *nonce_ptr
) {
    // hiding_nonce_commitment = G.ScalarBaseMult(hiding_nonce)
    // binding_nonce_commitment = G.ScalarBaseMult(binding_nonce)
    // nonce = (hiding_nonce, binding_nonce)
    // comm = (hiding_nonce_commitment, binding_nonce_commitment)
    // return (nonce, comm)

    NonceCommitmentPair_t *comm = (NonceCommitmentPair_t *) comm_ptr;
    const NoncePair_t *nonce = (const NoncePair_t *) nonce_ptr;

    ecc_ristretto255_scalarmult_base(comm->hiding_nonce_commitment, nonce->hiding_nonce);
    ecc_ristretto255_scalarmult_base(comm->binding_nonce_commitment, nonce->binding_nonce);
}

void ecc_frost_ristretto255_sha512_commit(
    byte_t *nonce_ptr,
    byte_t *comm
) {
    // hiding_nonce = G.RandomScalar()
    // binding_nonce = G.RandomScalar()
    // hiding_nonce_commitment = G.ScalarBaseMult(hiding_nonce)
    // binding_nonce_commitment = G.ScalarBaseMult(binding_nonce)
    // nonce = (hiding_nonce, binding_nonce)
    // comm = (hiding_nonce_commitment, binding_nonce_commitment)
    // return (nonce, comm)

    NoncePair_t *nonce = (NoncePair_t *) nonce_ptr;

    ecc_ristretto255_scalar_random(nonce->hiding_nonce);
    ecc_ristretto255_scalar_random(nonce->binding_nonce);

    ecc_frost_ristretto255_sha512_commit_with_nonce(comm, nonce_ptr);
}

void ecc_frost_ristretto255_sha512_group_commitment(
    byte_t *group_comm,
    const byte_t *commitment_list, const int commitment_list_len,
    const byte_t *binding_factor
) {
    ecc_memzero(group_comm, ecc_frost_ristretto255_sha512_ELEMENTSIZE);

    byte_t T[ecc_ristretto255_ELEMENTSIZE];

    for (int i = 0; i < commitment_list_len; i++) {
        const int pos = i * ecc_frost_ristretto255_sha512_SIGNINGCOMMITMENTSIZE;
        const SigningCommitment_t *comm = (const SigningCommitment_t *) &commitment_list[pos];

        // for (_, D_i, E_i) in commitment_list:
        //   group_comm = group_comm + (D_i + (E_i * binding_factor))
        ecc_ristretto255_scalarmult(T, binding_factor, comm->binding_nonce_commitment);
        ecc_ristretto255_add(T, comm->hiding_nonce_commitment, T);
        ecc_ristretto255_add(group_comm, group_comm, T);
    }

    // cleanup stack memory
    ecc_memzero(T, sizeof T);
}

void ecc_frost_ristretto255_sha512_sign(
    byte_t *sig_share,
    byte_t *comm_share,
    const int index,
    const byte_t *sk_i,
    const byte_t *group_public_key,
    const byte_t *nonce_i_ptr,
    const byte_t *comm_i_ptr,
    const byte_t *msg, const int msg_len,
    const byte_t *commitment_list, const int commitment_list_len,
    const byte_t *participant_list, const int participant_list_len
) {

    const NoncePair_t *nonce_i = (const NoncePair_t *) nonce_i_ptr;
    const NonceCommitmentPair_t *comm_i = (const NonceCommitmentPair_t *) comm_i_ptr;

    byte_t binding_factor[32];
    ecc_frost_ristretto255_sha512_compute_binding_factor(
        binding_factor,
        commitment_list, commitment_list_len,
        msg, msg_len
    );
#if ECC_LOG
    ecc_log("sign, binding_factor", binding_factor, sizeof binding_factor);
#endif

    // Compute the group commitment
    byte_t group_commitment[ecc_ristretto255_ELEMENTSIZE];
    ecc_frost_ristretto255_sha512_group_commitment(
        group_commitment,
        commitment_list, commitment_list_len,
        binding_factor
    );
#if ECC_LOG
    ecc_log("sign, group_commitment", group_commitment, sizeof group_commitment);
#endif

    // lambda_i = derive_lagrange_coefficient(index, participant_list)
    byte_t lambda_i[ecc_ristretto255_SCALARSIZE];
    byte_t x_i[ecc_ristretto255_SCALARSIZE] = {(byte_t) index, 0};
    ecc_frost_ristretto255_sha512_derive_lagrange_coefficient(
        lambda_i,
        x_i,
        participant_list, participant_list_len
    );
#if ECC_LOG
    ecc_log("sign, lambda_i", lambda_i, sizeof lambda_i);
#endif

    // Compute the per-message challenge
    byte_t challenge[32];
    ecc_frost_ristretto255_sha512_compute_challenge(
        challenge,
        group_commitment,
        group_public_key,
        msg, msg_len
    );
#if ECC_LOG
    ecc_log("sign, challenge", challenge, sizeof challenge);
#endif

//    # Compute the signature share
//    (hiding_nonce, binding_nonce) = nonce_i
//    sig_share = hiding_nonce + (binding_nonce * binding_factor) + (lambda_i * sk_i * c)
    byte_t t1[ecc_ristretto255_SCALARSIZE];
    byte_t t2[ecc_ristretto255_SCALARSIZE];
    ecc_ristretto255_scalar_mul(t1, lambda_i, sk_i);
    ecc_ristretto255_scalar_mul(t1, t1, challenge);
    ecc_ristretto255_scalar_mul(t2, nonce_i->binding_nonce, binding_factor);
    ecc_ristretto255_scalar_add(sig_share, nonce_i->hiding_nonce, t1);
    ecc_ristretto255_scalar_add(sig_share, sig_share, t2);

    // Compute the commitment share
//    (hiding_nonce_commitment, binding_nonce_commitment) = comm_i
//    comm_share = hiding_nonce_commitment + (binding_nonce_commitment * binding_factor)
    byte_t T[ecc_ristretto255_ELEMENTSIZE];
    ecc_ristretto255_scalarmult(T, binding_factor, comm_i->binding_nonce_commitment);
    ecc_ristretto255_add(comm_share, comm_i->hiding_nonce_commitment, T);

    // cleanup stack memory
    ecc_memzero(binding_factor, sizeof binding_factor);
    ecc_memzero(group_commitment, sizeof group_commitment);
    ecc_memzero(lambda_i, sizeof lambda_i);
    ecc_memzero(x_i, sizeof x_i);
    ecc_memzero(challenge, sizeof challenge);
    ecc_memzero(t1, sizeof t1);
    ecc_memzero(t2, sizeof t2);
    ecc_memzero(T, sizeof T);
}

int ecc_frost_ristretto255_sha512_verify_signature_share(
    const int index,
    const byte_t *public_key_share_i,
    const byte_t *comm_i_ptr,
    const byte_t *sig_share_i,
    const byte_t *commitment_list, const int commitment_list_len,
    const byte_t *participant_list, const int participant_list_len,
    const byte_t *group_public_key,
    const byte_t *msg, const int msg_len
) {
    const NonceCommitmentPair_t *comm_i = (const NonceCommitmentPair_t *) comm_i_ptr;

    byte_t binding_factor[32];
    ecc_frost_ristretto255_sha512_compute_binding_factor(
        binding_factor,
        commitment_list, commitment_list_len,
        msg, msg_len
    );
#if ECC_LOG
    ecc_log("verify_signature_share, binding_factor", binding_factor, sizeof binding_factor);
#endif

    // Compute the group commitment
    byte_t group_commitment[ecc_ristretto255_ELEMENTSIZE];
    ecc_frost_ristretto255_sha512_group_commitment(
        group_commitment,
        commitment_list, commitment_list_len,
        binding_factor
    );
#if ECC_LOG
    ecc_log("verify_signature_share, group_commitment", group_commitment, sizeof group_commitment);
#endif

    // # Compute the commitment share
    // (hiding_nonce_commitment, binding_nonce_commitment) = comm_i
    // comm_share = hiding_nonce_commitment + (binding_nonce_commitment * binding_factor)
    byte_t T[ecc_ristretto255_ELEMENTSIZE];
    byte_t comm_share[ecc_ristretto255_ELEMENTSIZE];
    ecc_ristretto255_scalarmult(T, binding_factor, comm_i->binding_nonce_commitment);
    ecc_ristretto255_add(comm_share, comm_i->hiding_nonce_commitment, T);
#if ECC_LOG
    ecc_log("verify_signature_share, binding_nonce_commitment", comm_i->binding_nonce_commitment, sizeof comm_i->binding_nonce_commitment);
    ecc_log("verify_signature_share, comm_share", comm_share, sizeof comm_share);
#endif

    // Compute the per-message challenge
    byte_t challenge[32];
    ecc_frost_ristretto255_sha512_compute_challenge(
        challenge,
        group_commitment,
        group_public_key,
        msg, msg_len
    );
#if ECC_LOG
    ecc_log("verify_signature_share, challenge", challenge, sizeof challenge);
#endif

    // l = G.ScalarBaseMult(sig_share)
    byte_t l[ecc_ristretto255_ELEMENTSIZE];
    ecc_ristretto255_scalarmult_base(l, sig_share_i);

    // lambda_i = derive_lagrange_coefficient(index, participant_list)
    byte_t lambda_i[ecc_ristretto255_SCALARSIZE];
    byte_t x_i[ecc_ristretto255_SCALARSIZE] = {(byte_t) index, 0};
    ecc_frost_ristretto255_sha512_derive_lagrange_coefficient(
        lambda_i,
        x_i,
        participant_list, participant_list_len
    );

    // r = comm_share + (PK_i * c * lambda_i)
    byte_t t[ecc_ristretto255_SCALARSIZE];
    byte_t r[ecc_ristretto255_ELEMENTSIZE];
    ecc_ristretto255_scalar_mul(t, challenge, lambda_i);
    ecc_ristretto255_scalarmult(r, t, public_key_share_i);
    ecc_ristretto255_add(r, comm_share, r);

    // return l == r
    // 1 if the signature share is valid, and 0 otherwise.
    int cmp = ecc_compare(l, r, ecc_ristretto255_ELEMENTSIZE);

    // cleanup stack memory
    ecc_memzero(binding_factor, sizeof binding_factor);
    ecc_memzero(group_commitment, sizeof group_commitment);
    ecc_memzero(T, sizeof T);
    ecc_memzero(comm_share, sizeof comm_share);
    ecc_memzero(challenge, sizeof challenge);
    ecc_memzero(l, sizeof l);
    ecc_memzero(lambda_i, sizeof lambda_i);
    ecc_memzero(x_i, sizeof x_i);
    ecc_memzero(t, sizeof t);
    ecc_memzero(r, sizeof r);

    return cmp == 0 ? 1 : 0;
}

void ecc_frost_ristretto255_sha512_trusted_dealer_keygen_with_secret_and_coefficients(
    byte_t *public_key,
    byte_t *secret_key_shares,
    const int n,
    const int t,
    const byte_t *secret_key,
    const byte_t *coefficients
) {
    ecc_frost_ristretto255_sha512_secret_share_shard_with_coefficients(
        secret_key_shares,
        n,
        t,
        coefficients
    );
    ecc_ristretto255_scalarmult_base(public_key, secret_key);
}

void ecc_frost_ristretto255_sha512_trusted_dealer_keygen(
    byte_t *secret_key,
    byte_t *public_key,
    byte_t *secret_key_shares,
    const int n,
    const int t
) {
    ecc_ristretto255_scalar_random(secret_key);

    byte_t coefficients[1024];
    memcpy(coefficients, secret_key, ecc_ristretto255_SCALARSIZE);
    for (int i = 1; i < t; i++) {
        const int pos = i * ecc_ristretto255_SCALARSIZE;
        ecc_ristretto255_scalar_random(&coefficients[pos]);
    }

    ecc_frost_ristretto255_sha512_trusted_dealer_keygen_with_secret_and_coefficients(
        public_key,
        secret_key_shares,
        n,
        t,
        secret_key,
        coefficients
    );

    // cleanup stack memory
    ecc_memzero(coefficients, sizeof coefficients);
}

void ecc_frost_ristretto255_sha512_secret_share_shard_with_coefficients(
    byte_t *points,
    const int n,
    const int t,
    const byte_t *coefficients
) {
    byte_t y_i[ecc_ristretto255_SCALARSIZE];

    for (int i = 1; i <= n; i++) {
        byte_t x_i[ecc_ristretto255_SCALARSIZE] = {(byte_t) i, 0};

        ecc_frost_ristretto255_sha512_polynomial_evaluate(y_i, x_i, coefficients, t);
        const int pos = (i - 1) * ecc_frost_ristretto255_sha512_POINTSIZE;
        Point_t *point_i = (Point_t *) &points[pos];
#if ECC_LOG
        ecc_log("y_i", y_i, ecc_ristretto255_SCALARSIZE);
#endif
        memcpy(point_i->x, x_i, ecc_ristretto255_SCALARSIZE);
        memcpy(point_i->y, y_i, ecc_ristretto255_SCALARSIZE);
    }

    // cleanup stack memory
    ecc_memzero(y_i, sizeof y_i);
}

void ecc_frost_ristretto255_sha512_secret_share_shard(
    byte_t *points,
    const byte_t *s,
    const int n,
    const int t
) {
    byte_t coefficients[1024];
    memcpy(coefficients, s, ecc_ristretto255_SCALARSIZE);
    for (int i = 1; i < t; i++) {
        const int pos = i * ecc_ristretto255_SCALARSIZE;
        ecc_ristretto255_scalar_random(&coefficients[pos]);
    }

    ecc_frost_ristretto255_sha512_secret_share_shard_with_coefficients(
        points,
        n,
        t,
        coefficients
    );

    // cleanup stack memory
    ecc_memzero(coefficients, sizeof coefficients);
}

void ecc_frost_ristretto255_sha512_frost_aggregate(
    byte_t *signature_ptr,
    const byte_t *group_commitment,
    const byte_t *sig_shares, const int sig_shares_len
) {
//    z = 0
//    for z_i in sig_shares:
//      z = z + z_i
//    return (R, z)

    Signature_t *signature = (Signature_t *) signature_ptr;

    byte_t z[ecc_ristretto255_SCALARSIZE] = {0};
    for (int i = 0; i < sig_shares_len; i++) {
        const int pos = i * ecc_frost_ristretto255_sha512_SCALARSIZE;
        const byte_t *z_i = &sig_shares[pos];
        ecc_ristretto255_scalar_add(z, z, z_i);
    }

    memcpy(signature->R, group_commitment, ecc_frost_ristretto255_sha512_ELEMENTSIZE);
    memcpy(signature->z, z, sizeof z);

    // cleanup stack memory
    ecc_memzero(z, sizeof z);
}
