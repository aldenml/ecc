/*
 * Copyright (c) 2022, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#include "frost.h"
#include <assert.h>
#include <stdint.h>
#include "util.h"
#include "ristretto255.h"

#define Ne ecc_ristretto255_ELEMENTSIZE

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

typedef uint64_t SignerID;

typedef struct {
    SignerID id;
    byte_t D[Ne];
    byte_t E[Ne];
} SigningCommitment_t;

static_assert(ecc_frost_ristretto255_sha512_SCALARSIZE == ecc_ristretto255_SCALARSIZE, "");
static_assert(ecc_frost_ristretto255_sha512_SECRETKEYSIZE == ecc_ristretto255_SCALARSIZE, "");
static_assert(ecc_frost_ristretto255_sha512_PUBLICKEYSIZE == ecc_ristretto255_ELEMENTSIZE, "");
static_assert(ecc_frost_ristretto255_sha512_POINTSIZE == 2 * ecc_ristretto255_SCALARSIZE, "");
static_assert(ecc_frost_ristretto255_sha512_NONCEPAIRSIZE == 2 * ecc_ristretto255_SCALARSIZE, "");
static_assert(ecc_frost_ristretto255_sha512_NONCECOMMITMENTPAIRSIZE == 2 * ecc_ristretto255_ELEMENTSIZE, "");
static_assert(ecc_frost_ristretto255_sha512_SIGNINGCOMMITMENTPAIRSIZE == 8 + 2 * ecc_ristretto255_ELEMENTSIZE, "");

static_assert(sizeof(Point_t) == ecc_frost_ristretto255_sha512_POINTSIZE, "");
static_assert(sizeof(NoncePair_t) == ecc_frost_ristretto255_sha512_NONCEPAIRSIZE, "");
static_assert(sizeof(NonceCommitmentPair_t) == ecc_frost_ristretto255_sha512_NONCECOMMITMENTPAIRSIZE, "");
static_assert(sizeof(NonceCommitmentPair_t) == ecc_frost_ristretto255_sha512_NONCECOMMITMENTPAIRSIZE, "");
static_assert(sizeof(SignerID) == 8, "");
static_assert(sizeof(SigningCommitment_t) == ecc_frost_ristretto255_sha512_SIGNINGCOMMITMENTPAIRSIZE, "");

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
