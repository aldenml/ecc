/*
 * Copyright (c) 2022, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#ifndef ECC_FROST_H
#define ECC_FROST_H

#include "export.h"

// https://github.com/cfrg/draft-irtf-cfrg-frost
// https://cfrg.github.io/draft-irtf-cfrg-frost/draft-irtf-cfrg-frost.html
// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-frost-01
// https://en.wikipedia.org/wiki/Secure_multi-party_computation

// const
/**
 * Size of a scalar, since this is using the ristretto255
 * curve the size is 32 bytes.
 */
#define ecc_frost_ristretto255_sha512_SCALARSIZE 32

// const
/**
 * Size of an element, since this is using the ristretto255
 * curve the size is 32 bytes.
 */
#define ecc_frost_ristretto255_sha512_ELEMENTSIZE 32

// const
/**
 * Size of a private key, since this is using the ristretto255
 * curve the size is 32 bytes, the size of an scalar.
 */
#define ecc_frost_ristretto255_sha512_SECRETKEYSIZE 32

// const
/**
 * Size of a public key, since this is using the ristretto255
 * curve the size is 32 bytes, the size of a group element.
 */
#define ecc_frost_ristretto255_sha512_PUBLICKEYSIZE 32

// const
/**
 * Size of a schnorr signature, a pair of scalars.
 */
#define ecc_frost_ristretto255_sha512_SIGNATURESIZE 64

// const
/**
 * Size of a scalar point for polynomial evaluation (x, y).
 */
#define ecc_frost_ristretto255_sha512_POINTSIZE 64

// const
/**
 * Size of a nonce tuple.
 */
#define ecc_frost_ristretto255_sha512_NONCEPAIRSIZE 64

// const
/**
 * Size of a nonce commitment tuple.
 */
#define ecc_frost_ristretto255_sha512_NONCECOMMITMENTPAIRSIZE 64

// const
/**
 * Size of a signing commitment structure.
 */
#define ecc_frost_ristretto255_sha512_SIGNINGCOMMITMENTSIZE 66

/**
 *
 * @param[out] h1 size:32
 * @param m size:m_len
 * @param m_len the length of `m`, it should be less than 512
 */
ECC_EXPORT
void ecc_frost_ristretto255_sha512_H1(
    byte_t *h1,
    const byte_t *m, int m_len
);

/**
 *
 * @param[out] h2 size:32
 * @param m size:m_len
 * @param m_len the length of `m`, it should be less than 512
 */
ECC_EXPORT
void ecc_frost_ristretto255_sha512_H2(
    byte_t *h2,
    const byte_t *m, int m_len
);

/**
 *
 * @param[out] h3 size:64
 * @param m size:m_len
 * @param m_len the length of `m`, it should be less than 512
 */
ECC_EXPORT
void ecc_frost_ristretto255_sha512_H3(
    byte_t *h3,
    const byte_t *m, int m_len
);

/**
 * Generate a single-party setting Schnorr signature.
 *
 * @param[out] signature signature, size:ecc_frost_ristretto255_sha512_SIGNATURESIZE
 * @param msg message to be signed, size:msg_len
 * @param msg_len the length of `msg`
 * @param SK private key, a scalar, size:ecc_frost_ristretto255_sha512_SECRETKEYSIZE
 */
ECC_EXPORT
void ecc_frost_ristretto255_sha512_schnorr_signature_generate(
    byte_t *signature,
    const byte_t *msg, int msg_len,
    const byte_t *SK
);

/**
 * Verify a Schnorr signature.
 *
 * @param msg signed message, size:msg_len
 * @param msg_len the length of `msg`
 * @param signature signature, size:ecc_frost_ristretto255_sha512_SIGNATURESIZE
 * @param PK public key, a group element, size:ecc_frost_ristretto255_sha512_PUBLICKEYSIZE
 * @return 1 if signature is valid, and 0 otherwise
 */
ECC_EXPORT
int ecc_frost_ristretto255_sha512_schnorr_signature_verify(
    const byte_t *msg, int msg_len,
    const byte_t *signature,
    const byte_t *PK
);

/**
 * Evaluate a polynomial f at a particular input x, i.e., y = f(x)
 * using Horner's method.
 *
 * @param[out] value scalar result of the polynomial evaluated at input x, size:ecc_frost_ristretto255_sha512_SCALARSIZE
 * @param x input at which to evaluate the polynomial, a scalar, size:ecc_frost_ristretto255_sha512_SCALARSIZE
 * @param coeffs the polynomial coefficients, a list of scalars, size:coeffs_len*ecc_frost_ristretto255_sha512_SCALARSIZE
 * @param coeffs_len the number of coefficients in `coeffs`
 */
ECC_EXPORT
void ecc_frost_ristretto255_sha512_polynomial_evaluate(
    byte_t *value,
    const byte_t *x,
    const byte_t *coeffs, int coeffs_len
);

/**
 * Lagrange coefficients are used in FROST to evaluate a polynomial f at f(0),
 * given a set of t other points, where f is represented as a set of coefficients.
 *
 * @param[out] L_i the i-th Lagrange coefficient, size:ecc_frost_ristretto255_sha512_SCALARSIZE
 * @param x_i an x-coordinate contained in L, a scalar, size:ecc_frost_ristretto255_sha512_SCALARSIZE
 * @param L the set of x-coordinates, each a scalar, size:L_len*ecc_frost_ristretto255_sha512_SCALARSIZE
 * @param L_len the number of x-coordinates in `L`
 */
ECC_EXPORT
void ecc_frost_ristretto255_sha512_derive_lagrange_coefficient(
    byte_t *L_i,
    const byte_t *x_i,
    const byte_t *L, int L_len
);

/**
 * This is an optimization that works like `ecc_frost_ristretto255_sha512_derive_lagrange_coefficient`
 * but with a set of points (x, y).
 *
 * @param[out] L_i the i-th Lagrange coefficient, size:ecc_frost_ristretto255_sha512_SCALARSIZE
 * @param x_i an x-coordinate contained in L, a scalar, size:ecc_frost_ristretto255_sha512_SCALARSIZE
 * @param L the set of (x, y)-points, size:L_len*ecc_frost_ristretto255_sha512_POINTSIZE
 * @param L_len the number of (x, y)-points in `L`
 */
ECC_EXPORT
void ecc_frost_ristretto255_sha512_derive_lagrange_coefficient_with_points(
    byte_t *L_i,
    const byte_t *x_i,
    const byte_t *L, int L_len
);

/**
 * Secret sharing requires "splitting" a secret, which is represented
 * as a constant term of some polynomial f of degree t. Recovering the
 * constant term occurs with a set of t points using polynomial interpolation.
 *
 * @param[out] constant_term the constant term of f, i.e., f(0), size:ecc_frost_ristretto255_sha512_SCALARSIZE
 * @param points a set of `t` points on a polynomial f, each a tuple of two scalar values representing the x and y coordinates, size:points_len*ecc_frost_ristretto255_sha512_POINTSIZE
 * @param points_len the number of points in `points`
 */
ECC_EXPORT
void ecc_frost_ristretto255_sha512_polynomial_interpolation(
    byte_t *constant_term,
    const byte_t *points, int points_len
);

/**
 * Generate a pair of public commitments corresponding to the nonce pair.
 *
 * @param[out] comm a nonce commitment pair, size:ecc_frost_ristretto255_sha512_NONCECOMMITMENTPAIRSIZE
 * @param nonce a nonce pair, size:ecc_frost_ristretto255_sha512_NONCEPAIRSIZE
 */
ECC_EXPORT
void ecc_frost_ristretto255_sha512_commit_with_nonce(
    byte_t *comm,
    const byte_t *nonce
);

/**
 * Generate a pair of nonces and their corresponding public commitments.
 *
 * @param[out] nonce a nonce pair, size:ecc_frost_ristretto255_sha512_NONCEPAIRSIZE
 * @param[out] comm a nonce commitment pair, size:ecc_frost_ristretto255_sha512_NONCECOMMITMENTPAIRSIZE
 */
ECC_EXPORT
void ecc_frost_ristretto255_sha512_commit(
    byte_t *nonce,
    byte_t *comm
);

/**
 *
 * @param[out] group_comm size:ecc_frost_ristretto255_sha512_ELEMENTSIZE
 * @param commitment_list a list of commitments issued by each signer, MUST be sorted in ascending order by signer index, size:commitment_list_len*ecc_frost_ristretto255_sha512_SIGNINGCOMMITMENTSIZE
 * @param commitment_list_len the number of elements in `commitment_list`, should be less than 28
 * @param binding_factor size:ecc_frost_ristretto255_sha512_SCALARSIZE
 */
ECC_EXPORT
void ecc_frost_ristretto255_sha512_group_commitment(
    byte_t *group_comm,
    const byte_t *commitment_list, int commitment_list_len,
    const byte_t *binding_factor
);

/**
 * To produce a signature share.
 *
 * @param[out] sig_share signature share, size:ecc_frost_ristretto255_sha512_SCALARSIZE
 * @param[out] comm_share commitment share, size:ecc_frost_ristretto255_sha512_ELEMENTSIZE
 * @param index index `i` of the signer. Note index will never equal `0` and must be less thant 256
 * @param sk_i signer secret key share, size:ecc_frost_ristretto255_sha512_SECRETKEYSIZE
 * @param group_public_key public key corresponding to the signer secret key share, size:ecc_frost_ristretto255_sha512_PUBLICKEYSIZE
 * @param nonce_i pair of scalar values generated in round one, size:ecc_frost_ristretto255_sha512_NONCEPAIRSIZE
 * @param comm_i pair of element values generated in round one, size:ecc_frost_ristretto255_sha512_NONCECOMMITMENTPAIRSIZE
 * @param msg the message to be signed (sent by the Coordinator), size:msg_len
 * @param msg_len the length of `msg`
 * @param commitment_list a list of commitments issued by each signer, MUST be sorted in ascending order by signer index, size:commitment_list_len*ecc_frost_ristretto255_sha512_SIGNINGCOMMITMENTSIZE
 * @param commitment_list_len the number of elements in `commitment_list`, should be less than 28
 * @param participant_list a set containing identifiers for each signer, size:participant_list_len
 * @param participant_list_len the number of elements in `participant_list`
 */
ECC_EXPORT
void ecc_frost_ristretto255_sha512_sign(
    byte_t *sig_share,
    byte_t *comm_share,
    int index,
    const byte_t *sk_i,
    const byte_t *group_public_key,
    const byte_t *nonce_i,
    const byte_t *comm_i,
    const byte_t *msg, int msg_len,
    const byte_t *commitment_list, int commitment_list_len,
    const byte_t *participant_list, int participant_list_len
);

ECC_EXPORT
int ecc_frost_ristretto255_sha512_verify_signature_share(
    int index,
    const byte_t *group_public_key,
    const byte_t *PK_i,
    const byte_t *sig_share,
    const byte_t *comm_share,
    const byte_t *R,
    const byte_t *msg, int msg_len,
    const byte_t *participant_list, int participant_list_len
);

ECC_EXPORT
void ecc_frost_ristretto255_sha512_trusted_dealer_keygen_with_secret_and_coefficients(
    byte_t *public_key,
    byte_t *secret_key_shares,
    int n,
    int t,
    const byte_t *secret_key,
    const byte_t *coefficients
);

ECC_EXPORT
void ecc_frost_ristretto255_sha512_trusted_dealer_keygen(
    byte_t *secret_key,
    byte_t *public_key,
    byte_t *secret_key_shares,
    int n,
    int t
);

ECC_EXPORT
void ecc_frost_ristretto255_sha512_secret_share_shard_with_coefficients(
    byte_t *points,
    int n,
    int t,
    const byte_t *coefficients
);

ECC_EXPORT
void ecc_frost_ristretto255_sha512_secret_share_shard(
    byte_t *points,
    const byte_t *s,
    int n,
    int t
);

ECC_EXPORT
void ecc_frost_ristretto255_sha512_frost_aggregate(
    byte_t *signature,
    const byte_t *R,
    const byte_t *sig_shares, int sig_shares_len
);

#endif // ECC_FROST_H
