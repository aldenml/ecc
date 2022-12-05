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
 * Size of a schnorr signature, a pair of a scalar and an element.
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
 * Map arbitrary inputs to non-zero Scalar elements of the prime-order group scalar field.
 *
 * @param[out] h1 size:ecc_frost_ristretto255_sha512_SCALARSIZE
 * @param m size:m_len
 * @param m_len the length of `m`
 */
ECC_EXPORT
void ecc_frost_ristretto255_sha512_H1(
    byte_t *h1,
    const byte_t *m, int m_len
);

/**
 * Map arbitrary inputs to non-zero Scalar elements of the prime-order group scalar field.
 *
 * This is a variant of H2 that folds internally all inputs in the same
 * hash calculation.
 *
 * @param[out] h1 size:ecc_frost_ristretto255_sha512_SCALARSIZE
 * @param m1 size:m1_len
 * @param m1_len the length of `m1`
 * @param m2 size:m2_len
 * @param m2_len the length of `m2`
 */
ECC_EXPORT
void ecc_frost_ristretto255_sha512_H1_2(
    byte_t *h1,
    const byte_t *m1, int m1_len,
    const byte_t *m2, int m2_len
);

/**
 * Map arbitrary inputs to non-zero Scalar elements of the prime-order group scalar field.
 *
 * @param[out] h2 size:ecc_frost_ristretto255_sha512_SCALARSIZE
 * @param m size:m_len
 * @param m_len the length of `m`
 */
ECC_EXPORT
void ecc_frost_ristretto255_sha512_H2(
    byte_t *h2,
    const byte_t *m, int m_len
);

/**
 * Map arbitrary inputs to non-zero Scalar elements of the prime-order group scalar field.
 *
 * This is a variant of H2 that folds internally all inputs in the same
 * hash calculation.
 *
 * @param[out] h2 size:ecc_frost_ristretto255_sha512_SCALARSIZE
 * @param m1 size:m1_len
 * @param m1_len the length of `m1`
 * @param m2 size:m2_len
 * @param m2_len the length of `m2`
 * @param m3 size:m3_len
 * @param m3_len the length of `m3`
 */
ECC_EXPORT
void ecc_frost_ristretto255_sha512_H2_3(
    byte_t *h2,
    const byte_t *m1, int m1_len,
    const byte_t *m2, int m2_len,
    const byte_t *m3, int m3_len
);

/**
 * This is an alias for the ciphersuite hash function with
 * domain separation applied.
 *
 * @param[out] h3 size:64
 * @param m size:m_len
 * @param m_len the length of `m`
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
 * Compute the binding factor based on the signer commitment list and a message to be signed.
 *
 * @param[out] binding_factor a Scalar representing the binding factor, size:ecc_frost_ristretto255_sha512_SCALARSIZE
 * @param encoded_commitment_list an encoded commitment list, size:encoded_commitment_list_len*ecc_frost_ristretto255_sha512_SIGNINGCOMMITMENTSIZE
 * @param encoded_commitment_list_len the number of elements in `encoded_commitment_list`
 * @param msg the message to be signed (sent by the Coordinator), size:msg_len
 * @param msg_len the length of `msg`
 */
ECC_EXPORT
void ecc_frost_ristretto255_sha512_compute_binding_factor(
    byte_t *binding_factor,
    const byte_t *encoded_commitment_list, int encoded_commitment_list_len,
    const byte_t *msg, int msg_len
);

/**
 * Create the per-message challenge.
 *
 * @param[out] challenge a challenge Scalar value, size:ecc_frost_ristretto255_sha512_SCALARSIZE
 * @param group_commitment an Element representing the group commitment, size:ecc_frost_ristretto255_sha512_ELEMENTSIZE
 * @param group_public_key public key corresponding to the signer secret key share, size:ecc_frost_ristretto255_sha512_PUBLICKEYSIZE
 * @param msg the message to be signed (sent by the Coordinator), size:msg_len
 * @param msg_len the length of `msg`
 */
ECC_EXPORT
void ecc_frost_ristretto255_sha512_compute_challenge(
    byte_t *challenge,
    const byte_t *group_commitment,
    const byte_t *group_public_key,
    const byte_t *msg, int msg_len
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
 * Create the group commitment from a commitment list.
 *
 * @param[out] group_comm size:ecc_frost_ristretto255_sha512_ELEMENTSIZE
 * @param commitment_list a list of commitments issued by each signer, MUST be sorted in ascending order by signer index, size:commitment_list_len*ecc_frost_ristretto255_sha512_SIGNINGCOMMITMENTSIZE
 * @param commitment_list_len the number of elements in `commitment_list`
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
 * @param commitment_list_len the number of elements in `commitment_list`
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

/**
 * Check that the signature share is valid.
 *
 * @param index Index `i` of the signer. Note index will never equal `0`.
 * @param public_key_share_i the public key for the ith signer, size:ecc_frost_ristretto255_sha512_PUBLICKEYSIZE
 * @param comm_i pair of Element values (hiding_nonce_commitment, binding_nonce_commitment) generated in round one from the ith signer, size:ecc_frost_ristretto255_sha512_NONCECOMMITMENTPAIRSIZE
 * @param sig_share_i a Scalar value indicating the signature share as produced in round two from the ith signer, size:ecc_frost_ristretto255_sha512_SCALARSIZE
 * @param commitment_list a list of commitments issued by each signer, MUST be sorted in ascending order by signer index, size:commitment_list_len*ecc_frost_ristretto255_sha512_SIGNINGCOMMITMENTSIZE
 * @param commitment_list_len the number of elements in `commitment_list`
 * @param participant_list a set containing identifiers for each signer, size:participant_list_len
 * @param participant_list_len the number of elements in `participant_list`
 * @param group_public_key the public key for the group, size:ecc_frost_ristretto255_sha512_PUBLICKEYSIZE
 * @param msg the message to be signed (sent by the Coordinator), size:msg_len
 * @param msg_len the length of `msg`
 * @return 1 if the signature share is valid, and 0 otherwise.
 */
ECC_EXPORT
int ecc_frost_ristretto255_sha512_verify_signature_share(
    int index,
    const byte_t *public_key_share_i,
    const byte_t *comm_i,
    const byte_t *sig_share_i,
    const byte_t *commitment_list, int commitment_list_len,
    const byte_t *participant_list, int participant_list_len,
    const byte_t *group_public_key,
    const byte_t *msg, int msg_len
);

/**
 * Generates a group secret s uniformly at random and uses
 * Shamir and Verifiable Secret Sharing to create secret shares
 * of s to be sent to all other participants.
 *
 * @param[out] public_key public key Element, size:ecc_frost_ristretto255_sha512_PUBLICKEYSIZE
 * @param secret_key_shares shares of the secret key, each a Scalar value, size:n*ecc_frost_ristretto255_sha512_SCALARSIZE
 * @param n the number of shares to generate
 * @param t the threshold of the secret sharing scheme
 * @param secret_key a secret key Scalar, size:ecc_frost_ristretto255_sha512_SCALARSIZE
 * @param coefficients size:t*ecc_frost_ristretto255_sha512_SCALARSIZE
 */
ECC_EXPORT
void ecc_frost_ristretto255_sha512_trusted_dealer_keygen_with_secret_and_coefficients(
    byte_t *public_key,
    byte_t *secret_key_shares,
    int n,
    int t,
    const byte_t *secret_key,
    const byte_t *coefficients
);

/**
 * Generates a group secret s uniformly at random and uses
 * Shamir and Verifiable Secret Sharing to create secret shares
 * of s to be sent to all other participants.
 *
 * @param[out] secret_key a secret key Scalar, size:ecc_frost_ristretto255_sha512_SCALARSIZE
 * @param[out] public_key public key Element, size:ecc_frost_ristretto255_sha512_PUBLICKEYSIZE
 * @param[out] secret_key_shares shares of the secret key, each a Scalar value, size:n*ecc_frost_ristretto255_sha512_SCALARSIZE
 * @param n the number of shares to generate
 * @param t the threshold of the secret sharing scheme
 */
ECC_EXPORT
void ecc_frost_ristretto255_sha512_trusted_dealer_keygen(
    byte_t *secret_key,
    byte_t *public_key,
    byte_t *secret_key_shares,
    int n,
    int t
);

/**
 * Split a secret into shares.
 *
 * @param points A list of n secret shares, each of which is an element of F, size:n*ecc_frost_ristretto255_sha512_POINTSIZE
 * @param n the number of shares to generate
 * @param t the threshold of the secret sharing scheme
 * @param coefficients size:t*ecc_frost_ristretto255_sha512_SCALARSIZE
 */
ECC_EXPORT
void ecc_frost_ristretto255_sha512_secret_share_shard_with_coefficients(
    byte_t *points,
    int n,
    int t,
    const byte_t *coefficients
);

/**
 * Split a secret into shares.
 *
 * @param[out] points A list of n secret shares, each of which is an element of F, size:n*ecc_frost_ristretto255_sha512_POINTSIZE
 * @param s secret to be shared, an element of F, size:ecc_frost_ristretto255_sha512_SCALARSIZE
 * @param n the number of shares to generate
 * @param t the threshold of the secret sharing scheme
 */
ECC_EXPORT
void ecc_frost_ristretto255_sha512_secret_share_shard(
    byte_t *points,
    const byte_t *s,
    int n,
    int t
);

/**
 * Performs the aggregate operation to obtain the resulting signature.
 *
 * @param[out] signature a Schnorr signature consisting of an Element and Scalar value, size:ecc_frost_ristretto255_sha512_SIGNATURESIZE
 * @param group_commitment the group commitment returned by compute_group_commitment, size:ecc_frost_ristretto255_sha512_PUBLICKEYSIZE
 * @param sig_shares a set of signature shares z_i for each signer, size:sig_shares_len*ecc_frost_ristretto255_sha512_SCALARSIZE
 * @param sig_shares_len the number of elements in `sig_shares`, must satisfy THRESHOLD_LIMIT <= sig_shares_len <= MAX_SIGNERS
 */
ECC_EXPORT
void ecc_frost_ristretto255_sha512_frost_aggregate(
    byte_t *signature,
    const byte_t *group_commitment,
    const byte_t *sig_shares, int sig_shares_len
);

#endif // ECC_FROST_H
