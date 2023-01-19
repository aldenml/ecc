/*
 * Copyright (c) 2022-2023, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#ifndef ECC_FROST_H
#define ECC_FROST_H

#include "export.h"

// https://github.com/cfrg/draft-irtf-cfrg-frost
// https://cfrg.github.io/draft-irtf-cfrg-frost/draft-irtf-cfrg-frost.html
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
 * Size of a scalar point for polynomial evaluation (x, y).
 */
#define ecc_frost_ristretto255_sha512_POINTSIZE 64

// const
/**
 *
 */
#define ecc_frost_ristretto255_sha512_COMMITMENTSIZE 96

// const
/**
 *
 */
#define ecc_frost_ristretto255_sha512_BINDINGFACTORSIZE 64

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
 * Size of a nonce tuple.
 */
#define ecc_frost_ristretto255_sha512_NONCEPAIRSIZE 64

// const
/**
 * Size of a nonce commitment tuple.
 */
#define ecc_frost_ristretto255_sha512_NONCECOMMITMENTPAIRSIZE 64

/**
 *
 * @param[out] nonce size:ecc_frost_ristretto255_sha512_SCALARSIZE
 * @param secret size:ecc_frost_ristretto255_sha512_SCALARSIZE
 * @param random_bytes size:32
 */
ECC_EXPORT
void ecc_frost_ristretto255_sha512_nonce_generate_with_randomness(
    byte_t *nonce,
    const byte_t *secret,
    const byte_t *random_bytes
);

/**
 *
 * @param[out] nonce size:ecc_frost_ristretto255_sha512_SCALARSIZE
 * @param secret size:ecc_frost_ristretto255_sha512_SCALARSIZE
 */
ECC_EXPORT
void ecc_frost_ristretto255_sha512_nonce_generate(
    byte_t *nonce,
    const byte_t *secret
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
void ecc_frost_ristretto255_sha512_derive_interpolating_value(
    byte_t *L_i,
    const byte_t *x_i,
    const byte_t *L, int L_len
);

/**
 * This is an optimization that works like `ecc_frost_ristretto255_sha512_derive_interpolating_value`
 * but with a set of points (x, y).
 *
 * @param[out] L_i the i-th Lagrange coefficient, size:ecc_frost_ristretto255_sha512_SCALARSIZE
 * @param x_i an x-coordinate contained in L, a scalar, size:ecc_frost_ristretto255_sha512_SCALARSIZE
 * @param L the set of (x, y)-points, size:L_len*ecc_frost_ristretto255_sha512_POINTSIZE
 * @param L_len the number of (x, y)-points in `L`
 */
ECC_EXPORT
void ecc_frost_ristretto255_sha512_derive_interpolating_value_with_points(
    byte_t *L_i,
    const byte_t *x_i,
    const byte_t *L, int L_len
);

/**
 * Encodes a list of participant commitments into a bytestring for use in the
 * FROST protocol.
 *
 * @param[out] out size:commitment_list_len*ecc_frost_ristretto255_sha512_COMMITMENTSIZE
 * @param commitment_list a list of commitments issued by each signer, MUST be sorted in ascending order by signer index, size:commitment_list_len*ecc_frost_ristretto255_sha512_COMMITMENTSIZE
 * @param commitment_list_len the number of elements in `commitment_list`
 */
ECC_EXPORT
void ecc_frost_ristretto255_sha512_encode_group_commitment_list(
    byte_t *out,
    const byte_t *commitment_list, int commitment_list_len
);

/**
 * Extracts participant identifiers from a commitment list.
 *
 * @param[out] identifiers size:commitment_list_len*ecc_frost_ristretto255_sha512_SCALARSIZE
 * @param commitment_list a list of commitments issued by each signer, MUST be sorted in ascending order by signer index, size:commitment_list_len*ecc_frost_ristretto255_sha512_COMMITMENTSIZE
 * @param commitment_list_len the number of elements in `commitment_list`
 */
ECC_EXPORT
void ecc_frost_ristretto255_sha512_participants_from_commitment_list(
    byte_t *identifiers,
    const byte_t *commitment_list, int commitment_list_len
);

/**
 * Extracts a binding factor from a list of binding factors.
 *
 * @param[out] binding_factor size:ecc_frost_ristretto255_sha512_SCALARSIZE
 * @param binding_factor_list a list of binding factors for each participant, MUST be sorted in ascending order by signer index, size:binding_factor_list_len*ecc_frost_ristretto255_sha512_BINDINGFACTORSIZE
 * @param binding_factor_list_len the number of elements in `binding_factor_list`
 * @param identifier participant identifier, size:ecc_frost_ristretto255_sha512_SCALARSIZE
 * @return 0 on success, or -1 if the designated participant is not known
 */
ECC_EXPORT
int ecc_frost_ristretto255_sha512_binding_factor_for_participant(
    byte_t *binding_factor,
    const byte_t *binding_factor_list, int binding_factor_list_len,
    const byte_t *identifier
);

/**
 * Compute binding factors based on the participant commitment list and message
 * to be signed.
 *
 * @param[out] binding_factor_list list of binding factors (identifier, Scalar) tuples representing the binding factors, size:commitment_list_len*ecc_frost_ristretto255_sha512_BINDINGFACTORSIZE
 * @param commitment_list a list of commitments issued by each signer, MUST be sorted in ascending order by signer index, size:commitment_list_len*ecc_frost_ristretto255_sha512_COMMITMENTSIZE
 * @param commitment_list_len the number of elements in `commitment_list`
 * @param msg the message to be signed, size:msg_len
 * @param msg_len the length of `msg`
 */
ECC_EXPORT
void ecc_frost_ristretto255_sha512_compute_binding_factors(
    byte_t *binding_factor_list,
    const byte_t *commitment_list, int commitment_list_len,
    const byte_t *msg, int msg_len
);

/**
 * Create the group commitment from a commitment list.
 *
 * @param[out] group_comm size:ecc_frost_ristretto255_sha512_ELEMENTSIZE
 * @param commitment_list a list of commitments issued by each signer, MUST be sorted in ascending order by signer index, size:commitment_list_len*ecc_frost_ristretto255_sha512_COMMITMENTSIZE
 * @param commitment_list_len the number of elements in `commitment_list`
 * @param binding_factor_list size:ecc_frost_ristretto255_sha512_BINDINGFACTORSIZE
 * @param binding_factor_list_len the number of elements in `binding_factor_list`
 */
ECC_EXPORT
void ecc_frost_ristretto255_sha512_compute_group_commitment(
    byte_t *group_comm,
    const byte_t *commitment_list, int commitment_list_len,
    const byte_t *binding_factor_list, int binding_factor_list_len
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
 * @param[out] nonce a nonce pair, size:ecc_frost_ristretto255_sha512_NONCEPAIRSIZE
 * @param[out] comm a nonce commitment pair, size:ecc_frost_ristretto255_sha512_NONCECOMMITMENTPAIRSIZE
 * @param sk_i the secret key share, size:ecc_frost_ristretto255_sha512_SCALARSIZE
 * @param hiding_nonce_randomness size:32
 * @param binding_nonce_randomness size:32
 */
ECC_EXPORT
void ecc_frost_ristretto255_sha512_commit_with_randomness(
    byte_t *nonce,
    byte_t *comm,
    const byte_t *sk_i,
    const byte_t *hiding_nonce_randomness,
    const byte_t *binding_nonce_randomness
);

/**
 * @param[out] nonce a nonce pair, size:ecc_frost_ristretto255_sha512_NONCEPAIRSIZE
 * @param[out] comm a nonce commitment pair, size:ecc_frost_ristretto255_sha512_NONCECOMMITMENTPAIRSIZE
 * @param sk_i the secret key share, size:ecc_frost_ristretto255_sha512_SCALARSIZE
 */
ECC_EXPORT
void ecc_frost_ristretto255_sha512_commit(
    byte_t *nonce,
    byte_t *comm,
    const byte_t *sk_i
);

/**
 * To produce a signature share.
 *
 * @param[out] sig_share signature share, size:ecc_frost_ristretto255_sha512_SCALARSIZE
 * @param identifier identifier of the signer. Note identifier will never equal 0, size:ecc_frost_ristretto255_sha512_SCALARSIZE
 * @param sk_i signer secret key share, size:ecc_frost_ristretto255_sha512_SECRETKEYSIZE
 * @param group_public_key public key corresponding to the signer secret key share, size:ecc_frost_ristretto255_sha512_PUBLICKEYSIZE
 * @param nonce_i pair of scalar values generated in round one, size:ecc_frost_ristretto255_sha512_NONCEPAIRSIZE
 * @param msg the message to be signed (sent by the Coordinator), size:msg_len
 * @param msg_len the length of `msg`
 * @param commitment_list a list of commitments issued by each signer, MUST be sorted in ascending order by signer index, size:commitment_list_len*ecc_frost_ristretto255_sha512_COMMITMENTSIZE
 * @param commitment_list_len the number of elements in `commitment_list`
 */
ECC_EXPORT
void ecc_frost_ristretto255_sha512_sign(
    byte_t *sig_share,
    const byte_t *identifier,
    const byte_t *sk_i,
    const byte_t *group_public_key,
    const byte_t *nonce_i,
    const byte_t *msg, int msg_len,
    const byte_t *commitment_list, int commitment_list_len
);

/**
 * Performs the aggregate operation to obtain the resulting signature.
 *
 * @param[out] signature a Schnorr signature consisting of an Element and Scalar value, size:ecc_frost_ristretto255_sha512_SIGNATURESIZE
 * @param commitment_list the group commitment returned by compute_group_commitment, size:commitment_list_len*ecc_frost_ristretto255_sha512_PUBLICKEYSIZE
 * @param commitment_list_len the group commitment returned by compute_group_commitment, size:ecc_frost_ristretto255_sha512_PUBLICKEYSIZE
 * @param msg the message to be signed (sent by the Coordinator), size:msg_len
 * @param msg_len the length of `msg`
 * @param sig_shares a set of signature shares z_i for each signer, size:sig_shares_len*ecc_frost_ristretto255_sha512_SCALARSIZE
 * @param sig_shares_len the number of elements in `sig_shares`, must satisfy THRESHOLD_LIMIT <= sig_shares_len <= MAX_SIGNERS
 */
ECC_EXPORT
void ecc_frost_ristretto255_sha512_aggregate(
    byte_t *signature,
    const byte_t *commitment_list, int commitment_list_len,
    const byte_t *msg, int msg_len,
    const byte_t *sig_shares, int sig_shares_len
);

/**
 * Check that the signature share is valid.
 *
 * @param identifier identifier of the signer. Note identifier will never equal 0, size:ecc_frost_ristretto255_sha512_SCALARSIZE
 * @param public_key_share_i the public key for the ith signer, size:ecc_frost_ristretto255_sha512_PUBLICKEYSIZE
 * @param comm_i pair of Element values (hiding_nonce_commitment, binding_nonce_commitment) generated in round one from the ith signer, size:ecc_frost_ristretto255_sha512_NONCECOMMITMENTPAIRSIZE
 * @param sig_share_i a Scalar value indicating the signature share as produced in round two from the ith signer, size:ecc_frost_ristretto255_sha512_SCALARSIZE
 * @param commitment_list a list of commitments issued by each signer, MUST be sorted in ascending order by signer index, size:commitment_list_len*ecc_frost_ristretto255_sha512_COMMITMENTSIZE
 * @param commitment_list_len the number of elements in `commitment_list`
 * @param group_public_key the public key for the group, size:ecc_frost_ristretto255_sha512_PUBLICKEYSIZE
 * @param msg the message to be signed (sent by the Coordinator), size:msg_len
 * @param msg_len the length of `msg`
 * @return 1 if the signature share is valid, and 0 otherwise.
 */
ECC_EXPORT
int ecc_frost_ristretto255_sha512_verify_signature_share(
    const byte_t *identifier,
    const byte_t *public_key_share_i,
    const byte_t *comm_i,
    const byte_t *sig_share_i,
    const byte_t *commitment_list, int commitment_list_len,
    const byte_t *group_public_key,
    const byte_t *msg, int msg_len
);

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
 * @param[out] h3 size:ecc_frost_ristretto255_sha512_SCALARSIZE
 * @param m size:m_len
 * @param m_len the length of `m`
 */
ECC_EXPORT
void ecc_frost_ristretto255_sha512_H3(
    byte_t *h3,
    const byte_t *m, int m_len
);

/**
 * This is an alias for the ciphersuite hash function with
 * domain separation applied.
 *
 * This is a variant of H3 that folds internally all inputs in the same
 * hash calculation.
 *
 * @param[out] h3 size:ecc_frost_ristretto255_sha512_SCALARSIZE
 * @param m1 size:m1_len
 * @param m1_len the length of `m1`
 * @param m2 size:m2_len
 * @param m2_len the length of `m2`
 */
ECC_EXPORT
void ecc_frost_ristretto255_sha512_H3_2(
    byte_t *h3,
    const byte_t *m1, int m1_len,
    const byte_t *m2, int m2_len
);

/**
 * Implemented by computing H(contextString || "msg" || m).
 *
 * @param[out] h4 size:64
 * @param m size:m_len
 * @param m_len the length of `m`
 */
ECC_EXPORT
void ecc_frost_ristretto255_sha512_H4(
    byte_t *h4,
    const byte_t *m, int m_len
);

/**
 * Implemented by computing H(contextString || "com" || m).
 *
 * @param[out] h5 size:64
 * @param m size:m_len
 * @param m_len the length of `m`
 */
ECC_EXPORT
void ecc_frost_ristretto255_sha512_H5(
    byte_t *h5,
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
void ecc_frost_ristretto255_sha512_prime_order_sign(
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
int ecc_frost_ristretto255_sha512_prime_order_verify(
    const byte_t *msg, int msg_len,
    const byte_t *signature,
    const byte_t *PK
);

/**
 * @param[out] participant_private_keys MAX_PARTICIPANTS shares of the secret key s, each a tuple consisting of the participant identifier (a NonZeroScalar) and the key share (a Scalar), size:n*ecc_frost_ristretto255_sha512_POINTSIZE
 * @param[out] group_public_key public key corresponding to the group signing key, an Element, size:ecc_frost_ristretto255_sha512_ELEMENTSIZE
 * @param[out] vss_commitment a vector commitment of Elements in G, to each of the coefficients in the polynomial defined by secret_key_shares and whose first element is G.ScalarBaseMult(s), size:t*ecc_frost_ristretto255_sha512_ELEMENTSIZE
 * @param[out] polynomial_coefficients size:t*ecc_frost_ristretto255_sha512_SCALARSIZE
 * @param secret_key a group secret, a Scalar, that MUST be derived from at least Ns bytes of entropy, size:ecc_frost_ristretto255_sha512_SCALARSIZE
 * @param n the number of shares to generate
 * @param t the threshold of the secret sharing scheme
 * @param coefficients size:(t-1)*ecc_frost_ristretto255_sha512_SCALARSIZE
 */
ECC_EXPORT
void ecc_frost_ristretto255_sha512_trusted_dealer_keygen_with_coefficients(
    byte_t *participant_private_keys,
    byte_t *group_public_key,
    byte_t *vss_commitment,
    byte_t *polynomial_coefficients,
    const byte_t *secret_key,
    int n,
    int t,
    const byte_t *coefficients
);

/**
 * Split a secret into shares.
 *
 * @param[out] secret_key_shares A list of n secret shares, each of which is an element of F, size:n*ecc_frost_ristretto255_sha512_POINTSIZE
 * @param[out] polynomial_coefficients a vector of t coefficients which uniquely determine a polynomial f, size:t*ecc_frost_ristretto255_sha512_SCALARSIZE
 * @param s secret value to be shared, a scalar, size:ecc_frost_ristretto255_sha512_SCALARSIZE
 * @param coefficients an array of size t - 1 with randomly generated scalars, not including the 0th coefficient of the polynomial, size:(t-1)*ecc_frost_ristretto255_sha512_SCALARSIZE
 * @param n the number of shares to generate, an integer less than 2^16
 * @param t the threshold of the secret sharing scheme, an integer greater than 0
 * @return 0 if no errors, else -1
 */
ECC_EXPORT
int ecc_frost_ristretto255_sha512_secret_share_shard(
    byte_t *secret_key_shares,
    byte_t *polynomial_coefficients,
    const byte_t *s,
    const byte_t *coefficients,
    int n,
    int t
);

/**
 * Combines a shares list of length MIN_PARTICIPANTS to recover the secret.
 *
 * @param[out] s the resulting secret s that was previously split into shares, size:ecc_frost_ristretto255_sha512_SCALARSIZE
 * @param shares a list of at minimum MIN_PARTICIPANTS secret shares, each a tuple (i, f(i)) where i and f(i) are Scalars, size:shares_len*ecc_frost_ristretto255_sha512_POINTSIZE
 * @param shares_len the number of shares in `shares`
 * @return 0 if no errors, else -1
 */
ECC_EXPORT
int ecc_frost_ristretto255_sha512_secret_share_combine(
    byte_t *s,
    const byte_t *shares, int shares_len
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
 * Recover the constant term of an interpolating polynomial defined by a set
 * of points.
 *
 * @param[out] f_zero the constant term of f, i.e., f(0), a scalar, size:ecc_frost_ristretto255_sha512_SCALARSIZE
 * @param points a set of t points with distinct x coordinates on a polynomial f, each a tuple of two Scalar values representing the x and y coordinates, size:points_len*ecc_frost_ristretto255_sha512_POINTSIZE
 * @param points_len the number of elements in `points`
 */
ECC_EXPORT
void ecc_frost_ristretto255_sha512_polynomial_interpolate_constant(
    byte_t *f_zero,
    const byte_t *points, int points_len
);

/**
 * Compute the commitment using a polynomial f of degree at most MIN_PARTICIPANTS-1.
 *
 * @param[out] vss_commitment a vector commitment to each of the coefficients in coeffs, where each item of the vector commitment is an Element, size:coeffs_len*ecc_frost_ristretto255_sha512_ELEMENTSIZE
 * @param coeffs a vector of the MIN_PARTICIPANTS coefficients which uniquely determine a polynomial f, size:coeffs_len*ecc_frost_ristretto255_sha512_SCALARSIZE
 * @param coeffs_len the length of `coeffs`
 */
ECC_EXPORT
void ecc_frost_ristretto255_sha512_vss_commit(
    byte_t *vss_commitment,
    const byte_t *coeffs,
    int coeffs_len
);

/**
 * For verification of a participant's share.
 *
 * @param share_i a tuple of the form (i, sk_i), size:ecc_frost_ristretto255_sha512_POINTSIZE
 * @param vss_commitment a vector commitment to each of the coefficients in coeffs, where each item of the vector commitment is an Element, size:t*ecc_frost_ristretto255_sha512_ELEMENTSIZE
 * @param t the threshold of the secret sharing scheme
 * @return 1 if sk_i is valid, and 0 otherwise.
 */
ECC_EXPORT
int ecc_frost_ristretto255_sha512_vss_verify(
    const byte_t *share_i,
    const byte_t *vss_commitment,
    int t
);

/**
 * Derive group info.
 *
 * @param[out] PK the public key representing the group, an Element, size:ecc_frost_ristretto255_sha512_ELEMENTSIZE
 * @param[out] participant_public_keys a list of MAX_PARTICIPANTS public keys PK_i for i=1,...,MAX_PARTICIPANTS, where each PK_i is the public key, an Element, for participant i., size:n*ecc_frost_ristretto255_sha512_ELEMENTSIZE
 * @param n the number of shares to generate
 * @param t the threshold of the secret sharing scheme
 * @param vss_commitment a VSS commitment to a secret polynomial f, a vector commitment to each of the coefficients in coeffs, where each element of the vector commitment is an Element, size:t*ecc_frost_ristretto255_sha512_ELEMENTSIZE
 */
ECC_EXPORT
void ecc_frost_ristretto255_sha512_derive_group_info(
    byte_t *PK,
    byte_t *participant_public_keys,
    int n,
    int t,
    const byte_t *vss_commitment
);

#endif // ECC_FROST_H
