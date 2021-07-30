/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#ifndef ECC_SIGN_H
#define ECC_SIGN_H

#include "export.h"

// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-04
// https://github.com/cfrg/draft-irtf-cfrg-bls-signature
//
// The variant implemented here is the minimal-pubkey-size: public keys are
// points in G1, signatures are points in G2.

/**
 * Size of the signing public key.
 */
#define ecc_sign_bls12_381_PUBLICKEYSIZE 48 // size of a compressed G1 element in BLS12-381

/**
 * Size of the signing private key.
 */
#define ecc_sign_bls12_381_PRIVATEKEYSIZE 32 // size of a scalar in BLS12-381

/**
 * Signature size.
 */
#define ecc_sign_bls12_381_SIGNATURESIZE 96 // size of a compressed G2 element in BLS12-381

/**
 * Generates a secret key `sk` deterministically from a secret
 * octet string `ikm`. The secret key is guaranteed to be nonzero.
 *
 * For security, `ikm` MUST be infeasible to guess, e.g., generated
 * by a trusted source of randomness and be at least 32 bytes long.
 *
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-04#section-2.3
 *
 * @param sk (output) a secret key
 * @param ikm a secret octet string
 * @param ikm_len the length of `ikm`
 */
ECC_EXPORT
void ecc_sign_bls12_381_KeyGen(byte_t *sk, const byte_t *ikm, int ikm_len);

/**
 * Takes a secret key `sk and outputs the corresponding public key `pk`.
 *
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-04#section-2.4
 *
 * @param pk (output) a public key
 * @param sk the secret key
 */
ECC_EXPORT
void ecc_sign_bls12_381_SkToPk(byte_t *pk, const byte_t *sk);

/**
 * Ensures that a public key is valid.  In particular, it ensures
 * that a public key represents a valid, non-identity point that
 * is in the correct subgroup.
 *
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-04#section-2.5
 *
 * @param pk a public key in the format output by SkToPk
 * @return 0 for valid or -1 for invalid
 */
ECC_EXPORT
int ecc_sign_bls12_381_KeyValidate(const byte_t *pk);

/**
 * Computes a signature from sk, a secret key, and a message msg
 * and put the result in sig.
 *
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-04#section-2.6
 *
 * @param sig (output) the signature
 * @param msg input message
 * @param msg_len the length of `msg`
 * @param sk the secret key
 */
ECC_EXPORT
void ecc_sign_bls12_381_CoreSign(
    byte_t *sig,
    const byte_t *msg, int msg_len,
    const byte_t *sk
);

/**
 * Checks that a signature is valid for the message under the public key pk.
 *
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-04#section-2.7
 *
 * @param pk the public key
 * @param msg input message
 * @param msg_len the length of `msg`
 * @param sig the signature
 * @return 0 if valid, -1 if invalid
 */
ECC_EXPORT
int ecc_sign_bls12_381_CoreVerify(
    const byte_t *pk,
    const byte_t *msg, int msg_len,
    const byte_t *sig
);

/**
 * Aggregates multiple signatures into one.
 *
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-04#section-2.8
 *
 * @param sig (output) the aggregated signature that combines all inputs
 * @param signatures array of individual signatures
 * @param n amount of signatures in the array `signatures`
 * @return 0 if valid, -1 if invalid
 */
ECC_EXPORT
int ecc_sign_bls12_381_Aggregate(
    byte_t *sig,
    const byte_t **signatures, int n
);

#endif // ECC_SIGN_H
