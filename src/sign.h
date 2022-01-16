/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#ifndef ECC_SIGN_H
#define ECC_SIGN_H

#include "export.h"

// const
/**
 * Signature size.
 */
#define ecc_sign_ed25519_SIZE 64

// const
/**
 * Seed size.
 */
#define ecc_sign_ed25519_SEEDSIZE 32

// const
/**
 * Public key size.
 */
#define ecc_sign_ed25519_PUBLICKEYSIZE 32

// const
/**
 * Secret key size.
 */
#define ecc_sign_ed25519_SECRETKEYSIZE 64

/**
 * Signs the message msg whose length is msg_len bytes, using the
 * secret key sk, and puts the signature into sig.
 *
 * @param[out] sig the signature, size:ecc_sign_ed25519_SIZE
 * @param msg input message, size:msg_len
 * @param msg_len the length of `msg`
 * @param sk the secret key, size:ecc_sign_ed25519_SECRETKEYSIZE
 */
ECC_EXPORT
void ecc_sign_ed25519_sign(
    byte_t *sig,
    const byte_t *msg, int msg_len,
    const byte_t *sk
);

/**
 * Verifies that sig is a valid signature for the message msg whose length
 * is msg_len bytes, using the signer's public key pk.
 *
 * @param sig the signature, size:ecc_sign_ed25519_SIZE
 * @param msg input message, size:msg_len
 * @param msg_len the length of `msg`
 * @param pk the public key, size:ecc_sign_ed25519_PUBLICKEYSIZE
 * @return -1 if the signature fails verification, or 0 on success
 */
ECC_EXPORT
int ecc_sign_ed25519_verify(
    const byte_t *sig,
    const byte_t *msg, int msg_len,
    const byte_t *pk
);

/**
 * Generates a random key pair of public and private keys.
 *
 * @param[out] pk public key, size:ecc_sign_ed25519_PUBLICKEYSIZE
 * @param[out] sk private key, size:ecc_sign_ed25519_SECRETKEYSIZE
 */
ECC_EXPORT
void ecc_sign_ed25519_keypair(byte_t *pk, byte_t *sk);

/**
 * Generates a random key pair of public and private keys derived
 * from a seed.
 *
 * @param[out] pk public key, size:ecc_sign_ed25519_PUBLICKEYSIZE
 * @param[out] sk private key, size:ecc_sign_ed25519_SECRETKEYSIZE
 * @param seed seed to generate the keys, size:ecc_sign_ed25519_SEEDSIZE
 */
ECC_EXPORT
void ecc_sign_ed25519_seed_keypair(byte_t *pk, byte_t *sk, const byte_t *seed);

/**
 * Extracts the seed from the secret key sk and copies it into seed.
 *
 * @param[out] seed the seed used to generate the secret key, size:ecc_sign_ed25519_SEEDSIZE
 * @param sk the secret key, size:ecc_sign_ed25519_SECRETKEYSIZE
 */
ECC_EXPORT
void ecc_sign_ed25519_sk_to_seed(byte_t *seed, const byte_t *sk);

/**
 * Extracts the public key from the secret key sk and copies it into pk.
 *
 * @param[out] pk the public key, size:ecc_sign_ed25519_PUBLICKEYSIZE
 * @param sk the secret key, size:ecc_sign_ed25519_SECRETKEYSIZE
 */
ECC_EXPORT
void ecc_sign_ed25519_sk_to_pk(byte_t *pk, const byte_t *sk);

// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-04
// https://github.com/cfrg/draft-irtf-cfrg-bls-signature
//
// The variant implemented here is the minimal-pubkey-size: public keys are
// points in G1, signatures are points in G2.

// const
/**
 * Size of the signing public key (size of a compressed G1 element in BLS12-381).
 */
#define ecc_sign_bls12_381_PUBLICKEYSIZE 48

// const
/**
 * Size of the signing private key (size of a scalar in BLS12-381).
 */
#define ecc_sign_bls12_381_PRIVATEKEYSIZE 32

// const
/**
 * Signature size (size of a compressed G2 element in BLS12-381).
 */
#define ecc_sign_bls12_381_SIGNATURESIZE 96

/**
 * Generates a secret key `sk` deterministically from a secret
 * octet string `ikm`. The secret key is guaranteed to be nonzero.
 *
 * For security, `ikm` MUST be infeasible to guess, e.g., generated
 * by a trusted source of randomness and be at least 32 bytes long.
 *
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-04#section-2.3
 *
 * @param[out] sk a secret key, size:ecc_sign_bls12_381_PRIVATEKEYSIZE
 * @param ikm a secret octet string, size:ikm_len
 * @param ikm_len the length of `ikm`
 */
ECC_EXPORT
void ecc_sign_bls12_381_KeyGen(byte_t *sk, const byte_t *ikm, int ikm_len);

/**
 * Takes a secret key `sk and outputs the corresponding public key `pk`.
 *
 * See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-04#section-2.4
 *
 * @param[out] pk a public key, size:ecc_sign_bls12_381_PUBLICKEYSIZE
 * @param sk the secret key, size:ecc_sign_bls12_381_PRIVATEKEYSIZE
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
 * @param pk a public key in the format output by SkToPk, size:ecc_sign_bls12_381_PUBLICKEYSIZE
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
 * @param[out] sig the signature, size:ecc_sign_bls12_381_SIGNATURESIZE
 * @param msg input message, size:msg_len
 * @param msg_len the length of `msg`
 * @param sk the secret key, size:ecc_sign_bls12_381_PRIVATEKEYSIZE
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
 * @param pk the public key, size:ecc_sign_bls12_381_PUBLICKEYSIZE
 * @param msg input message, size:msg_len
 * @param msg_len the length of `msg`
 * @param sig the signature, size:ecc_sign_bls12_381_SIGNATURESIZE
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
 * @param[out] sig the aggregated signature that combines all inputs, size:ecc_sign_bls12_381_SIGNATURESIZE
 * @param signatures array of individual signatures, size:n*ecc_sign_bls12_381_SIGNATURESIZE
 * @param n amount of signatures in the array `signatures`
 * @return 0 if valid, -1 if invalid
 */
ECC_EXPORT
int ecc_sign_bls12_381_Aggregate(
    byte_t *sig,
    const byte_t **signatures, int n
);

#endif // ECC_SIGN_H
