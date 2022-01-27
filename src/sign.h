/*
 * Copyright (c) 2021-2022, Alden Torres
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

// Compliant Ethereum BLS Signature API implementation.
//
// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-04
// https://github.com/cfrg/draft-irtf-cfrg-bls-signature
// https://github.com/ethereum/consensus-specs/blob/v1.0.0/specs/phase0/beacon-chain.md#bls-signatures
// https://github.com/ethereum/py_ecc
// https://github.com/ethereum/bls12-381-tests
//

// const
/**
 * Size of the signing private key (size of a scalar in BLS12-381).
 */
#define ecc_sign_eth_bls_PRIVATEKEYSIZE 32

// const
/**
 * Size of the signing public key (size of a compressed G1 element in BLS12-381).
 */
#define ecc_sign_eth_bls_PUBLICKEYSIZE 48

// const
/**
 * Signature size (size of a compressed G2 element in BLS12-381).
 */
#define ecc_sign_eth_bls_SIGNATURESIZE 96

/**
 * Generates a secret key `sk` deterministically from a secret
 * octet string `ikm`. The secret key is guaranteed to be nonzero.
 *
 * For security, `ikm` MUST be infeasible to guess, e.g., generated
 * by a trusted source of randomness and be at least 32 bytes long.
 *
 * @param[out] sk a secret key, size:ecc_sign_eth_bls_PRIVATEKEYSIZE
 * @param ikm a secret octet string, size:ikm_len
 * @param ikm_len the length of `ikm`
 */
ECC_EXPORT
void ecc_sign_eth_bls_KeyGen(byte_t *sk, const byte_t *ikm, int ikm_len);

/**
 * Takes a secret key `sk` and outputs the corresponding public key `pk`.
 *
 * @param[out] pk a public key, size:ecc_sign_eth_bls_PUBLICKEYSIZE
 * @param sk the secret key, size:ecc_sign_eth_bls_PRIVATEKEYSIZE
 */
ECC_EXPORT
void ecc_sign_eth_bls_SkToPk(byte_t *pk, const byte_t *sk);

/**
 * Ensures that a public key is valid.  In particular, it ensures
 * that a public key represents a valid, non-identity point that
 * is in the correct subgroup.
 *
 * @param pk a public key in the format output by SkToPk, size:ecc_sign_eth_bls_PUBLICKEYSIZE
 * @return 0 for valid or -1 for invalid
 */
ECC_EXPORT
int ecc_sign_eth_bls_KeyValidate(const byte_t *pk);

/**
 * Computes a signature from sk, a secret key, and a message message
 * and put the result in sig.
 *
 * @param[out] signature the signature, size:ecc_sign_eth_bls_SIGNATURESIZE
 * @param sk the secret key, size:ecc_sign_eth_bls_PRIVATEKEYSIZE
 * @param message input message, size:message_len
 * @param message_len the length of `message`
 */
ECC_EXPORT
void ecc_sign_eth_bls_Sign(
    byte_t *signature,
    const byte_t *sk,
    const byte_t *message, int message_len
);

/**
 * Checks that a signature is valid for the message under the public key pk.
 *
 * @param pk the public key, size:ecc_sign_eth_bls_PUBLICKEYSIZE
 * @param message input message, size:message_len
 * @param message_len the length of `message`
 * @param signature the signature, size:ecc_sign_eth_bls_SIGNATURESIZE
 * @return 0 if valid, -1 if invalid
 */
ECC_EXPORT
int ecc_sign_eth_bls_Verify(
    const byte_t *pk,
    const byte_t *message, int message_len,
    const byte_t *signature
);

/**
 * Aggregates multiple signatures into one.
 *
 * @param[out] signature the aggregated signature that combines all inputs, size:ecc_sign_eth_bls_SIGNATURESIZE
 * @param signatures array of individual signatures, size:n*ecc_sign_eth_bls_SIGNATURESIZE
 * @param n amount of signatures in the array `signatures`
 * @return 0 if valid, -1 if invalid
 */
ECC_EXPORT
int ecc_sign_eth_bls_Aggregate(
    byte_t *signature,
    const byte_t *signatures, int n
);

/**
 *
 * @param pks size:n*ecc_sign_eth_bls_PUBLICKEYSIZE
 * @param n the number of public keys in `pks`
 * @param message size:message_len
 * @param message_len the length of `message`
 * @param signature size:ecc_sign_eth_bls_SIGNATURESIZE
 * @return 0 if valid, -1 if invalid
 */
ECC_EXPORT
int ecc_sign_eth_bls_FastAggregateVerify(
    const byte_t *pks, int n,
    const byte_t *message, int message_len,
    const byte_t *signature
);

/**
 * Checks an aggregated signature over several (PK, message) pairs. The
 * messages are concatenated and in PASCAL-encoded form [size, chars].
 *
 * In order to keep the API simple, the maximum length of a message is 255.
 *
 * @param n number of pairs
 * @param pks size:n*ecc_sign_eth_bls_PUBLICKEYSIZE
 * @param messages size:messages_len
 * @param messages_len total length of the buffer `messages`
 * @param signature size:ecc_sign_eth_bls_SIGNATURESIZE
 * @return 0 if valid, -1 if invalid
 */
ECC_EXPORT
int ecc_sign_eth_bls_AggregateVerify(
    int n,
    const byte_t *pks,
    const byte_t *messages, int messages_len,
    const byte_t *signature
);

#endif // ECC_SIGN_H
