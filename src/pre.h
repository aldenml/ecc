/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#ifndef ECC_PRE_H
#define ECC_PRE_H

#include "export.h"

// This is a proxy re-encryption (PRE) scheme implementation guided by
// the following papers:
//
// - "A Fully Secure Unidirectional and Multi-user Proxy Re-encryption Scheme" by H. Wang and Z. Cao, 2009
// - "A Multi-User CCA-Secure Proxy Re-Encryption Scheme" by Y. Cai and X. Liu, 2014
// - "Cryptographically Enforced Orthogonal Access Control at Scale" by B. Wall and P. Walsh, 2018
//
// See https://en.wikipedia.org/wiki/Proxy_re-encryption
//
// Since there is no standard for these schemes, I called this implementation PRE-SCHEME1
// which is a an instance with the following implementation details decisions:
//
// - Curve BLS12-381, https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-pairing-friendly-curves-09#section-4.2.1
// - Messages are elements of Fp12 in BLS12-381
// - Public keys are in the G1 group of BLS12-381
// - Private keys are scalars in BLS12-381
// - Signature and signing keys uses Ed25519, https://ed25519.cr.yp.to
// - Only two levels are supported, level 1 (simple encrypt) and level 2 (re-encryption by proxy)
// - Pairing for blinding operations are mostly done in the G2 group of BLS12-381
//
// NOTE Only messages of ecc_pre_schema1_MESSAGESIZE size are accepted in the protocol,
// they are short but suitable to use as the seed for other symmetric encryption protocols.

// const
/**
 * Size of the PRE-SCHEMA1 plaintext and ciphertext messages (size of a Fp12 element in BLS12-381).
 */
#define ecc_pre_schema1_MESSAGESIZE 576

// const
/**
 * Size of the PRE-SCHEMA1 seed used in all operations.
 */
#define ecc_pre_schema1_SEEDSIZE 32

// const
/**
 * Size of the PRE-SCHEMA1 public key (size of a G1 element in BLS12-381).
 */
#define ecc_pre_schema1_PUBLICKEYSIZE 96

// const
/**
 * Size of the PRE-SCHEMA1 private key (size of a scalar in BLS12-381).
 */
#define ecc_pre_schema1_PRIVATEKEYSIZE 32

// const
/**
 * Size of the PRE-SCHEMA1 signing public key (ed25519 signing public key size).
 */
#define ecc_pre_schema1_SIGNINGPUBLICKEYSIZE 32

// const
/**
 * Size of the PRE-SCHEMA1 signing private key (ed25519 signing secret key size).
 */
#define ecc_pre_schema1_SIGNINGPRIVATEKEYSIZE 64

// const
/**
 * Size of the PRE-SCHEMA1 signature (ed25519 signature size).
 */
#define ecc_pre_schema1_SIGNATURESIZE 64

// const
/**
 * Size of the whole ciphertext structure, that is the result
 * of the simple Encrypt operation.
 */
#define ecc_pre_schema1_CIPHERTEXTLEVEL1SIZE \
    ecc_pre_schema1_PUBLICKEYSIZE +          \
    ecc_pre_schema1_MESSAGESIZE +            \
    32 +                                     \
    ecc_pre_schema1_SIGNINGPUBLICKEYSIZE +     \
    ecc_pre_schema1_SIGNATURESIZE // 800
// 32 is ecc_hash_sha256_SIZE

// const
/**
 * Size of the whole ciphertext structure, that is the result
 * of the one-hop ReEncrypt operation.
 */
#define ecc_pre_schema1_CIPHERTEXTLEVEL2SIZE \
    ecc_pre_schema1_CIPHERTEXTLEVEL1SIZE +   \
    ecc_pre_schema1_PUBLICKEYSIZE +          \
    ecc_pre_schema1_MESSAGESIZE +            \
    ecc_pre_schema1_PUBLICKEYSIZE +          \
    ecc_pre_schema1_MESSAGESIZE +            \
    ecc_pre_schema1_SIGNINGPUBLICKEYSIZE +     \
    ecc_pre_schema1_SIGNATURESIZE // 2240

// const
/**
 * Size of the whole re-encryption key structure.
 */
#define ecc_pre_schema1_REKEYSIZE        \
    ecc_pre_schema1_PUBLICKEYSIZE +      \
    ecc_pre_schema1_MESSAGESIZE +        \
    ecc_pre_schema1_SIGNINGPUBLICKEYSIZE + \
    ecc_pre_schema1_SIGNATURESIZE +      \
    192 // 960
// 192 is ecc_bls12_381_G2SIZE

/**
 * Generates a random message suitable to use in the protocol.
 *
 * The output can be used in other key derivation algorithms for other
 * symmetric encryption protocols.
 *
 * @param[out] m a random plaintext message, size:ecc_pre_schema1_MESSAGESIZE
 */
ECC_EXPORT
void ecc_pre_schema1_MessageGen(byte_t *m);

/**
 * Derive a public/private key pair deterministically
 * from the input "seed".
 *
 * @param[out] pk public key, size:ecc_pre_schema1_PUBLICKEYSIZE
 * @param[out] sk private key, size:ecc_pre_schema1_PRIVATEKEYSIZE
 * @param seed input seed to generate the key pair, size:ecc_pre_schema1_SEEDSIZE
 */
ECC_EXPORT
void ecc_pre_schema1_DeriveKey(
    byte_t *pk, byte_t *sk,
    const byte_t *seed
);

/**
 * Generate a public/private key pair.
 *
 * @param[out] pk public key, size:ecc_pre_schema1_PUBLICKEYSIZE
 * @param[out] sk private key, size:ecc_pre_schema1_PRIVATEKEYSIZE
 */
ECC_EXPORT
void ecc_pre_schema1_KeyGen(byte_t *pk, byte_t *sk);

/**
 * Derive a signing public/private key pair deterministically
 * from the input "seed".
 *
 * @param[out] spk signing public key, size:ecc_pre_schema1_SIGNINGPUBLICKEYSIZE
 * @param[out] ssk signing private key, size:ecc_pre_schema1_SIGNINGPRIVATEKEYSIZE
 * @param seed input seed to generate the key pair, size:ecc_pre_schema1_SEEDSIZE
 */
ECC_EXPORT
void ecc_pre_schema1_DeriveSigningKey(
    byte_t *spk, byte_t *ssk,
    const byte_t *seed
);

/**
 * Generate a signing public/private key pair.
 *
 * @param[out] spk signing public key, size:ecc_pre_schema1_SIGNINGPUBLICKEYSIZE
 * @param[out] ssk signing private key, size:ecc_pre_schema1_SIGNINGPRIVATEKEYSIZE
 */
ECC_EXPORT
void ecc_pre_schema1_SigningKeyGen(byte_t *spk, byte_t *ssk);

/**
 * Encrypt a message `m` to delegatee j, given j’s public key (pk_j) and the
 * sender i’s signing key pair (spk_i, ssk_i). Produces a ciphertext C_j.
 *
 * This is also called encryption of level 1, since it's used to encrypt to
 * itself (i.e j == i), in order to have later the ciphertext re-encrypted
 * by the proxy with the re-encryption key (level 2).
 *
 * @param[out] C_j_raw a CiphertextLevel1_t structure, size:ecc_pre_schema1_CIPHERTEXTLEVEL1SIZE
 * @param m the plaintext message, size:ecc_pre_schema1_MESSAGESIZE
 * @param pk_j delegatee's public key, size:ecc_pre_schema1_PUBLICKEYSIZE
 * @param spk_i sender signing public key, size:ecc_pre_schema1_SIGNINGPUBLICKEYSIZE
 * @param ssk_i sender signing private key, size:ecc_pre_schema1_SIGNINGPRIVATEKEYSIZE
 * @param seed seed used to generate the internal ephemeral key, size:ecc_pre_schema1_SEEDSIZE
 */
ECC_EXPORT
void ecc_pre_schema1_EncryptWithSeed(
    byte_t *C_j_raw,
    const byte_t *m,
    const byte_t *pk_j,
    const byte_t *spk_i,
    const byte_t *ssk_i,
    const byte_t *seed
);

/**
 * Encrypt a message `m` to delegatee j, given j’s public key (pk_j) and the
 * sender i’s signing key pair (spk_i, ssk_i). Produces a ciphertext C_j.
 *
 * This is also called encryption of level 1, since it's used to encrypt to
 * itself (i.e j == i), in order to have later the ciphertext re-encrypted
 * by the proxy with the re-encryption key (level 2).
 *
 * @param[out] C_j_raw a CiphertextLevel1_t structure, size:ecc_pre_schema1_CIPHERTEXTLEVEL1SIZE
 * @param m the plaintext message, size:ecc_pre_schema1_MESSAGESIZE
 * @param pk_j delegatee's public key, size:ecc_pre_schema1_PUBLICKEYSIZE
 * @param spk_i sender signing public key, size:ecc_pre_schema1_SIGNINGPUBLICKEYSIZE
 * @param ssk_i sender signing private key, size:ecc_pre_schema1_SIGNINGPRIVATEKEYSIZE
 */
ECC_EXPORT
void ecc_pre_schema1_Encrypt(
    byte_t *C_j_raw,
    const byte_t *m,
    const byte_t *pk_j,
    const byte_t *spk_i,
    const byte_t *ssk_i
);

/**
 * Generate a re-encryption key from user i (the delegator) to user j (the delegatee).
 *
 * Requires the delegator’s private key (sk_i), the delegatee’s public key (pk_j), and
 * the delegator’s signing key pair (spk_i, ssk_i).
 *
 * @param[out] tk_i_j_raw a ReKey_t structure, size:ecc_pre_schema1_REKEYSIZE
 * @param sk_i delegator’s private key, size:ecc_pre_schema1_PRIVATEKEYSIZE
 * @param pk_j delegatee’s public key, size:ecc_pre_schema1_PUBLICKEYSIZE
 * @param spk_i delegator’s signing public key, size:ecc_pre_schema1_SIGNINGPUBLICKEYSIZE
 * @param ssk_i delegator’s signing private key, size:ecc_pre_schema1_SIGNINGPRIVATEKEYSIZE
 */
ECC_EXPORT
void ecc_pre_schema1_ReKeyGen(
    byte_t *tk_i_j_raw,
    const byte_t *sk_i,
    const byte_t *pk_j,
    const byte_t *spk_i,
    const byte_t *ssk_i
);

/**
 * Re-encrypt a ciphertext encrypted to i (C_i) into a ciphertext encrypted
 * to j (C_j), given a re-encryption key (tk_i_j) and the proxy’s signing key
 * pair (spk, ssk).
 *
 * This operation is performed by the proxy and is also called encryption of
 * level 2, since it takes a ciphertext from a level 1 and re-encrypt it.
 *
 * It also validate the signature on the encrypted ciphertext and re-encryption key.
 *
 * @param[out] C_j_raw a CiphertextLevel2_t structure, size:ecc_pre_schema1_CIPHERTEXTLEVEL2SIZE
 * @param C_i_raw a CiphertextLevel1_t structure, size:ecc_pre_schema1_CIPHERTEXTLEVEL1SIZE
 * @param tk_i_j_raw a ReKey_t structure, size:ecc_pre_schema1_REKEYSIZE
 * @param spk_i delegator’s signing public key, size:ecc_pre_schema1_SIGNINGPUBLICKEYSIZE
 * @param pk_j delegatee’s public key, size:ecc_pre_schema1_PUBLICKEYSIZE
 * @param spk proxy’s signing public key, size:ecc_pre_schema1_SIGNINGPUBLICKEYSIZE
 * @param ssk proxy’s signing private key, size:ecc_pre_schema1_SIGNINGPRIVATEKEYSIZE
 * @return 0 if all the signatures are valid, -1 if there is an error
 */
ECC_EXPORT
int ecc_pre_schema1_ReEncrypt(
    byte_t *C_j_raw,
    const byte_t *C_i_raw,
    const byte_t *tk_i_j_raw,
    const byte_t *spk_i,
    const byte_t *pk_j,
    const byte_t *spk,
    const byte_t *ssk
);

/**
 * Decrypt a signed ciphertext (C_i) given the private key of the recipient
 * i (sk_i). Returns the original message that was encrypted, m.
 *
 * This operations is usually performed by the delegator, since it encrypted
 * the message just to be stored and later be re-encrypted by the proxy.
 *
 * It also validate the signature on the encrypted ciphertext.
 *
 * @param[out] m the original plaintext message, size:ecc_pre_schema1_MESSAGESIZE
 * @param C_i_raw a CiphertextLevel1_t structure, size:ecc_pre_schema1_CIPHERTEXTLEVEL1SIZE
 * @param sk_i recipient private key, size:ecc_pre_schema1_PRIVATEKEYSIZE
 * @param spk_i recipient signing public key, size:ecc_pre_schema1_SIGNINGPUBLICKEYSIZE
 * @return 0 if all the signatures are valid, -1 if there is an error
 */
ECC_EXPORT
int ecc_pre_schema1_DecryptLevel1(
    byte_t *m,
    const byte_t *C_i_raw,
    const byte_t *sk_i,
    const byte_t *spk_i
);

/**
 * Decrypt a signed ciphertext (C_j) given the private key of the recipient
 * j (sk_j). Returns the original message that was encrypted, m.
 *
 * This operations is usually performed by the delegatee, since it is the proxy
 * that re-encrypt the message and send the ciphertext to the final recipient.
 *
 * It also validate the signature on the encrypted ciphertext.
 *
 * @param[out] m the original plaintext message, size:ecc_pre_schema1_MESSAGESIZE
 * @param C_j_raw a CiphertextLevel2_t structure, size:ecc_pre_schema1_CIPHERTEXTLEVEL2SIZE
 * @param sk_j recipient private key, size:ecc_pre_schema1_PRIVATEKEYSIZE
 * @param spk proxy’s signing public key, size:ecc_pre_schema1_SIGNINGPUBLICKEYSIZE
 * @return 0 if all the signatures are valid, -1 if there is an error
 */
ECC_EXPORT
int ecc_pre_schema1_DecryptLevel2(
    byte_t *m,
    const byte_t *C_j_raw,
    const byte_t *sk_j,
    const byte_t *spk
);

#endif // ECC_PRE_H
