/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#ifndef ECC_ED25519_H
#define ECC_ED25519_H

#include "export.h"

/**
 * Size of the serialized group elements.
 */
#define ecc_ed25519_SIZE 32

/**
 * Size of the input to perform the Elligator 2 map operation.
 */
#define ecc_ed25519_UNIFORMSIZE 32

/**
 * Size of the scalar used in the curve operations.
 */
#define ecc_ed25519_SCALARSIZE 32

/**
 * Size of a non reduced scalar.
 */
#define ecc_ed25519_NONREDUCEDSCALARSIZE 64

/**
 * Checks that p represents a point on the edwards25519 curve, in canonical
 * form, on the main subgroup, and that the point doesn't have a small order.
 *
 * @param p potential point to test
 * @return 1 on success, and 0 if the checks didn't pass
 */
ECC_EXPORT
int ecc_ed25519_is_valid_point(const byte_t *p);

/**
 * Adds the point p to the point q and stores the resulting point into r.
 *
 * @param r (output) the result
 * @param p input point operand
 * @param q input point operand
 * @return 0 on success, or -1 if p and/or q are not valid points
 */
ECC_EXPORT
int ecc_ed25519_add(byte_t *r, const byte_t *p, const byte_t *q);

/**
 * Subtracts the point p to the point q and stores the resulting point into r.
 *
 * @param r (output) the result
 * @param p input point operand
 * @param q input point operand
 * @return 0 on success, or -1 if p and/or q are not valid points
 */
ECC_EXPORT
int ecc_ed25519_sub(byte_t *r, const byte_t *p, const byte_t *q);

/**
 * Maps a 32 bytes vector r to a point, and stores its compressed
 * representation into p. The point is guaranteed to be on the main
 * subgroup.
 *
 * This function directly exposes the Elligator 2 map, uses the high
 * bit to set the sign of the X coordinate, and the resulting point is
 * multiplied by the cofactor.
 *
 * @param p (output) point in the main subgroup
 * @param r input vector
 */
ECC_EXPORT
void ecc_ed25519_from_uniform(byte_t *p, const byte_t *r);

/**
 * Fills p with the representation of a random group element.
 *
 * @param p (output) random group element
 */
ECC_EXPORT
void ecc_ed25519_random(byte_t *p);

/**
 * Chose a random scalar in the [0..L[ interval, L being the order of the
 * main subgroup (2^252 + 27742317777372353535851937790883648493) and fill
 * r with the bytes.
 *
 * @param r (output) scalar
 */
ECC_EXPORT
void ecc_ed25519_scalar_random(byte_t *r);

/**
 * Computes the multiplicative inverse of s over L, and puts it into recip.
 *
 * @param recip (output) the result
 * @param s an scalar
 * @return 0 on success, or -1 if s is zero
 */
ECC_EXPORT
int ecc_ed25519_scalar_invert(byte_t *recip, const byte_t *s);

/**
 * Returns neg so that s + neg = 0 (mod L).
 *
 * @param neg (output) the result
 * @param s an scalar
 */
ECC_EXPORT
void ecc_ed25519_scalar_negate(byte_t *neg, const byte_t *s);

/**
 * Returns comp so that s + comp = 1 (mod L).
 *
 * @param comp (output) the result
 * @param s an scalar
 */
ECC_EXPORT
void ecc_ed25519_scalar_complement(byte_t *comp, const byte_t *s);

/**
 * Stores x + y (mod L) into z.
 *
 * @param z (output) the result
 * @param x input scalar operand
 * @param y input scalar operand
 */
ECC_EXPORT
void ecc_ed25519_scalar_add(byte_t *z, const byte_t *x, const byte_t *y);

/**
 * Stores x - y (mod L) into z.
 *
 * @param z (output) the result
 * @param x input scalar operand
 * @param y input scalar operand
 */
ECC_EXPORT
void ecc_ed25519_scalar_sub(byte_t *z, const byte_t *x, const byte_t *y);

/**
 * Stores x * y (mod L) into z.
 *
 * @param z (output) the result
 * @param x input scalar operand
 * @param y input scalar operand
 */
ECC_EXPORT
void ecc_ed25519_scalar_mul(byte_t *z, const byte_t *x, const byte_t *y);

/**
 * Reduces s to s mod L and puts the bytes representing the integer
 * into r where L = (2^252 + 27742317777372353535851937790883648493) is
 * the order of the group.
 *
 * The interval `s` is sampled from should be at least 317 bits to
 * ensure almost uniformity of `r` over `L`.
 *
 * @param r (output) the reduced scalar
 * @param s the integer to reduce
 */
ECC_EXPORT
void ecc_ed25519_scalar_reduce(byte_t *r, const byte_t *s);

/**
 * Multiplies a point p by a valid scalar n (no clamped) and puts the
 * Y coordinate of the resulting point into q.
 *
 * Note that n is "clamped" (the 3 low bits are cleared to make it
 * a multiple of the cofactor, bit 254 is set and bit 255 is cleared
 * to respect the original design).
 *
 * This function returns 0 on success, or -1 if n is 0 or if p is not
 * on the curve, not on the main subgroup, is a point of small order,
 * or is not provided in canonical form.
 *
 * @param q (output) the result
 * @param n the valid input scalar
 * @param p the point on the curve
 * @return 0 on success, or -1 otherwise.
 */
ECC_EXPORT
int ecc_ed25519_scalarmult(byte_t *q, const byte_t *n, const byte_t *p);

/**
 * Multiplies the base point (x, 4/5) by a scalar n (no clamped) and puts the
 * Y coordinate of the resulting point into q.
 *
 * @param q (output) the result
 * @param n the valid input scalar
 * @return -1 if n is 0, and 0 otherwise.
 */
ECC_EXPORT
int ecc_ed25519_scalarmult_base(byte_t *q, const byte_t *n);

/**
 * Signature size.
 */
#define ecc_ed25519_sign_SIZE 64

/**
 * Seed size.
 */
#define ecc_ed25519_sign_SEEDSIZE 32

/**
 * Public key size.
 */
#define ecc_ed25519_sign_PUBLICKEYSIZE 32

/**
 * Secret key size.
 */
#define ecc_ed25519_sign_SECRETKEYSIZE 64

/**
 * Signs the message msg whose length is m_len bytes, using the secret key sk, and
 * puts the signature into sig.
 *
 * @param sig (output) the signature
 * @param msg input message
 * @param msg_len the length of `msg`
 * @param sk the secret key
 */
ECC_EXPORT
void ecc_ed25519_sign(
    byte_t *sig,
    const byte_t *msg, int msg_len,
    const byte_t *sk
);

/**
 * Verifies that sig is a valid signature for the message msg whose length
 * is msg_len bytes, using the signer's public key pk.
 *
 * @param sig the signature
 * @param msg input message
 * @param msg_len the length of `msg`
 * @param pk the public key
 * @return -1 if the signature fails verification, or 0 on success
 */
ECC_EXPORT
int ecc_ed25519_sign_verify(
    const byte_t *sig,
    const byte_t *msg, int msg_len,
    const byte_t *pk
);

/**
 * Generates a random key pair of public and private keys.
 *
 * @param pk (output) public key
 * @param sk (output) private key
 */
ECC_EXPORT
void ecc_ed25519_sign_keypair(byte_t *pk, byte_t *sk);

/**
 * Generates a random key pair of public and private keys derived
 * from a seed.
 *
 * @param pk (output) public key
 * @param sk (output) private key
 * @param seed seed to generate the keys
 */
ECC_EXPORT
void ecc_ed25519_sign_seed_keypair(byte_t *pk, byte_t *sk, const byte_t *seed);

/**
 * Extracts the seed from the secret key sk and copies it into seed.
 *
 * @param seed (output) the seed used to generate the secret key
 * @param sk the secret key
 */
ECC_EXPORT
void ecc_ed25519_sign_sk_to_seed(byte_t *seed, const byte_t *sk);

/**
 * Extracts the public key from the secret key sk and copies it into pk.
 *
 * @param pk (output) the public key
 * @param sk the secret key
 */
ECC_EXPORT
void ecc_ed25519_sign_sk_to_pk(byte_t *pk, const byte_t *sk);

#endif // ECC_ED25519_H
