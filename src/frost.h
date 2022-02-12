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
 * Size of an scalar, since this is using the ristretto255
 * curve the size is 32 bytes.
 */
#define ecc_frost_ristretto255_sha512_SCALARSIZE 32

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
 * @param L_len the number of x-coordinates in `L`, it should be less than 256
 */
ECC_EXPORT
void ecc_frost_ristretto255_sha512_derive_lagrange_coefficient(
    byte_t *L_i,
    const byte_t *x_i,
    const byte_t *L, int L_len
);

#endif // ECC_FROST_H
