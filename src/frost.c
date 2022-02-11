/*
 * Copyright (c) 2022, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#include "frost.h"
#include <assert.h>
#include "util.h"
#include "ristretto255.h"

static_assert(ecc_frost_ristretto255_sha512_SCALARSIZE == ecc_ristretto255_SCALARSIZE, "");
static_assert(ecc_frost_ristretto255_sha512_SECRETKEYSIZE == ecc_ristretto255_SCALARSIZE, "");
static_assert(ecc_frost_ristretto255_sha512_PUBLICKEYSIZE == ecc_ristretto255_ELEMENTSIZE, "");

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
