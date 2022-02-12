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

typedef struct {
    byte_t x[ecc_frost_ristretto255_sha512_SCALARSIZE];
    byte_t y[ecc_frost_ristretto255_sha512_SCALARSIZE];
} Point_t;

static_assert(ecc_frost_ristretto255_sha512_SCALARSIZE == ecc_ristretto255_SCALARSIZE, "");
static_assert(ecc_frost_ristretto255_sha512_SECRETKEYSIZE == ecc_ristretto255_SCALARSIZE, "");
static_assert(ecc_frost_ristretto255_sha512_PUBLICKEYSIZE == ecc_ristretto255_ELEMENTSIZE, "");
static_assert(ecc_frost_ristretto255_sha512_POINTSIZE == 2 * ecc_ristretto255_SCALARSIZE, "");

static_assert(sizeof(Point_t) == ecc_frost_ristretto255_sha512_POINTSIZE, "");

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

void ecc_frost_ristretto255_sha512_derive_lagrange_coefficient_with_points(
    byte_t *L_i,
    const byte_t *x_i,
    const byte_t *L, const int L_len
) {
    byte_t numerator[ecc_frost_ristretto255_sha512_SCALARSIZE] = {1, 0};
    byte_t denominator[ecc_frost_ristretto255_sha512_SCALARSIZE] = {1, 0};

    byte_t t[ecc_frost_ristretto255_sha512_SCALARSIZE];

    for (int n = 0; n < L_len; n++) {
        const Point_t *point = (const Point_t *) &L[n * ecc_frost_ristretto255_sha512_POINTSIZE];
        const byte_t *x_j = point->x;
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

void ecc_frost_ristretto255_sha512_polynomial_interpolation(
    byte_t *constant_term,
    const byte_t *points, const int points_len
) {
    // f_zero = F(0)
    // for point in points:
    //   delta = point.y * derive_lagrange_coefficient(point.x, L)
    //   f_zero = f_zero + delta

    ecc_memzero(constant_term, ecc_frost_ristretto255_sha512_SCALARSIZE);

    byte_t L_i[ecc_frost_ristretto255_sha512_SCALARSIZE];
    byte_t delta[ecc_frost_ristretto255_sha512_SCALARSIZE];

    for (int i = 0; i < points_len; i++) {
        const Point_t *point = (const Point_t *) &points[i * ecc_frost_ristretto255_sha512_POINTSIZE];

        ecc_frost_ristretto255_sha512_derive_lagrange_coefficient_with_points(L_i, point->x, points, points_len);
        ecc_ristretto255_scalar_mul(delta, point->y, L_i);

        ecc_ristretto255_scalar_add(constant_term, constant_term, delta);
    }
}
