/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#ifndef ECC_OPRF_H
#define ECC_OPRF_H

#include "export.h"

// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-06#section-5.1

ECC_EXPORT
void ecc_oprf_ristretto255_sha512_HashToGroup(byte_t *out, const byte_t *in, int in_len);

ECC_EXPORT
void ecc_oprf_ristretto255_sha512_HashToScalar(byte_t *out, const byte_t *msg, int msg_len);

ECC_EXPORT
void ecc_oprf_ristretto255_sha512_BlindWithScalar(
    byte_t *out,
    const byte_t *in, int in_len,
    const byte_t *s
);

#endif // ECC_OPRF_H
