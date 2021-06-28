/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#ifndef ECC_OPAQUE_H
#define ECC_OPAQUE_H

#include "export.h"

ECC_EXPORT
void ecc_opaque_ristretto255_sha512_HashToScalar(byte_t *out, const byte_t *msg, int msg_len);

// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-05#section-4.3.1

ECC_EXPORT
void ecc_opaque_ristretto255_sha512_DeriveAuthKeyPair(
    byte_t *private_key, byte_t *public_key,
    const byte_t *seed, int seed_len
);

#endif // ECC_OPAQUE_H
