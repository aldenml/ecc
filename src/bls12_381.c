/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#include "bls12_381.h"
#include <assert.h>
#include <blst.h>

static_assert(sizeof(blst_scalar) == ecc_bls12_381_SCALARSIZE, "");

void ecc_bls12_381_keygen(byte_t *out_SK, const byte_t *IKM, int IKM_len) {
    blst_keygen((blst_scalar *) out_SK, IKM, IKM_len, 0, 0);
}
