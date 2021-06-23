/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#include "bls12_381.h"
#include <blst.h>

void ecc_bls12_381_keygen(BYTE *out_SK, const BYTE *IKM, int IKM_len) {
    blst_keygen((blst_scalar *) out_SK, IKM, IKM_len, 0, 0);
}
