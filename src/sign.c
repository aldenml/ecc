/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#include "sign.h"
#include <sodium.h>
#include <blst.h>

void ecc_sign_bls12_381_keygen(byte_t *sk, const byte_t *ikm, int ikm_len) {
    blst_keygen((blst_scalar *) sk, ikm, ikm_len, 0, 0);
}
