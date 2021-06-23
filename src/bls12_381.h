/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#ifndef ECC_BLS12_381_H
#define ECC_BLS12_381_H

#include "export.h"

ECC_EXPORT
void ecc_bls12_381_keygen(BYTE *out_SK, const BYTE *IKM, int IKM_len);

#endif // ECC_BLS12_381_H
