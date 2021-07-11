/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#ifndef ECC_BLS12_381_H
#define ECC_BLS12_381_H

#include "export.h"

/**
 * Size of the scalar used in the curve operations.
 */
#define ecc_bls12_381_SCALARSIZE 32

/**
 *
 * @param out_SK
 * @param IKM
 * @param IKM_len
 */
ECC_EXPORT
void ecc_bls12_381_keygen(byte_t *out_SK, const byte_t *IKM, int IKM_len);

#endif // ECC_BLS12_381_H
