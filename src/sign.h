/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#ifndef ECC_SIGN_H
#define ECC_SIGN_H

#include "export.h"

// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-04

/**
 *
 * @param out_SK
 * @param IKM
 * @param IKM_len
 */
ECC_EXPORT
void ecc_sign_bls12_381_keygen(byte_t *sk, const byte_t *ikm, int ikm_len);


#endif // ECC_SIGN_H
