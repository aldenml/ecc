/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#ifndef ECC_SIGN_H
#define ECC_SIGN_H

#include "export.h"

// eth2
// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-04
// https://github.com/cfrg/draft-irtf-cfrg-bls-signature

#define ecc_sign_bls_eth2_PRIVATEKEYSIZE 32

/**
 *
 * @param out_SK
 * @param IKM
 * @param IKM_len
 */
ECC_EXPORT
void ecc_sign_bls_eth2_keygen(byte_t *sk, const byte_t *ikm, int ikm_len);


#endif // ECC_SIGN_H
