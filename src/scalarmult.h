/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#ifndef ECC_SCALARMULT_H
#define ECC_SCALARMULT_H

#include "export.h"

ECC_EXPORT
int ecc_scalarmult_curve25519(BYTE *q, const BYTE *n, const BYTE *p);

ECC_EXPORT
int ecc_scalarmult_curve25519_base(BYTE *q, const BYTE *n);

ECC_EXPORT
int ecc_scalarmult_ed25519(BYTE *q, const BYTE *n, const BYTE *p);

ECC_EXPORT
int ecc_scalarmult_ed25519_noclamp(BYTE *q, const BYTE *n, const BYTE *p);

ECC_EXPORT
int ecc_scalarmult_ed25519_base(BYTE *q, const BYTE *n);

ECC_EXPORT
int ecc_scalarmult_ed25519_base_noclamp(BYTE *q, const BYTE *n);

ECC_OPRF_EXPORT
ECC_EXPORT
int ecc_scalarmult_ristretto255(BYTE *q, const BYTE *n, const BYTE *p);

ECC_EXPORT
int ecc_scalarmult_ristretto255_base(BYTE *q, const BYTE *n);

#endif // ECC_SCALARMULT_H