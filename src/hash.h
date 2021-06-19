/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#ifndef ECC_HASH_H
#define ECC_HASH_H

#include "export.h"

ECC_EXPORT
void ecc_hash_sha256(BYTE *out, const BYTE *in, int len);

ECC_OPRF_EXPORT
ECC_EXPORT
void ecc_hash_sha512(BYTE *out, const BYTE *in, int len);

#endif // ECC_HASH_H
