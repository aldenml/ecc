/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#ifndef ECC_ECC_H
#define ECC_ECC_H

#include "export.h"

/**
 * Fills `n` bytes at buf with an unpredictable sequence of bytes.
 */
ECC_OPRF_EXPORT
ECC_EXPORT
void ecc_randombytes(BYTE *buf, int n);

ECC_EXPORT
int ecc_compare(const BYTE *a, const BYTE *b, int len);

ECC_EXPORT
int ecc_is_zero(const BYTE *n, int len);

ECC_EXPORT
void ecc_increment(BYTE *n, int len);

ECC_EXPORT
void ecc_add(BYTE *a, const BYTE *b, int len);

ECC_EXPORT
void ecc_sub(BYTE *a, const BYTE *b, int len);

#endif // ECC_ECC_H
