/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#include "ecc.h"
#include <sodium.h>

int ecc_is_zero(const BYTE *n, int len) {
    return sodium_is_zero(n, len);
}

void ecc_increment(BYTE *n, int len) {
    return sodium_increment(n, len);
}

void ecc_add(BYTE *a, const BYTE *b, int len) {
    sodium_add(a, b, len);
}

void ecc_sub(BYTE *a, const BYTE *b, int len) {
    sodium_sub(a, b, len);
}
