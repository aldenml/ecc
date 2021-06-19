/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#include "hash.h"
#include <sodium.h>

void ecc_hash_sha256(BYTE *out, const BYTE *in, int len) {
    crypto_hash_sha256(out, in, len);
}

void ecc_hash_sha512(BYTE *out, const BYTE *in, int len) {
    crypto_hash_sha512(out, in, len);
}
