/*
 * Copyright (c) 2021, Alden Torres
 *
 * Licensed under the terms of the MIT license.
 * Copy of the license at https://opensource.org/licenses/MIT
 */

#include "scalarmult.h"
#include <sodium.h>

int ecc_scalarmult_ed25519(BYTE *q, const BYTE *n, const BYTE *p) {
    return crypto_scalarmult_ed25519(q, n, p);
}

int ecc_scalarmult_ed25519_noclamp(BYTE *q, const BYTE *n, const BYTE *p) {
    return crypto_scalarmult_ed25519_noclamp(q, n, p);
}

int ecc_scalarmult_ed25519_base(BYTE *q, const BYTE *n) {
    return crypto_scalarmult_ed25519_base(q, n);
}

int ecc_scalarmult_ed25519_base_noclamp(BYTE *q, const BYTE *n) {
    return crypto_scalarmult_ed25519_base_noclamp(q, n);
}
