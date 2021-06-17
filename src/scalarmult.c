#include "scalarmult.h"
#include <sodium.h>

int ecc_scalarmult_curve25519(BYTE *q, const BYTE *n, const BYTE *p) {
    return crypto_scalarmult_curve25519(q, n, p);
}

int ecc_scalarmult_curve25519_base(BYTE *q, const BYTE *n) {
    return crypto_scalarmult_curve25519_base(q, n);
}

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

int ecc_scalarmult_ristretto255(BYTE *q, const BYTE *n, const BYTE *p) {
    return crypto_scalarmult_ristretto255(q, n, p);
}

int ecc_scalarmult_ristretto255_base(BYTE *q, const BYTE *n) {
    return crypto_scalarmult_ristretto255_base(q, n);
}
