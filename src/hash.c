#include "hash.h"
#include <sodium.h>

void ecc_hash_sha256(BYTE *out, const BYTE *in, int len) {
    crypto_hash_sha256(out, in, len);
}

void ecc_hash_sha512(BYTE *out, const BYTE *in, int len) {
    crypto_hash_sha512(out, in, len);
}
